# -*- coding: utf-8 -*-
"""
Плагин DeviceMonitor для osysHome.
Мониторит устройства в сети, проверяя доступность через TCP-порт или ICMP, и выполняет действия при изменении их статуса.
Поддерживает:
- Добавление, удаление, редактирование и просмотр устройств через веб-интерфейс.
- Выполнение Python-кода (например, setProperty) или shell-команд (опционально) для действий при переходе online/offline.
- Хранение конфигурации в базе данных SQLite (таблица plugins, поле config).
- Настройки безопасности через веб-интерфейс и REST API.
"""

import threading
import time
import socket
import subprocess
import logging
import os
import shutil
from flask import render_template, request, redirect, url_for, flash, current_app
from app.core.main.BasePlugin import BasePlugin
from app.database import session_scope
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Float
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm.exc import DetachedInstanceError
from app.core.lib.object import setProperty

# Базовый класс для моделей SQLAlchemy
Base = declarative_base()

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    action_online = Column(String)
    action_offline = Column(String)
    interval_online = Column(Integer, nullable=False, default=60)
    interval_offline = Column(Integer, nullable=False, default=30)
    retries = Column(Integer, nullable=False, default=3)
    status = Column(String, default="offline")
    next_check = Column(Float, default=0)

class DeviceMonitor(BasePlugin):
    """Класс плагина DeviceMonitor, наследующийся от BasePlugin."""

    def __init__(self, app, name=__name__):
        """
        Инициализация плагина.

        :param app: Объект Flask-приложения.
        :param name: Имя модуля (по умолчанию __name__).
        """
        super().__init__(app, name)
        self.app = app
        self.title = "Device Monitor"
        self.description = "Мониторинг устройств в сети с проверкой TCP-порта или ICMP."
        self.version = "0.7.9"
        self.author = "NickNeo"
        self.category = "Network"
        self.system = False
        self.actions = ["admin", "cycle"]
        self.logger = logging.getLogger(__name__)
        self.locks = {}  # Словарь блокировок для каждого device_id
        self.ping_available = True  # Флаг доступности команды ping

    def initialization(self):
        """
        Инициализация плагина.
        Создаёт таблицу устройств, проверяет доступность команды ping, инициализирует настройки и запускает фоновую задачу.
        """
        self.logger.info("Initializing DeviceMonitor plugin")
        
        # Проверка доступности команды ping
        if not shutil.which("ping"):
            self.ping_available = False
            self.logger.warning("Command 'ping' not found in system PATH. ICMP checks will be disabled. Please install 'ping' or ensure it is in PATH.")
        else:
            try:
                # Тестовый запуск ping на localhost
                subprocess.run(
                    ["ping", "-c", "1", "-W", "2", "127.0.0.1"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                self.logger.debug("Command 'ping' is available and functional")
            except subprocess.CalledProcessError as e:
                self.ping_available = False
                self.logger.warning(f"Command 'ping' failed to execute: {e.stderr}. ICMP checks will be disabled. Ensure sufficient permissions (e.g., run as root or enable NET_RAW capability). If the process is running in an LXC container, grant rights to the user with the command 'setcap cap_net_raw+ep /bin/ping'.")
            except Exception as e:
                self.ping_available = False
                self.logger.warning(f"Error testing 'ping' command: {e}. ICMP checks will be disabled. Ensure sufficient permissions or check system configuration. If the process is running in an LXC container, grant rights to the user with the command 'setcap cap_net_raw+ep /bin/ping'.")

        # Создание таблицы устройств
        try:
            with session_scope() as session:
                Base.metadata.create_all(session.bind)
                self.logger.info("Created or verified devices table")
                
                # Инициализация настройки allow_shell_commands
                if 'allow_shell_commands' not in self.config:
                    self.config['allow_shell_commands'] = False
                    self.saveConfig()
                    self.logger.info("Initialized allow_shell_commands to False")
                else:
                    self.logger.debug(f"Loaded allow_shell_commands: {self.config['allow_shell_commands']}")
        except OperationalError as e:
            self.logger.error(f"Error creating devices table: {e}")
            raise
        
        # Запуск фоновой задачи
        threading.Thread(target=self.cyclic_task, daemon=True).start()

    def loadConfig(self):
        """
        Загрузка конфигурации плагина из базы данных.

        Returns:
            dict: Словарь с настройками плагина.
        """
        self.logger.debug("Loading DeviceMonitor configuration")
        return super().loadConfig()

    def saveConfig(self):
        """
        Сохранение конфигурации плагина в базу данных.
        """
        self.logger.debug("Saving DeviceMonitor configuration")
        super().saveConfig()

    def check_tcp_port(self, host, port, retries=3, timeout=2):
        """
        Проверка доступности устройства через TCP-порт.

        :param host: IP-адрес или hostname устройства.
        :param port: Порт для проверки (например, 80 для HTTP).
        :param retries: Количество попыток подключения.
        :param timeout: Таймаут для каждой попытки (секунды).
        :return: True, если порт доступен, иначе False.
        """
        for attempt in range(1, retries + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    self.logger.debug(f"Port {port} on {host} is open (attempt {attempt})")
                    return True
                self.logger.debug(f"Port {port} on {host} is closed (attempt {attempt})")
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Error checking {host}:{port} (attempt {attempt}): {e}")
                time.sleep(1)
        return False

    def check_icmp_host(self, host, retries=3, timeout=2):
        """
        Проверка доступности хоста через ICMP (ping).

        :param host: IP-адрес или hostname устройства.
        :param retries: Количество попыток пинга.
        :param timeout: Таймаут для каждого пинга (секунды).
        :return: True, если хост доступен, иначе False.
        """
        if not self.ping_available:
            self.logger.error(f"ICMP check for {host} skipped: 'ping' command is not available or lacks permissions")
            return False

        for attempt in range(1, retries + 1):
            try:
                cmd = ["ping", "-c", "1", "-W", str(timeout), host]
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                self.logger.debug(f"ICMP ping to {host} successful (attempt {attempt}): {result.stdout}")
                return True
            except subprocess.CalledProcessError as e:
                self.logger.debug(f"ICMP ping to {host} failed (attempt {attempt}): {e.stderr}")
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Error pinging {host} (attempt {attempt}): {e}")
                time.sleep(1)
        self.logger.debug(f"All {retries} ICMP ping attempts to {host} failed")
        return False

    def run_action(self, action):
        """
        Выполнение действия: Python-кода (например, setProperty) или shell-команды (если разрешено).

        :param action: Строка с Python-кодом (например, 'setProperty("Relay01.alive", "0", "DevMon")') или shell-командой.
        """
        if not action:
            return
        try:
            # Проверяем, является ли действие Python-кодом (содержит setProperty)
            if "setProperty(" in action:
                # Создаём контекст для выполнения Python-кода
                context = {"setProperty": setProperty}
                # Выполняем Python-код
                exec(action, context)
                self.logger.info(f"Executed Python action: {action}")
            else:
                # Проверяем, разрешены ли shell-команды
                if self.config.get('allow_shell_commands', False):
                    # Выполняем как shell-команду
                    subprocess.run(action, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.logger.info(f"Executed shell action: {action}")
                else:
                    self.logger.warning(f"Shell action '{action}' skipped: shell commands are disabled in settings")
        except AttributeError as e:
            self.logger.error(f"Error executing action '{action}': {e}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error executing shell action '{action}': {e.stderr}")
        except SyntaxError as e:
            self.logger.error(f"Syntax error in Python action '{action}': {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error executing action '{action}': {e}")

    def check_device(self, device_id):
        """
        Проверка статуса устройства и выполнение действий при его изменении.

        :param device_id: ID устройства в базе данных.
        """
        # Получаем или создаём блокировку для устройства
        if device_id not in self.locks:
            self.locks[device_id] = threading.Lock()
        
        with self.locks[device_id]:
            self.logger.debug(f"Checking device ID {device_id}")
            try:
                with session_scope() as session:
                    device = session.query(Device).get(device_id)
                    if not device:
                        self.logger.warning(f"Device with ID {device_id} not found")
                        return
                    # Проверяем в зависимости от порта: TCP (port 1–65535) или ICMP (port 0)
                    online = False
                    check_type = "TCP" if device.port > 0 else "ICMP"
                    if device.port == 0:
                        online = self.check_icmp_host(device.host, device.retries)
                        self.logger.debug(f"Checked device {device.name} ({device.host}:{device.port}) via ICMP: online={online}")
                    else:
                        online = self.check_tcp_port(device.host, device.port, device.retries)
                        self.logger.debug(f"Checked device {device.name} ({device.host}:{device.port}) via TCP: online={online}")
                    
                    # Выполняем действия только при изменении статуса
                    if online and device.status == "offline":
                        device.status = "online"
                        self.run_action(device.action_online)
                        device.next_check = time.time() + device.interval_online
                        self.logger.info(f"Device {device.name} ({device.host}:{device.port}) is now online via {check_type}")
                    elif not online and device.status == "online":
                        device.status = "offline"
                        self.run_action(device.action_offline)
                        device.next_check = time.time() + device.interval_offline
                        self.logger.info(f"Device {device.name} ({device.host}:{device.port}) is now offline via {check_type}")
                    else:
                        # Статус не изменился, обновляем только время следующей проверки
                        device.next_check = time.time() + (
                            device.interval_online if device.status == "online" else device.interval_offline
                        )
                        self.logger.debug(f"Device {device.name} ({device.host}:{device.port}) status unchanged: {device.status}")
                    
                    session.commit()
            except DetachedInstanceError as e:
                self.logger.error(f"DetachedInstanceError for device ID {device_id}: {e}")
            except Exception as e:
                self.logger.error(f"Error checking device ID {device_id}: {e}")
            finally:
                self.logger.debug(f"Finished checking device ID {device_id}")

    def cyclic_task(self):
        """
        Фоновая задача для периодической проверки устройств.
        """
        self.logger.info("Starting DeviceMonitor cycle")
        while True:
            try:
                with session_scope() as session:
                    current_time = time.time()
                    devices_to_check = session.query(Device).filter(Device.next_check <= current_time).all()
                    device_ids = [device.id for device in devices_to_check]
                    self.logger.debug(f"Devices to check: {device_ids}")
                    next_check = min(
                        [d.next_check for d in session.query(Device).all()],
                        default=current_time + 60
                    ) if session.query(Device).count() > 0 else current_time + 60
                
                # Проверяем устройства последовательно
                for device_id in device_ids:
                    self.check_device(device_id)
                
                time.sleep(max(0, next_check - time.time()))
            except Exception as e:
                self.logger.error(f"Error in cyclic task: {e}")
                time.sleep(5)

    def admin(self, request):
        """
        Обработка запросов для административного интерфейса.

        :param request: Объект запроса Flask.
        :return: HTML-страница или редирект.
        """
        self.logger.debug("Entering DeviceMonitor admin route")
        endpoints = [rule.endpoint for rule in current_app.url_map.iter_rules()]
        self.logger.debug(f"Available endpoints: {endpoints}")

        with session_scope() as session:
            # Обработка POST-запросов
            if request.method == "POST":
                action = request.form.get("action")
                self.logger.debug(f"Processing POST action: {action}")
                if action == "add":
                    try:
                        name = request.form.get("name", "").strip()
                        host = request.form.get("host", "").strip()
                        port = request.form.get("port", "").strip()
                        if not name or not host:
                            raise ValueError("Имя и хост обязательны")
                        try:
                            port = int(port) if port else 0
                            if not (0 <= port <= 65535):
                                raise ValueError("Порт должен быть в диапазоне 0–65535")
                            interval_online = int(request.form.get("interval_online", 60))
                            interval_offline = int(request.form.get("interval_offline", 30))
                            retries = int(request.form.get("retries", 3))
                            if interval_online < 1 or interval_offline < 1 or retries < 1:
                                raise ValueError("Интервалы и попытки должны быть положительными")
                        except ValueError as e:
                            if "Порт" not in str(e) and "Интервалы" not in str(e):
                                raise ValueError("Порт, интервалы и попытки должны быть числами")
                            raise
                        new_device = Device(
                            name=name,
                            host=host,
                            port=port,
                            action_online=request.form.get("action_online", "").strip(),
                            action_offline=request.form.get("action_offline", "").strip(),
                            interval_online=interval_online,
                            interval_offline=interval_offline,
                            retries=retries,
                            status="offline",
                            next_check=0
                        )
                        session.add(new_device)
                        session.commit()
                        self.logger.info(f"Added device: {name} ({host}:{port})")
                        flash(f"Устройство '{name}' добавлено", "success")
                        return redirect(url_for("DeviceMonitor.module"))
                    except ValueError as e:
                        self.logger.error(f"Invalid input: {e}")
                        flash(str(e), "danger")
                    except Exception as e:
                        self.logger.error(f"Error adding device: {e}")
                        flash("Ошибка при добавлении устройства", "danger")
                elif action == "edit":
                    try:
                        device_id = request.form.get("device_id")
                        name = request.form.get("name", "").strip()
                        host = request.form.get("host", "").strip()
                        port = request.form.get("port", "").strip()
                        if not device_id or not name or not host:
                            raise ValueError("ID устройства, имя и хост обязательны")
                        try:
                            device_id = int(device_id)
                            port = int(port) if port else 0
                            if not (0 <= port <= 65535):
                                raise ValueError("Порт должен быть в диапазоне 0–65535")
                            interval_online = int(request.form.get("interval_online", 60))
                            interval_offline = int(request.form.get("interval_offline", 30))
                            retries = int(request.form.get("retries", 3))
                            if interval_online < 1 or interval_offline < 1 or retries < 1:
                                raise ValueError("Интервалы и попытки должны быть положительными")
                        except ValueError as e:
                            if "Порт" not in str(e) and "Интервалы" not in str(e):
                                raise ValueError("Порт, интервалы и попытки должны быть числами")
                            raise
                        device = session.query(Device).get(device_id)
                        if not device:
                            raise ValueError(f"Устройство с ID {device_id} не найдено")
                        device.name = name
                        device.host = host
                        device.port = port
                        device.action_online = request.form.get("action_online", "").strip()
                        device.action_offline = request.form.get("action_offline", "").strip()
                        device.interval_online = interval_online
                        device.interval_offline = interval_offline
                        device.retries = retries
                        session.commit()
                        self.logger.info(f"Edited device ID {device_id}: {name} ({host}:{port})")
                        flash(f"Устройство '{name}' обновлено", "success")
                        return redirect(url_for("DeviceMonitor.module"))
                    except ValueError as e:
                        self.logger.error(f"Invalid input for edit: {e}")
                        flash(str(e), "danger")
                    except Exception as e:
                        self.logger.error(f"Error editing device: {e}")
                        flash("Ошибка при редактировании устройства", "danger")
                elif action == "delete":
                    try:
                        device_id = request.form.get("device_id")
                        if not device_id:
                            raise ValueError("ID устройства обязателен")
                        device_id = int(device_id)
                        device = session.query(Device).get(device_id)
                        if not device:
                            raise ValueError(f"Устройство с ID {device_id} не найдено")
                        session.delete(device)
                        session.commit()
                        self.logger.info(f"Deleted device ID {device_id}")
                        flash("Устройство удалено", "success")
                        return redirect(url_for("DeviceMonitor.module"))
                    except ValueError as e:
                        self.logger.error(f"Invalid input for delete: {e}")
                        flash(str(e), "danger")
                    except Exception as e:
                        self.logger.error(f"Error deleting device: {e}")
                        flash("Ошибка при удалении устройства", "danger")
                elif action == "update_settings":
                    try:
                        self.config['allow_shell_commands'] = request.form.get("allow_shell_commands") == "on"
                        self.saveConfig()
                        self.logger.info(f"Updated allow_shell_commands to {self.config['allow_shell_commands']}")
                        flash("Настройки обновлены", "success")
                        return redirect(url_for("DeviceMonitor.module", action="settings"))
                    except Exception as e:
                        self.logger.error(f"Error updating settings: {e}")
                        flash("Ошибка при обновлении настроек", "danger")
                        return redirect(url_for("DeviceMonitor.module", action="settings"))

            # Обработка GET-запросов
            action = request.args.get("action")
            if action == "add":
                self.logger.debug("Rendering add device page")
                return render_template("device_monitor_add.html")
            elif action == "edit":
                device_id = request.args.get("id")
                if not device_id:
                    self.logger.error("Missing device_id for edit")
                    flash("ID устройства обязателен", "danger")
                    return redirect(url_for("DeviceMonitor.module"))
                try:
                    device_id = int(device_id)
                    device = session.query(Device).get(device_id)
                    if not device:
                        self.logger.error(f"Device with ID {device_id} not found")
                        flash(f"Устройство с ID {device_id} не найдено", "danger")
                        return redirect(url_for("DeviceMonitor.module"))
                    self.logger.debug(f"Rendering edit device page for ID {device_id}")
                    return render_template("device_monitor_edit.html", device=device)
                except ValueError:
                    self.logger.error(f"Invalid device_id: {device_id}")
                    flash("Неверный ID устройства", "danger")
                    return redirect(url_for("DeviceMonitor.module"))
            elif action == "settings":
                self.logger.debug("Rendering settings page")
                return render_template("device_monitor_settings.html", allow_shell_commands=self.config.get('allow_shell_commands', False))

            # Основная страница со списком устройств
            devices = session.query(Device).all()
            self.logger.info(f"Rendering admin page with {len(devices)} devices")
            return render_template("device_monitor_admin.html", devices=devices)

# Регистрация плагина
plugin = DeviceMonitor