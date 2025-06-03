from app.database import Column, SurrogatePK, db
from sqlalchemy import Integer, String, Float, Text

class OnlineDevice(SurrogatePK, db.Model):
    __tablename__ = "online_devices"
    name = Column(String(255), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    action_online = Column(Text)
    action_offline = Column(Text)
    interval_online = Column(Integer, nullable=False, default=60)
    interval_offline = Column(Integer, nullable=False, default=30)
    retries = Column(Integer, nullable=False, default=3)
    status = Column(String(50), default="offline")
    next_check = Column(Float, default=0)