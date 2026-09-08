from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, JSON, String

from backend.database.connection import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)

    event_id = Column(String, unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    source_type = Column(String, nullable=False)
    host_id = Column(String, nullable=False, index=True)
    user_id = Column(String, nullable=True, index=True)

    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)

    event_type = Column(String, nullable=False)
    severity = Column(String, nullable=True)

    features = Column(JSON, nullable=False, default=dict)
    raw_data = Column(JSON, nullable=True)

    anomaly_score = Column(Float, nullable=True)
    rule_score = Column(Float, nullable=True)
    detected = Column(Integer, default=0)
