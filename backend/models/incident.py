from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, JSON, String

from backend.database.connection import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    host = Column(String, nullable=False)
    user = Column(String, nullable=True)

    severity = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False)

    mitre_techniques = Column(JSON, nullable=True)
    explanation = Column(String, nullable=True)

    correlated_events = Column(JSON, nullable=True)
