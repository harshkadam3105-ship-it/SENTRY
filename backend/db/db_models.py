from sqlalchemy import Column, String, Integer, Float, TIMESTAMP, JSON, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Event(Base):
    __tablename__ = "events"
    id = Column(UUID(as_uuid=True), primary_key=True)
    timestamp = Column(TIMESTAMP, nullable=False)
    source_type = Column(String, nullable=False)
    host_id = Column(String, nullable=False)
    user_id = Column(String)
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String)
    event_type = Column(String, nullable=False)
    severity = Column(Integer, CheckConstraint("severity >= 0 AND severity <= 5"))
    features = Column(JSON)
    raw_data = Column(JSON)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(UUID(as_uuid=True), primary_key=True)
    title = Column(String, nullable=False)
    severity = Column(Integer)
    risk_score = Column(Float)
    confidence = Column(Float)
    status = Column(String)
    created_at = Column(TIMESTAMP)
    updated_at = Column(TIMESTAMP)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(UUID(as_uuid=True), primary_key=True)
    hostname = Column(String)
    ip = Column(String)
    os = Column(String)
    criticality = Column(Integer)
    status = Column(String)


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), primary_key=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"), primary_key=True)
    relationship_score = Column(Float)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), primary_key=True)
    mitre_id = Column(String, primary_key=True)
    technique = Column(String)
    confidence = Column(Float)
