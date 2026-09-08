from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict, List
from uuid import UUID


# Event Schema (Unified Contract)

class EventIn(BaseModel):
    event_id: UUID
    timestamp: datetime
    source_type: str   # "network" | "endpoint" | "application"
    host_id: str
    user_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str
    severity: int      # 0–5
    features: Dict     # model/correlation features
    raw_data: Dict     # original source payload


# Incident Schema

class IncidentIn(BaseModel):
    id: UUID
    title: str
    severity: int
    risk_score: float
    confidence: float
    status: str        # "open", "contained", "resolved", etc.
    created_at: datetime
    updated_at: datetime


# Asset Schema

class AssetIn(BaseModel):
    id: UUID
    hostname: str
    ip: str
    os: str
    criticality: int   # used in risk formula
    status: str        # "normal", "isolated", etc.


# Linking Tables (Optional Models)

class IncidentEvent(BaseModel):
    incident_id: UUID
    event_id: UUID
    relationship_score: float

class AttackTechnique(BaseModel):
    incident_id: UUID
    mitre_id: str
    technique: str
    confidence: float
