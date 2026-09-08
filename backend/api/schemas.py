from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    event_id: str
    timestamp: Optional[str] = None

    source_type: str
    host_id: str
    user_id: Optional[str] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    event_type: str
    severity: Optional[str] = None

    features: Dict[str, Any] = Field(default_factory=dict)
    raw_data: Optional[Dict[str, Any]] = None


class BaselineRequest(BaseModel):
    events: list[EventCreate]