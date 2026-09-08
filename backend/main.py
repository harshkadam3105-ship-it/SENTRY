import sys
import os
from datetime import datetime
from uuid import uuid4
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc

# Ensure current directory is in Python path for submodule resolution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db.schema import EventIn, HostActionRequest
from db.db_models import Base, Event, Incident, Asset
from db.database import engine, get_db
from core.websocket_manager import manager
from core.response_action import isolate_host, restore_host

# Create database tables
try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print("[Sentry] Database table creation note:", e)

app = FastAPI(title="Sentry Backend")

# Enable CORS for frontend dev server and Docker environments
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Seed fallback incidents if database has not been populated yet by correlation engine
SEED_INCIDENTS = [
    {
        "incident_id": "INC-001",
        "id": "b1c3e34a-1234-5678-90ab-cdef12345678",
        "created_at": "2026-09-08T08:12:34Z",
        "host": "workstation-14.corp",
        "host_id": "workstation-14.corp",
        "user": "alice.chen",
        "user_id": "alice.chen",
        "severity": "critical",
        "risk_score": 0.94,
        "mitre_techniques": ["T1110", "T1078", "T1021"],
        "explanation": "52 failed SSH logins from external IP followed immediately by successful credential auth and lateral RDP.",
        "correlated_events": [
            {
                "event_id": "EVT-001a",
                "type": "failed_login",
                "timestamp": "2026-09-08T08:10:11Z",
                "anomaly_score": 0.87,
                "rule_score": 0.95,
                "detail": "52 failed SSH login attempts from 192.168.1.105",
            },
            {
                "event_id": "EVT-001b",
                "type": "lateral_movement",
                "timestamp": "2026-09-08T08:12:05Z",
                "anomaly_score": 0.91,
                "rule_score": 0.89,
                "detail": "RDP connection to internal server dc-01.corp",
            },
        ],
    },
    {
        "incident_id": "INC-002",
        "id": "c2d4e45b-2345-6789-01bc-def012345679",
        "created_at": "2026-09-08T07:45:12Z",
        "host": "srv-finance-02",
        "host_id": "srv-finance-02",
        "user": "svc_backup",
        "severity": "high",
        "risk_score": 0.78,
        "mitre_techniques": ["T1048", "T1567"],
        "explanation": "Unusual outbound data transfer (4.2 GB) via HTTPS to unknown external IP.",
        "correlated_events": [
            {
                "event_id": "EVT-002a",
                "type": "suspicious_flow",
                "timestamp": "2026-09-08T07:44:00Z",
                "anomaly_score": 0.82,
                "rule_score": 0.74,
                "detail": "Outbound flow spike to 198.51.100.44:443 (4.2 GB in 6 minutes)",
            },
        ],
    },
    {
        "incident_id": "INC-003",
        "id": "d3e5f56c-3456-7890-12cd-ef0123456780",
        "created_at": "2026-09-08T06:30:00Z",
        "host": "dev-box-03",
        "host_id": "dev-box-03",
        "user": "bob.miller",
        "severity": "medium",
        "risk_score": 0.55,
        "mitre_techniques": ["T1059"],
        "explanation": "Base64-encoded PowerShell command executed by developer account.",
        "correlated_events": [
            {
                "event_id": "EVT-003a",
                "type": "new_process",
                "timestamp": "2026-09-08T06:29:15Z",
                "anomaly_score": 0.60,
                "rule_score": 0.70,
                "detail": "powershell.exe -EncodedCommand SQBFAFgA...",
            },
        ],
    },
]


# ---------------- HEALTH ----------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "sentry-backend", "engine": "postgresql+fastapi"}


# ---------------- EVENTS ----------------

@app.post("/events")
async def ingest_event(event: EventIn, db: Session = Depends(get_db)):
    try:
        db_event = Event(
            id=event.event_id,
            timestamp=event.timestamp,
            source_type=event.source_type,
            host_id=event.host_id,
            user_id=event.user_id,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            src_port=event.src_port,
            dst_port=event.dst_port,
            protocol=event.protocol,
            event_type=event.event_type,
            severity=event.severity,
            features=event.features,
            raw_data=event.raw_data,
        )
        db.add(db_event)
        db.commit()
        db.refresh(db_event)
    except Exception as e:
        print("[Sentry] DB event insert notice:", e)

    # Broadcast event straight to connected dashboards in real time
    try:
        data = event.model_dump(mode="json")
    except AttributeError:
        data = event.dict()
    await manager.broadcast({"type": "event", "data": data})

    return {"status": "ok", "event_id": str(event.event_id)}


@app.get("/events")
def list_events(limit: int = 100, db: Session = Depends(get_db)):
    try:
        events = db.query(Event).order_by(desc(Event.timestamp)).limit(limit).all()
        if events:
            return events
    except Exception as e:
        print("[Sentry] Event query notice:", e)

    # Flatten seed incident events as fallback
    fallback_events = []
    for inc in SEED_INCIDENTS:
        fallback_events.extend(inc.get("correlated_events") or [])
    return fallback_events[:limit]


# ---------------- INCIDENTS ----------------

@app.get("/incidents")
def list_incidents(limit: int = 50, db: Session = Depends(get_db)):
    try:
        incidents = db.query(Incident).order_by(desc(Incident.created_at)).limit(limit).all()
        if incidents:
            return incidents
    except Exception as e:
        print("[Sentry] Incident query notice:", e)

    return SEED_INCIDENTS[:limit]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            return incident
    except Exception as e:
        print("[Sentry] Single incident query notice:", e)

    for inc in SEED_INCIDENTS:
        if inc["incident_id"] == incident_id or inc.get("id") == incident_id:
            return inc

    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


# ---------------- ASSETS ----------------

@app.get("/assets")
def list_assets(db: Session = Depends(get_db)):
    try:
        assets = db.query(Asset).all()
        if assets:
            return assets
    except Exception:
        pass

    return [
        {"id": "a1", "hostname": "workstation-14.corp", "ip": "192.168.1.14", "os": "Windows 11", "status": "isolated"},
        {"id": "a2", "hostname": "srv-finance-02", "ip": "192.168.2.5", "os": "Ubuntu 22.04", "status": "normal"},
        {"id": "a3", "hostname": "demo-app-1", "ip": "10.0.0.10", "os": "Linux", "status": "normal"},
        {"id": "a4", "hostname": "demo-net-1", "ip": "10.0.0.20", "os": "Linux", "status": "normal"},
    ]


# ---------------- RESPONSE ACTIONS ----------------

@app.post("/actions/isolate")
async def isolate(request: HostActionRequest, db: Session = Depends(get_db)):
    result = isolate_host(request.container_name)

    if result.get("status") == "isolated":
        try:
            asset = db.query(Asset).filter(Asset.hostname == request.container_name).first()
            if asset:
                asset.status = "isolated"
                db.commit()
        except Exception:
            pass
        await manager.broadcast({"type": "action", "data": result})

    return result


@app.post("/actions/isolate-host")
async def isolate_host_alias(payload: dict, db: Session = Depends(get_db)):
    container = payload.get("container_name") or payload.get("host") or "unknown-host"
    return await isolate(HostActionRequest(container_name=container), db)


@app.post("/actions/restore")
async def restore(request: HostActionRequest, db: Session = Depends(get_db)):
    if not request.network_name:
        request.network_name = "sentry-net"

    result = restore_host(request.container_name, request.network_name)

    if result.get("status") == "restored":
        try:
            asset = db.query(Asset).filter(Asset.hostname == request.container_name).first()
            if asset:
                asset.status = "normal"
                db.commit()
        except Exception:
            pass
        await manager.broadcast({"type": "action", "data": result})

    return result


# ---------------- WEBSOCKET ----------------

@app.websocket("/ws")
@app.websocket("/ws/incidents")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep-alive receive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
