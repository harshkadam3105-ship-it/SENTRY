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

SEED_INCIDENTS_EXTRA = [
    {
        "incident_id": "INC-004",
        "id": "e4f6a67d-4567-8901-23de-f01234567891",
        "created_at": "2026-09-08T09:05:50Z",
        "host": "server-api-01.corp",
        "host_id": "server-api-01.corp",
        "user": "svc_account",
        "user_id": "svc_account",
        "severity": "high",
        "risk_score": 0.82,
        "mitre_techniques": ["T1136", "T1059", "T1098"],
        "explanation": "Unauthorized service account creation at 03:00 UTC followed by scheduled task persistence mechanism. Pattern strongly suggests attacker establishing long-term access foothold.",
        "correlated_events": [
            {
                "event_id": "EVT-004a",
                "type": "account_creation",
                "timestamp": "2026-09-08T09:03:00Z",
                "anomaly_score": 0.88,
                "rule_score": 0.76,
                "detail": "New service account 'svc_monitor2' created outside provisioning hours (03:00 UTC)",
            },
            {
                "event_id": "EVT-004b",
                "type": "persistence",
                "timestamp": "2026-09-08T09:04:30Z",
                "anomaly_score": 0.85,
                "rule_score": 0.79,
                "detail": "Scheduled task registered: runs encoded PowerShell at system startup",
            },
        ],
    },
    {
        "incident_id": "INC-005",
        "id": "f5a7b78e-5678-9012-34ef-012345678902",
        "created_at": "2026-09-08T10:34:00Z",
        "host": "workstation-31.corp",
        "host_id": "workstation-31.corp",
        "user": "dave.kim",
        "user_id": "dave.kim",
        "severity": "low",
        "risk_score": 0.23,
        "mitre_techniques": ["T1071"],
        "explanation": "Single outbound connection to an unrecognized IP on a non-standard port. Could be legitimate tool or minor policy violation. Flagged for review; low confidence of malicious intent.",
        "correlated_events": [
            {
                "event_id": "EVT-005a",
                "type": "network_anomaly",
                "timestamp": "2026-09-08T10:32:00Z",
                "anomaly_score": 0.28,
                "rule_score": 0.19,
                "detail": "Outbound connection on port 8443 to IP not in corporate egress allowlist",
            },
        ],
    },
    {
        "incident_id": "INC-006",
        "id": "a6b8c89f-6789-0123-45fa-123456789013",
        "created_at": "2026-09-08T11:18:42Z",
        "host": "laptop-mgmt-05.corp",
        "host_id": "laptop-mgmt-05.corp",
        "user": "eve.patel",
        "user_id": "eve.patel",
        "severity": "critical",
        "risk_score": 0.97,
        "mitre_techniques": ["T1003", "T1021", "T1078", "T1110"],
        "explanation": "CRITICAL: Active ransomware deployment in progress. Credential dumping via LSASS followed by rapid pass-the-hash propagation to 7 hosts. File encryption has begun. IMMEDIATE ISOLATION REQUIRED.",
        "correlated_events": [
            {
                "event_id": "EVT-006a",
                "type": "credential_dump",
                "timestamp": "2026-09-08T11:15:00Z",
                "anomaly_score": 0.99,
                "rule_score": 0.98,
                "detail": "LSASS memory access by non-system process — credential dumping detected (Mimikatz signature)",
            },
            {
                "event_id": "EVT-006b",
                "type": "lateral_movement",
                "timestamp": "2026-09-08T11:16:30Z",
                "anomaly_score": 0.95,
                "rule_score": 0.91,
                "detail": "Pass-the-hash lateral movement to 7 hosts in 90 seconds using dumped NTLM hashes",
            },
            {
                "event_id": "EVT-006c",
                "type": "ransomware_indicator",
                "timestamp": "2026-09-08T11:18:00Z",
                "anomaly_score": 0.97,
                "rule_score": 0.96,
                "detail": "Mass file encryption activity detected: 3,400 files modified with .locked extension",
            },
        ],
    },
    {
        "incident_id": "INC-007",
        "id": "b7c9d90a-7890-1234-56ab-234567890124",
        "created_at": "2026-09-08T12:01:11Z",
        "host": "server-file-03.corp",
        "host_id": "server-file-03.corp",
        "user": "frank.wu",
        "user_id": "frank.wu",
        "severity": "medium",
        "risk_score": 0.44,
        "mitre_techniques": ["T1083", "T1005"],
        "explanation": "Unusual file discovery and bulk staging of sensitive HR and finance documents. Activity pattern consistent with insider reconnaissance prior to exfiltration. No external connections observed yet.",
        "correlated_events": [
            {
                "event_id": "EVT-007a",
                "type": "file_discovery",
                "timestamp": "2026-09-08T11:59:00Z",
                "anomaly_score": 0.47,
                "rule_score": 0.41,
                "detail": "Recursive directory enumeration of /finance and /hr shares — 12,000 files indexed in 3 minutes",
            },
            {
                "event_id": "EVT-007b",
                "type": "data_collection",
                "timestamp": "2026-09-08T12:00:20Z",
                "anomaly_score": 0.45,
                "rule_score": 0.43,
                "detail": "Bulk copy of 850 MB from shared drive to local temp directory",
            },
        ],
    },
]

# Merge seed lists
SEED_INCIDENTS = SEED_INCIDENTS + SEED_INCIDENTS_EXTRA



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
