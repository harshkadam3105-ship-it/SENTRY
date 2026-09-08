from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import json
import asyncio
import random
from datetime import datetime, timezone
from typing import List

app = FastAPI(title="SentinelX Backend Stub", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MOCK_INCIDENTS = [
    {
        "incident_id": "INC-001",
        "created_at": "2026-09-08T08:12:34Z",
        "host": "workstation-14.corp",
        "user": "alice.chen",
        "severity": "critical",
        "risk_score": 0.94,
        "mitre_techniques": ["T1110", "T1078", "T1021"],
        "correlated_events": [
            {
                "event_id": "EVT-001a",
                "type": "auth_failure",
                "timestamp": "2026-09-08T08:10:11Z",
                "anomaly_score": 0.87,
                "rule_score": 0.95,
                "detail": "52 failed SSH login attempts from 192.168.1.105"
            },
            {
                "event_id": "EVT-001b",
                "type": "lateral_movement",
                "timestamp": "2026-09-08T08:12:05Z",
                "anomaly_score": 0.91,
                "rule_score": 0.89,
                "detail": "RDP connection to internal server dc-01.corp"
            }
        ],
        "explanation": "Brute-force credential attack succeeded; attacker pivoted laterally via RDP within 2 minutes of gaining access."
    },
    {
        "incident_id": "INC-002",
        "created_at": "2026-09-08T09:45:00Z",
        "host": "server-db-02.corp",
        "user": "bob.martinez",
        "severity": "high",
        "risk_score": 0.78,
        "mitre_techniques": ["T1048", "T1567"],
        "correlated_events": [
            {
                "event_id": "EVT-002a",
                "type": "data_exfiltration",
                "timestamp": "2026-09-08T09:43:00Z",
                "anomaly_score": 0.82,
                "rule_score": 0.74,
                "detail": "Unusual outbound DNS traffic: 4.2 GB to external resolver"
            }
        ],
        "explanation": "Large volume of data transferred via DNS tunneling to an external endpoint not in the allowlist."
    },
    {
        "incident_id": "INC-003",
        "created_at": "2026-09-08T10:22:15Z",
        "host": "laptop-dev-07.corp",
        "user": "carol.jones",
        "severity": "medium",
        "risk_score": 0.51,
        "mitre_techniques": ["T1059"],
        "correlated_events": [
            {
                "event_id": "EVT-003a",
                "type": "suspicious_process",
                "timestamp": "2026-09-08T10:21:00Z",
                "anomaly_score": 0.55,
                "rule_score": 0.48,
                "detail": "PowerShell execution with encoded command from user context"
            }
        ],
        "explanation": "Encoded PowerShell script executed from non-administrative user context. May indicate phishing payload."
    }
]

connected_websockets: List[WebSocket] = []


@app.get("/health")
async def health():
    return {"status": "ok", "service": "sentinelx-backend-stub"}


@app.get("/incidents")
async def get_incidents():
    return MOCK_INCIDENTS


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    for inc in MOCK_INCIDENTS:
        if inc["incident_id"] == incident_id:
            return inc
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@app.get("/events")
async def get_events():
    events = []
    for inc in MOCK_INCIDENTS:
        events.extend(inc.get("correlated_events") or [])
    return events


@app.get("/assets")
async def get_assets():
    hosts = list({inc["host"] for inc in MOCK_INCIDENTS})
    return [{"host": h, "status": "monitored"} for h in hosts]


@app.post("/ingest")
async def ingest(payload: dict):
    return {"status": "accepted", "payload": payload}


@app.post("/actions/isolate-host")
async def isolate_host(payload: dict):
    host = payload.get("host", "unknown")
    return {"status": "isolated", "host": host, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.websocket("/ws/incidents")
async def websocket_incidents(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        # Send initial batch
        for inc in MOCK_INCIDENTS:
            await websocket.send_text(json.dumps(inc))
            await asyncio.sleep(0.5)
        # Then push a new synthetic incident every 15s (demo mode)
        counter = len(MOCK_INCIDENTS) + 1
        while True:
            await asyncio.sleep(15)
            synthetic = {
                "incident_id": f"INC-{counter:03d}",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "host": random.choice(["workstation-03.corp", "server-api-01.corp", "laptop-mgmt-05.corp"]),
                "user": random.choice(["dave.kim", "eve.patel", "frank.wu"]),
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "risk_score": round(random.uniform(0.2, 0.99), 2),
                "mitre_techniques": random.sample(["T1110", "T1078", "T1021", "T1048", "T1059", "T1136"], 2),
                "correlated_events": [
                    {
                        "event_id": f"EVT-{counter:03d}a",
                        "type": "anomaly_detected",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "anomaly_score": round(random.uniform(0.3, 0.95), 2),
                        "rule_score": round(random.uniform(0.3, 0.95), 2),
                        "detail": "Synthetic demo event generated by stub backend"
                    }
                ],
                "explanation": "Stub-generated incident for demo pipeline testing."
            }
            await websocket.send_text(json.dumps(synthetic))
            counter += 1
    except WebSocketDisconnect:
        connected_websockets.remove(websocket)
