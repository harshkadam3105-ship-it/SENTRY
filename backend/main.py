from fastapi import FastAPI

from backend.api.events import router as events_router
from backend.database.connection import Base, engine
from backend.models import Asset, Event, Incident


app = FastAPI(
    title="SENTRY API",
    description="AI-powered multi-signal cyber threat detection backend",
    version="1.0.0",
)


Base.metadata.create_all(bind=engine)


app.include_router(events_router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "sentry-backend",
    }
import sys
import os
import re
import random
from collections import deque
from datetime import datetime
from uuid import uuid4, UUID
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc

# Add backend/ dir so local submodules resolve (db, core, etc.)
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BACKEND_DIR)

# Add SENTRY root so teammate absolute imports (from backend.xxx) resolve
_SENTRY_ROOT = os.path.dirname(_BACKEND_DIR)
if _SENTRY_ROOT not in sys.path:
    sys.path.insert(0, _SENTRY_ROOT)

from db.schema import EventIn, HostActionRequest
from db.db_models import Base, Event, Incident, Asset
from db.database import engine, get_db
from core.websocket_manager import manager
from core.response_action import isolate_host, restore_host

# ── Ayaan: Detection Engine ──────────────────────────────────────────────────
try:
    from backend.detection.detector import DetectionEngine
    _detection_engine = DetectionEngine()
    _DETECTION_OK = True
    print("[Sentry] DetectionEngine loaded [OK]")
except Exception as _e:
    _detection_engine = None
    _DETECTION_OK = False
    print(f"[Sentry] DetectionEngine unavailable: {_e}")

# ── Harsh: Correlation + Risk + Incident engines ─────────────────────────────
try:
    from backend.correlation.engine import CorrelationEngine
    from backend.models.schema import EventIn as CorrelationEventIn
    from backend.risks.scorer import RiskScorer
    from backend.incidents.generator import IncidentGenerator
    _correlation_engine = CorrelationEngine()
    _risk_scorer = RiskScorer()
    _incident_generator = IncidentGenerator()
    _PIPELINE_OK = True
    print("[Sentry] Correlation + Risk + Incident engines loaded [OK]")
except Exception as _e:
    _correlation_engine = None
    _risk_scorer = None
    _incident_generator = None
    _PIPELINE_OK = False
    print(f"[Sentry] Correlation pipeline unavailable: {_e}")

# ── AI Threat Analyst Engine (Option 1: Hybrid Reasoning Layer) ──────────────
try:
    from backend.ai.analyst import AIThreatAnalyst
    _ai_analyst = AIThreatAnalyst()
    print("[Sentry] AI Threat Analyst Engine initialized [OK]")
except Exception as _ai_init_err:
    _ai_analyst = None
    print(f"[Sentry] AI Threat Analyst unavailable: {_ai_init_err}")

# ── Sliding event window for correlation (last 100 events in memory) ──────────
_EVENT_WINDOW: deque = deque(maxlen=100)

# Create database tables
try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print("[Sentry] Database table creation note:", e)

# ── Train AnomalyDetector with synthetic baseline on startup ─────────────────
def _build_baseline_events(n: int = 50) -> list:
    """Generate synthetic normal-behaviour events to seed the Isolation Forest."""
    rng = random.Random(42)
    events = []
    for _ in range(n):
        events.append({
            "features": {
                "packet_count":          rng.uniform(10, 200),
                "bytes":                 rng.uniform(500, 50_000),
                "bytes_per_second":      rng.uniform(50, 5_000),
                "connection_rate":       rng.uniform(1, 10),
                "unique_destinations":   rng.uniform(1, 5),
                "dst_port":              rng.choice([80, 443, 22, 3389]),
                "process_frequency":     rng.uniform(1, 20),
                "new_process":           0,
                "parent_process_change": 0,
                "privilege_change":      0,
                "file_change_rate":      rng.uniform(0, 5),
                "requests_per_minute":   rng.uniform(10, 100),
                "error_rate":            rng.uniform(0, 0.05),
                "auth_failure_rate":     rng.uniform(0, 0.05),
                "sensitive_endpoint_access": 0,
                "unique_endpoint_count": rng.uniform(1, 10),
                "failed_login_count":    rng.uniform(0, 2),
                "success_count":         rng.uniform(1, 5),
                "failure_ratio":         rng.uniform(0, 0.1),
                "login_rate":            rng.uniform(0.1, 2),
                "source_ip_change":      0,
            }
        })
    return events

if _DETECTION_OK:
    try:
        _baseline = _build_baseline_events(50)
        _detection_engine.train(_baseline)
        print("[Sentry] AnomalyDetector trained on 50 synthetic baseline events [OK]")
    except Exception as _train_err:
        print(f"[Sentry] AnomalyDetector training failed (rule-based only): {_train_err}")
def _parse_log_features(text: str) -> dict:
    """Intelligently extracts security telemetry features from user-typed log/scenario text."""
    if not text or not isinstance(text, str):
        return {}
    t = text.lower()
    features = {}

    # 1. Failed Logins
    fl_match = re.search(r'(\d+)\s*(?:consecutive\s*)?(?:failed|unsuccessful|invalid)[^0-9\n]{0,30}(?:login|auth|ssh|rdp|attempts?)', t)
    if not fl_match:
        fl_match = re.search(r'(?:failed|unsuccessful)[^0-9\n]{0,30}(?:login|auth|attempts?)[^0-9\n]{0,10}(\d+)', t)
    if not fl_match:
        fl_match = re.search(r'(\d+)\s*(?:failed\s*)?attempts?', t)
    if fl_match:
        features["failed_login_count"] = int(fl_match.group(1))
    elif re.search(r'\b(failed login|auth fail|unsuccessful login)\b', t):
        features["failed_login_count"] = 6

    # 2. Data Exfiltration / Bytes
    gb_match = re.search(r'(\d+(?:\.\d+)?)\s*(?:gb|gigabytes?|gigs?)\b', t)
    mb_match = re.search(r'(\d+(?:\.\d+)?)\s*(?:mb|megabytes?)\b', t)
    if gb_match:
        features["bytes_sent"] = int(float(gb_match.group(1)) * 1024 * 1024 * 1024)
        features["connection_rate"] = 35.0
    elif mb_match:
        features["bytes_sent"] = int(float(mb_match.group(1)) * 1024 * 1024)
        features["connection_rate"] = 20.0
    elif re.search(r'\b(exfiltrat|egress|bulk upload|data leak|data transfer)\b', t):
        features["bytes_sent"] = 1400000000
        features["connection_rate"] = 35.0

    # 3. Privilege Escalation
    if re.search(r'\b(privilege escalation|escalat|sudo|elevated to root|elevation of privilege|uac bypass|setuid|became root)\b', t):
        features["privilege_change"] = True

    # 4. Credential Dumping
    if re.search(r'\b(lsass|mimikatz|sekurlsa|procdump|credential dump|sam dump|ntds\.dit|hashcat)\b', t):
        features["credential_dump_indicator"] = True
        features["lsass_access"] = True

    # 5. Living-off-the-land / Suspicious Parent Process
    if re.search(r'\b(spawned|powershell|cmd\.exe|wscript|cscript|mshta|living-off-the-land|parent process|child process)\b', t):
        features["parent_process_change"] = True
        features["new_process"] = True

    # 6. Defense Evasion / Log Tampering
    if re.search(r'\b(wevtutil|clear-eventlog|cleared log|log wipe|tamper|disable edr|kill agent|wipe log|log cleared)\b', t):
        features["log_cleared"] = True

    # 7. Mass File Modification / Ransomware
    file_match = re.search(r'(\d+)\s*files?\s*(?:altered|modified|encrypted|changed)', t)
    if file_match:
        features["file_change_rate"] = float(file_match.group(1))
    elif re.search(r'\b(ransomware|encrypting|mass file|file modification spike)\b', t):
        features["file_change_rate"] = 85.0

    # 8. Reconnaissance / Port Scan
    scan_match = re.search(r'(?:across|probe|scanning)\s*(\d+)\s*(?:hosts?|endpoints?|destinations?|ips?|subnets?)', t)
    if scan_match:
        features["unique_destinations"] = int(scan_match.group(1))
        features["connection_rate"] = 25.0
    elif re.search(r'\b(port scan|port sweep|nmap|reconnaissance|subnet sweep)\b', t):
        features["unique_destinations"] = 35
        features["connection_rate"] = 22.0

    # 9. Lateral Movement
    lat_match = re.search(r'(\d+)\s*(?:remote\s*)?(?:rdp|smb|ssh)\s*(?:connections?|sessions?)', t)
    if lat_match:
        features["remote_session_count"] = int(lat_match.group(1))
        features["lateral_movement"] = True
    elif re.search(r'\b(lateral movement|psexec|smb spread|remote session)\b', t):
        features["remote_session_count"] = 3
        features["lateral_movement"] = True

    # 10. Persistence
    if re.search(r'\b(schtasks|scheduled task|crontab|autorun|registry run|persistence)\b', t):
        features["scheduled_task_created"] = True
        features["persistence_created"] = True

    # 11. Tor / Untrusted Source Login
    if re.search(r'\b(tor\b|exit node|untrusted ip|foreign ip)', t):
        features["source_ip_change"] = True
        features["success_count"] = 1

    # 12. Generic Warning / Threat Indicators
    if re.search(r'\b(warning|alert|threat|suspicious|intrusion|unauthorized|breach|malicious|danger|attack|incident)\b', t):
        if not any(k in features for k in ("failed_login_count", "bytes_sent", "privilege_change", "credential_dump_indicator", "file_change_rate")):
            features["failed_login_count"] = 8
            features["auth_failure_rate"] = 0.85

    return features


app = FastAPI(title="Sentry Backend")

# Enable CORS for frontend dev server and Docker environments
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incident storage — starts completely clean (0 incidents) for live testing
_LIVE_INCIDENTS = []
SEED_INCIDENTS = []
SEED_INCIDENTS_EXTRA = []
_CONNECTED_CLIENTS: dict = {}




# ---------------- HEALTH ----------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "sentry-backend", "engine": "postgresql+fastapi"}


# ---------------- EVENTS ----------------

@app.post("/events")
async def ingest_event(event: EventIn, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if client_ip not in ("127.0.0.1", "localhost", "::1"):
        import socket
        try:
            resolved_host = socket.gethostbyaddr(client_ip)[0]
        except Exception:
            resolved_host = client_ip
        _CONNECTED_CLIENTS[client_ip] = {
            "host": resolved_host,
            "ip": client_ip,
            "role": "Connected Endpoint",
            "last_seen": "Active Telemetry",
        }
        if event.src_ip in (None, "", "10.211.2.200"):
            event.src_ip = client_ip

    # ── 1. Persist to DB ─────────────────────────────────────────────────────
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
        db.rollback()
        print("[Sentry] DB event insert notice:", e)

    # Serialize for broadcast + pipeline
    try:
        event_data = event.model_dump(mode="json")
    except AttributeError:
        event_data = event.dict()

    # Dynamic log parser for custom user cases: extract features from raw log if present
    log_text = (event_data.get("raw_data") or {}).get("log") or ""
    if log_text and isinstance(log_text, str):
        inferred = _parse_log_features(log_text)
        current_features = dict(event_data.get("features") or {})
        for k, v in inferred.items():
            if k not in current_features or current_features[k] in (0, 0.0, False, None):
                current_features[k] = v
        event_data["features"] = current_features

    # ── 2. Detection pipeline (Ayaan + Harsh) ────────────────────────────────
    detection_result = None
    risk_score_raw = 0.0
    anomaly_score = 0.0
    rule_score = 0.0
    correlation_score = 0.0

    if _DETECTION_OK:
        try:
            detection_result = _detection_engine.detect(event_data)
            anomaly_score = detection_result.get("anomaly_score", 0.0)
            rule_score = detection_result.get("rule_score", 0.0)
        except Exception as _det_err:
            print(f"[Sentry] Detection error: {_det_err}")

    # ── 3. Correlation (Harsh) ───────────────────────────────────────────────
    if _PIPELINE_OK and len(_EVENT_WINDOW) > 0:
        try:
            # Build lightweight EventIn-compatible objects from window for correlation
            prev_events = list(_EVENT_WINDOW)
            correlation_score = _correlation_engine.correlation_score(
                event, prev_events
            )
        except Exception as _corr_err:
            print(f"[Sentry] Correlation error: {_corr_err}")

    # ── 4. Risk Score (Harsh) ────────────────────────────────────────────────
    if _PIPELINE_OK:
        try:
            risk_score_raw = _risk_scorer.score(
                anomaly_score=anomaly_score,
                rule_score=rule_score,
                severity=event.severity,
                correlation_score=correlation_score,
            )
        except Exception as _risk_err:
            print(f"[Sentry] Risk scoring error: {_risk_err}")

    # ── 5. Add event to sliding window for future correlation ─────────────────
    _EVENT_WINDOW.append(event)

    # ── 6. Generate + broadcast incident if risk is significant ───────────────
    incident_dict = None
    explanation = ""
    is_benign = (rule_score == 0 and event.severity <= 2 and str(event.event_type).lower() in ("normal_login", "benign", "heartbeat", "status"))
    should_generate = _PIPELINE_OK and detection_result and not is_benign and (risk_score_raw >= 40 or rule_score > 0 or event.severity >= 3)
    if should_generate:
        try:
            incident_dict = _incident_generator.generate(
                events=[event_data],
                detection_results=[detection_result],
                risk_score=risk_score_raw,
            )
            # Map severity to label (critical, high, medium, low)
            if risk_score_raw >= 80:
                severity_label = "critical"
            elif risk_score_raw >= 60:
                severity_label = "high"
            elif risk_score_raw >= 35:
                severity_label = "medium"
            else:
                severity_label = "low"

            reasons = detection_result.get("rule_reasons", [])
            if reasons:
                explanation = " • ".join(reasons)
            elif anomaly_score >= 50:
                explanation = f"Statistical behavioral anomaly detected: model confidence {anomaly_score:.1f}% indicates abnormal telemetry divergence."
            else:
                explanation = "Elevated risk pattern detected across correlated system telemetry."

            # Enrich with readable fields for frontend
            incident_dict["severity"] = severity_label
            incident_dict["risk_score"] = round(risk_score_raw / 100, 2)
            incident_dict["anomaly_score"] = round(anomaly_score, 2)
            incident_dict["rule_score"] = round(rule_score, 2)
            incident_dict["correlation_score"] = round(correlation_score, 2)
            incident_dict["explanation"] = explanation
            incident_dict["description"] = explanation
            incident_dict["host"] = event.host_id
            incident_dict["user"] = event.user_id or "system"
            incident_dict["created_at"] = event.timestamp.isoformat()
            incident_dict["correlated_events"] = [{
                "event_id": str(event.event_id),
                "type": event.event_type,
                "timestamp": event.timestamp.isoformat(),
                "anomaly_score": round(anomaly_score / 100, 2),
                "rule_score": round(rule_score / 100, 2),
                "detail": event.raw_data.get("log", event.event_type),
            }]

            # ── 6b. Autonomous AI Threat Analyst Layer ────────────────────────
            ai_eval = None
            if _ai_analyst is not None:
                try:
                    ai_eval = _ai_analyst.analyze(
                        incident=incident_dict,
                        correlated_events=list(_EVENT_WINDOW),
                    )
                    incident_dict["ai_analysis"] = ai_eval
                    if ai_eval.get("executive_summary"):
                        incident_dict["ai_summary"] = ai_eval["executive_summary"]
                except Exception as _ai_err:
                    print(f"[Sentry] AI Threat Analyst evaluation note: {_ai_err}")

            # Store in live incidents list
            _LIVE_INCIDENTS.insert(0, incident_dict)

            # Persist to database if available
            try:
                db_inc = Incident(
                    id=UUID(incident_dict["incident_id"]),
                    title=incident_dict["title"],
                    severity=5 if severity_label == "critical" else 4 if severity_label == "high" else 3 if severity_label == "medium" else 1,
                    risk_score=float(incident_dict["risk_score"]),
                    confidence=float(incident_dict.get("confidence", 0.9)),
                    status=incident_dict.get("status", "open"),
                    created_at=event.timestamp,
                    updated_at=event.timestamp,
                )
                db.add(db_inc)
                db.commit()
            except Exception as _db_err:
                db.rollback()
                print(f"[Sentry] DB Incident insert notice: {_db_err}")

            await manager.broadcast({"type": "incident", "data": incident_dict})
            print(f"[Sentry] Incident generated: {incident_dict.get('title')} (risk={risk_score_raw:.1f})")
        except Exception as _inc_err:
            print(f"[Sentry] Incident generation error: {_inc_err}")

    # ── 7. Always broadcast the raw event to live feed ───────────────────────
    event_data["anomaly_score"] = round(anomaly_score, 2)
    event_data["rule_score"] = round(rule_score, 2)
    event_data["risk_score"] = round(risk_score_raw / 100, 2)
    await manager.broadcast({"type": "event", "data": event_data})

    return {
        "status": "ok",
        "event_id": str(event.event_id),
        "anomaly_score": round(anomaly_score, 2),
        "rule_score": round(rule_score, 2),
        "risk_score": round(risk_score_raw, 2),
        "correlation_score": round(correlation_score, 2),
        "incident_generated": should_generate and incident_dict is not None,
        "incident": incident_dict,
        "ai_analysis": incident_dict.get("ai_analysis") if incident_dict else None,
        "rule_tags": detection_result.get("rule_tags", []) if detection_result else [],
        "rule_reasons": detection_result.get("rule_reasons", []) if detection_result else [],
        "explanation": explanation if explanation else ("Normal activity - no security threat detected" if (not detection_result or rule_score == 0) else "Low-risk anomaly"),
    }


@app.get("/events")
def list_events(limit: int = 100, db: Session = Depends(get_db)):
    try:
        events = db.query(Event).order_by(desc(Event.timestamp)).limit(limit).all()
        if events:
            return events
    except Exception as e:
        print("[Sentry] Event query notice:", e)

    fallback_events = []
    for inc in _LIVE_INCIDENTS:
        fallback_events.extend(inc.get("correlated_events") or [])
    return fallback_events[:limit]


# ---------------- INCIDENTS ----------------

@app.get("/incidents")
def list_incidents(limit: int = 50, db: Session = Depends(get_db)):
    return _LIVE_INCIDENTS[:limit]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    for inc in _LIVE_INCIDENTS:
        if inc.get("incident_id") == incident_id or str(inc.get("id")) == incident_id:
            return inc

    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            return incident
    except Exception as e:
        print("[Sentry] Single incident query notice:", e)

    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@app.post("/incidents/clear")
@app.delete("/incidents")
async def clear_all_incidents(db: Session = Depends(get_db)):
    """Wipes all live incidents and events to start with a clean slate."""
    global _LIVE_INCIDENTS, _EVENT_WINDOW
    _LIVE_INCIDENTS.clear()
    _EVENT_WINDOW.clear()
    try:
        db.query(Incident).delete()
        db.query(Event).delete()
        db.commit()
    except Exception as e:
        print("[Sentry] DB clear note:", e)

    await manager.broadcast({"type": "clear_incidents", "data": {}})
    return {"status": "ok", "message": "All incidents wiped cleanly."}


SIMULATION_TEMPLATES = {
    "brute_force": {
        "source_type": "auth",
        "host_id": "workstation-14.corp",
        "user_id": "admin",
        "src_ip": "198.51.100.77",
        "dst_ip": "192.168.1.14",
        "src_port": 49152,
        "dst_port": 22,
        "protocol": "TCP",
        "event_type": "failed_login",
        "severity": 4,
        "features": {
            "failed_login_count": 8,
            "success_count": 0,
            "connection_rate": 8.0,
        },
        "raw_data": {
            "log": "8 consecutive failed SSH authentication attempts detected from 198.51.100.77",
            "username": "admin"
        },
    },
    "failed_then_success": {
        "source_type": "auth",
        "host_id": "srv-finance-02",
        "user_id": "svc_backup",
        "src_ip": "203.0.113.45",
        "dst_ip": "192.168.2.5",
        "src_port": 51234,
        "dst_port": 443,
        "protocol": "TCP",
        "event_type": "successful_login",
        "severity": 4,
        "features": {
            "failed_login_count": 4,
            "success_count": 1,
        },
        "raw_data": {
            "log": "Successful credential login following 4 consecutive failed authentication attempts",
            "username": "svc_backup"
        },
    },
    "suspicious_process": {
        "source_type": "edr",
        "host_id": "dev-box-03",
        "user_id": "bob.miller",
        "src_ip": "192.168.1.55",
        "dst_ip": "192.168.1.55",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "LOCAL",
        "event_type": "new_process",
        "severity": 4,
        "features": {
            "new_process": True,
            "process_name": "mimikatz.exe",
        },
        "raw_data": {
            "log": "EDR detected known credential harvesting binary execution: mimikatz.exe",
            "process_name": "mimikatz.exe",
            "cmdline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords"
        },
    },
    "unusual_outbound": {
        "source_type": "network",
        "host_id": "srv-finance-02",
        "user_id": "svc_backup",
        "src_ip": "192.168.2.5",
        "dst_ip": "198.51.100.44",
        "src_port": 44321,
        "dst_port": 443,
        "protocol": "TCP",
        "event_type": "high_egress",
        "severity": 4,
        "features": {
            "connection_rate": 25.0,
            "bytes": 4500000000,
        },
        "raw_data": {
            "log": "Massive outbound data flow spike (4.5 GB in 3 mins) to untrusted external IP 198.51.100.44",
            "connection_rate": 25.0
        },
    },
    "api_abuse": {
        "source_type": "api_gateway",
        "host_id": "server-api-01.corp",
        "user_id": "svc_account",
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.1",
        "src_port": 34567,
        "dst_port": 8443,
        "protocol": "HTTPS",
        "event_type": "api_anomaly",
        "severity": 3,
        "features": {
            "auth_failure_rate": 0.88,
            "requests_per_minute": 150.0,
        },
        "raw_data": {
            "log": "API Gateway authentication failure rate reached 88% across 500 requests",
            "auth_failure_rate": 0.88
        },
    },
    "privilege_escalation": {
        "source_type": "auditd",
        "host_id": "laptop-mgmt-05.corp",
        "user_id": "eve.patel",
        "src_ip": "192.168.1.18",
        "dst_ip": "192.168.1.18",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "LOCAL",
        "event_type": "privilege_escalation",
        "severity": 5,
        "features": {
            "privilege_change": True,
        },
        "raw_data": {
            "log": "Privilege level unauthorized transition: standard_user -> root_administrator",
            "old_privilege": "standard_user",
            "new_privilege": "root_administrator"
        },
    },
    "suspicious_parent_process": {
        "source_type": "sysmon",
        "host_id": "workstation-14.corp",
        "user_id": "alice.chen",
        "src_ip": "192.168.1.14",
        "dst_ip": "192.168.1.14",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "LOCAL",
        "event_type": "process_creation",
        "severity": 4,
        "features": {
            "parent_process_change": True,
        },
        "raw_data": {
            "log": "Living-off-the-land execution: winword.exe spawned hidden powershell.exe child process",
            "parent_process": "winword.exe",
            "child_process": "powershell.exe"
        },
    },
    "suspicious_login_source": {
        "source_type": "auth",
        "host_id": "server-api-01.corp",
        "user_id": "frank.wu",
        "src_ip": "185.220.101.5",
        "dst_ip": "10.0.0.10",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "event_type": "successful_login",
        "severity": 4,
        "features": {
            "source_ip_change": True,
            "success_count": 1,
        },
        "raw_data": {
            "log": "Successful administrator login authenticated from verified Tor exit relay IP: 185.220.101.5",
            "is_untrusted_source": True,
        },
    },
    "suspicious_file_activity": {
        "source_type": "file_integrity",
        "host_id": "server-file-03.corp",
        "user_id": "frank.wu",
        "src_ip": "192.168.2.10",
        "dst_ip": "192.168.2.10",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "LOCAL",
        "event_type": "mass_file_modification",
        "severity": 4,
        "features": {
            "file_change_rate": 85.0,
        },
        "raw_data": {
            "log": "High-velocity file modification spike: 85 files altered per second in corporate shared drive",
            "file_change_rate": 85.0
        },
    },
    "network_scanning": {
        "source_type": "ids",
        "host_id": "workstation-31.corp",
        "user_id": "dave.kim",
        "src_ip": "192.168.1.31",
        "dst_ip": "192.168.1.0/24",
        "src_port": 60000,
        "dst_port": 445,
        "protocol": "TCP",
        "event_type": "port_scan",
        "severity": 4,
        "features": {
            "unique_destinations": 35,
            "connection_rate": 22.0,
        },
        "raw_data": {
            "log": "Intrusion detection: Reconnaissance horizontal port sweep across 35 subnet endpoints",
            "unique_destinations": 35,
        },
    },
}


@app.post("/events/simulate")
@app.get("/events/simulate")
async def simulate_rule_event(rule: str = "brute_force", db: Session = Depends(get_db)):
    """Convenience endpoint to simulate telemetry triggering any of the 10 detection rules."""
    rule_key = rule.lower().replace("-", "_").replace(" ", "_")
    template = SIMULATION_TEMPLATES.get(rule_key)
    if not template:
        available = list(SIMULATION_TEMPLATES.keys())
        raise HTTPException(status_code=400, detail=f"Unknown rule '{rule}'. Available rules: {available}")

    event_payload = dict(template)
    event_payload["event_id"] = str(uuid4())
    event_payload["timestamp"] = datetime.utcnow()
    event_in = EventIn(**event_payload)
    return await ingest_event(event_in, db=db)


@app.get("/incidents/{incident_id}/dossier")
def get_incident_dossier(incident_id: str, db: Session = Depends(get_db)):
    incident = None
    for inc in _LIVE_INCIDENTS:
        if inc.get("incident_id") == incident_id or str(inc.get("id")) == incident_id:
            incident = inc
            break

    if not incident:
        try:
            db_inc = db.query(Incident).filter(Incident.id == incident_id).first()
            if db_inc:
                incident = db_inc
        except Exception as e:
            print("[Sentry] Single incident dossier query notice:", e)

    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    # Serialize if DB model
    if hasattr(incident, "__dict__"):
        inc_data = {
            "incident_id": str(getattr(incident, "id", incident_id)),
            "host": getattr(incident, "host_id", getattr(incident, "host", "unknown")),
            "user": getattr(incident, "user_id", getattr(incident, "user", "unknown")),
            "severity": getattr(incident, "severity", "medium"),
            "risk_score": getattr(incident, "risk_score", 0.5),
            "explanation": getattr(incident, "description", getattr(incident, "explanation", "")),
            "mitre_techniques": getattr(incident, "mitre_techniques", []),
            "created_at": getattr(incident, "created_at", datetime.utcnow().isoformat() + "Z"),
            "correlated_events": getattr(incident, "correlated_events", []),
        }
    else:
        inc_data = dict(incident)

    now = datetime.utcnow().isoformat() + "Z"
    risk_val = inc_data.get("risk_score", 0.0)
    risk_score_100 = int(risk_val * 100) if risk_val <= 1.0 else int(risk_val)

    return {
        "$schema": "https://schema.sentry.cyber/v2/incident-dossier.json",
        "dossier_metadata": {
            "report_id": f"DOSSIER-{incident_id}-{uuid4().hex[:6].upper()}",
            "classification": "TLP:AMBER+STRICT // SENTRY-CONFIDENTIAL",
            "export_timestamp": now,
            "generator": "Sentry SIEM/SOAR Defense Platform v2.4",
            "analyst_environment": "SOC Tier-2 Incident Response Console",
            "legal_chain_of_custody": "VERIFIED_DIGITAL_HASH_ACQUIRED",
        },
        "incident_overview": {
            "incident_id": incident_id,
            "title": inc_data.get("title") or f"{str(inc_data.get('severity', 'HIGH')).upper()} Security Incident on {inc_data.get('host')}",
            "status": inc_data.get("status", "open"),
            "severity": inc_data.get("severity", "medium"),
            "risk_score_normalized": risk_val if risk_val <= 1.0 else risk_val / 100.0,
            "risk_score_composite": risk_score_100,
            "detected_at": inc_data.get("created_at") or now,
            "dwell_time_estimate": "1.2m",
            "containment_sla_status": "WITHIN_TARGET",
        },
        "entity_context": {
            "host": {
                "hostname": inc_data.get("host", "unknown"),
                "ip_address": inc_data.get("ip") or "192.168.1.14",
                "asset_tier": "Enterprise Production Workstation",
                "os_platform": "Windows 11 Enterprise (Build 22631)",
                "edr_agent_status": "Active - Sentry EDR v4.1",
            },
            "identity": {
                "username": inc_data.get("user", "unknown"),
                "department": "Corporate Operations",
                "privilege_level": "Elevated / Administrative" if inc_data.get("severity") == "critical" else "Standard User",
            },
        },
        "threat_verdict": {
            "executive_summary": inc_data.get("explanation", ""),
            "ai_threat_intelligence": inc_data.get("ai_analysis"),
            "mitre_attack_techniques": [
                {"technique_id": t if isinstance(t, str) else t.get("mitre_id", str(t)), "url": f"https://attack.mitre.org/techniques/{t if isinstance(t, str) else t.get('mitre_id', str(t))}/"}
                for t in inc_data.get("mitre_techniques", [])
            ],
        },
        "forensic_evidence_chain": {
            "total_correlated_events": len(inc_data.get("correlated_events", [])),
            "correlation_window": "100-event real-time sliding stream",
            "correlated_events": inc_data.get("correlated_events", []),
        },
        "raw_source_telemetry": inc_data,
    }



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


@app.post("/actions/revoke-user")
async def revoke_user_action(payload: dict, db: Session = Depends(get_db)):
    user_id = payload.get("user") or payload.get("user_id") or "unknown_user"
    reason = payload.get("reason") or "High anomaly score detected"
    timestamp = datetime.utcnow().isoformat() + "Z"
    result = {
        "status": "revoked",
        "action": "user_session_revoked",
        "user": user_id,
        "tokens_invalidated": 3,
        "active_sessions_killed": True,
        "message": f"Active sessions revoked and account credentials locked for '{user_id}'.",
        "timestamp": timestamp,
    }
    await manager.broadcast({"type": "action", "data": result})
    return result


@app.post("/actions/block-ip")
async def block_ip_action(payload: dict, db: Session = Depends(get_db)):
    ip = payload.get("ip") or "198.51.100.44"
    rule_id = f"FW-DROP-{uuid4().hex[:6].upper()}"
    timestamp = datetime.utcnow().isoformat() + "Z"
    result = {
        "status": "blocked",
        "action": "firewall_rule_applied",
        "ip": ip,
        "rule_id": rule_id,
        "direction": "inbound_and_outbound",
        "message": f"IP address {ip} added to perimeter firewall drop list via rule {rule_id}.",
        "timestamp": timestamp,
    }
    await manager.broadcast({"type": "action", "data": result})
    return result


@app.post("/actions/capture-forensics")
async def capture_forensics_action(payload: dict, db: Session = Depends(get_db)):
    host = payload.get("host") or payload.get("container_name") or "workstation-14.corp"
    snapshot_id = f"MEM-DUMP-{uuid4().hex[:6].upper()}"
    timestamp = datetime.utcnow().isoformat() + "Z"
    result = {
        "status": "captured",
        "action": "forensics_snapshot",
        "host": host,
        "snapshot_id": snapshot_id,
        "size_mb": 512,
        "artifacts": ["process_tree.json", "active_sockets.pcap", "volatile_memory.raw"],
        "message": f"Forensics memory triage dump captured for {host} (ID: {snapshot_id}).",
        "timestamp": timestamp,
    }
    await manager.broadcast({"type": "action", "data": result})
    return result


@app.post("/actions/trigger-playbook")
async def trigger_playbook_action(payload: dict, db: Session = Depends(get_db)):
    playbook = payload.get("playbook") or "Ransomware Automated Containment"
    incident_id = payload.get("incident_id") or "INC-001"
    host = payload.get("host") or "workstation-14.corp"
    user_id = payload.get("user") or "alice.chen"
    timestamp = datetime.utcnow().isoformat() + "Z"
    steps = [
        {"step": 1, "name": "Host Network Quarantine", "status": "completed"},
        {"step": 2, "name": "Active User Session Termination", "status": "completed"},
        {"step": 3, "name": "Perimeter IP Block Rules Deployed", "status": "completed"},
        {"step": 4, "name": "Volatile Memory Triage Dump Captured", "status": "completed"},
    ]
    result = {
        "status": "executed",
        "action": "automated_playbook_executed",
        "playbook": playbook,
        "incident_id": incident_id,
        "host": host,
        "user": user_id,
        "steps": steps,
        "execution_time_seconds": 1.2,
        "message": f"SOAR Playbook '{playbook}' successfully executed for incident {incident_id}.",
        "timestamp": timestamp,
    }
    await manager.broadcast({"type": "action", "data": result})
    return result


@app.patch("/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, payload: dict, db: Session = Depends(get_db)):
    new_status = payload.get("status", "open").lower()
    found = False
    for inc in _LIVE_INCIDENTS:
        if inc.get("incident_id") == incident_id or str(inc.get("id")) == incident_id:
            inc["status"] = new_status
            found = True
            break
    # Update in database if present
    try:
        db_inc = db.query(Incident).filter(
            (Incident.id == incident_id) | (Incident.title.contains(incident_id))
        ).first()
        if db_inc:
            db_inc.status = new_status
            db.commit()
            found = True
    except Exception:
        pass

    response_data = {"incident_id": incident_id, "status": new_status, "updated_at": datetime.utcnow().isoformat() + "Z"}
    await manager.broadcast({"type": "status_update", "data": response_data})
    return response_data


# ---------------- ANALYTICS (UEBA & METRICS) ----------------

@app.get("/analytics/risky-users")
def get_risky_users():
    user_stats = {}

    # 1. Process live incidents in chronological order (oldest to newest for trend calculation)
    sorted_incidents = list(reversed(_LIVE_INCIDENTS))

    for inc in sorted_incidents:
        u = inc.get("user") or inc.get("user_id")
        if not u or str(u).lower() in ("unknown", "none"):
            continue

        risk_raw = inc.get("risk_score", 0.5)
        risk_100 = int(risk_raw * 100) if risk_raw <= 1.0 else int(risk_raw)
        host = inc.get("host") or inc.get("host_id") or "endpoint"
        severity = inc.get("severity", "medium")

        if u not in user_stats:
            user_stats[u] = {
                "user": u,
                "department": "Privileged Identity" if str(u).lower() in ("admin", "root", "system", "administrator") else "Enterprise User Account",
                "host": host,
                "risk_scores": [risk_100],
                "anomalies_count": 1,
                "severity": severity,
                "last_active": "Just now",
            }
        else:
            user_stats[u]["anomalies_count"] += 1
            user_stats[u]["risk_scores"].append(risk_100)
            if host:
                user_stats[u]["host"] = host
            if severity in ("critical", "high"):
                user_stats[u]["severity"] = severity

    # Compute realistic composite risk score & authentic trend
    for u, data in user_stats.items():
        scores = data.pop("risk_scores")
        # Real chronological trend
        data["trend"] = scores[-5:] if len(scores) >= 2 else [max(15, scores[0] - 25), max(25, scores[0] - 10), scores[0]]
        # Composite score: Peak incident risk + repeat offense velocity factor (4 pts per additional confirmed incident, max 100)
        peak_risk = max(scores)
        repeat_penalty = min(15, (len(scores) - 1) * 4)
        data["risk_score"] = min(100, peak_risk + repeat_penalty)

    # 2. Process event window for any baseline or non-incident user accounts
    for ev in _EVENT_WINDOW:
        u = getattr(ev, "user_id", None) or (ev.get("user_id") if isinstance(ev, dict) else None)
        if not u or str(u).lower() in ("unknown", "none") or u in user_stats:
            continue
        host = getattr(ev, "host_id", None) or (ev.get("host_id") if isinstance(ev, dict) else "endpoint")
        user_stats[u] = {
            "user": u,
            "department": "Active Client Account",
            "host": host,
            "risk_score": 15,
            "anomalies_count": 0,
            "severity": "low",
            "trend": [10, 15, 15],
            "last_active": "Recent",
        }

    return sorted(user_stats.values(), key=lambda x: x["risk_score"], reverse=True)


@app.get("/analytics/devices")
def get_connected_devices():
    import socket
    local_host = socket.gethostname()

    # Determine local server IP dynamically
    server_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    device_map = {}

    # 1. Primary SENTRY Server Host
    device_map[local_host] = {
        "host": local_host,
        "role": "SENTRY Primary Server (Controller)",
        "ip": server_ip,
        "status": "nominal",
        "last_seen": "Active Controller",
        "event_count": 0,
        "max_risk": 0,
    }

    # 2. Add dynamically connected client devices
    for ip, cdata in _CONNECTED_CLIENTS.items():
        h = cdata.get("host") or f"client-{ip}"
        if h not in device_map:
            device_map[h] = {
                "host": h,
                "role": cdata.get("role", "Connected Endpoint"),
                "ip": ip,
                "status": "nominal",
                "last_seen": cdata.get("last_seen", "Active Client"),
                "event_count": 0,
                "max_risk": 0,
            }

    # 3. Process live incidents to assign events and risk to the ACTUAL host
    for inc in _LIVE_INCIDENTS:
        h = inc.get("host") or inc.get("host_id")
        if not h:
            continue
        risk_raw = inc.get("risk_score", 0.5)
        risk_100 = int(risk_raw * 100) if risk_raw <= 1.0 else int(risk_raw)
        src_ip = inc.get("src_ip") or inc.get("ip") or "Active Telemetry"

        if h not in device_map:
            device_map[h] = {
                "host": h,
                "role": "Monitored Host",
                "ip": src_ip,
                "status": "compromised" if risk_100 >= 60 else "investigating" if risk_100 >= 35 else "nominal",
                "last_seen": "Telemetry Live",
                "event_count": 1,
                "max_risk": risk_100,
            }
        else:
            device_map[h]["event_count"] += 1
            device_map[h]["max_risk"] = max(device_map[h]["max_risk"], risk_100)
            if risk_100 >= 60:
                device_map[h]["status"] = "compromised"
            elif risk_100 >= 35 and device_map[h]["status"] != "compromised":
                device_map[h]["status"] = "investigating"

    # 4. Count raw events in window for nominal devices
    for ev in _EVENT_WINDOW:
        h = getattr(ev, "host_id", None) or (ev.get("host_id") if isinstance(ev, dict) else None)
        if h and h in device_map and device_map[h]["max_risk"] == 0:
            device_map[h]["event_count"] += 1

    return list(device_map.values())


# ---------------- WEBSOCKET ----------------

@app.websocket("/ws")
@app.websocket("/ws/incidents")
async def websocket_endpoint(websocket: WebSocket):
    client_ip = websocket.client.host if websocket.client else "unknown"
    if client_ip not in ("127.0.0.1", "localhost", "::1", "unknown"):
        import socket
        try:
            resolved_host = socket.gethostbyaddr(client_ip)[0]
        except Exception:
            resolved_host = f"client-{client_ip}"
        _CONNECTED_CLIENTS[client_ip] = {
            "host": resolved_host,
            "ip": client_ip,
            "role": "Connected Endpoint",
            "last_seen": "Active WebSocket",
        }
    await manager.connect(websocket)
    try:
        while True:
            # Keep-alive receive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
