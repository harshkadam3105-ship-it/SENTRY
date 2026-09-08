import uuid
from datetime import datetime




def normalize_endpoint_event(raw: dict) -> dict:
    """Raw endpoint telemetry (e.g. psutil process/auth data) -> unified event schema."""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
        "source_type": "endpoint",
        "host_id": raw.get("hostname", "unknown-host"),
        "user_id": raw.get("user"),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "event_type": raw.get("event_type", "unknown"),
        "severity": raw.get("severity", 1),
        "features": raw.get("features", {}),
        "raw_data": raw,
    }


def normalize_network_event(raw: dict) -> dict:
    """Raw network telemetry -> unified event schema."""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
        "source_type": "network",
        "host_id": raw.get("host_id", "unknown-net-host"),
        "user_id": None,
        "src_ip": raw.get("src_ip"),
        "dst_ip": raw.get("dst_ip"),
        "src_port": raw.get("src_port"),
        "dst_port": raw.get("dst_port"),
        "protocol": raw.get("protocol"),
        "event_type": raw.get("event_type", "unknown"),
        "severity": raw.get("severity", 1),
        "features": raw.get("features", {}),
        "raw_data": raw,
    }


def normalize_application_event(raw: dict) -> dict:
    """Raw application logs -> unified event schema."""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
        "source_type": "application",
        "host_id": raw.get("host_id", "demo-app-1"),
        "user_id": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "event_type": raw.get("event_type", "app_log"),
        "severity": raw.get("severity", 1),
        "features": raw.get("features", {}),
        "raw_data": raw,
    }


NORMALIZERS = {
    "endpoint": normalize_endpoint_event,
    "network": normalize_network_event,
    "application": normalize_application_event,
}


def normalize(source_type: str, raw: dict) -> dict:
    fn = NORMALIZERS.get(source_type)
    if not fn:
        raise ValueError(f"Unknown source_type: {source_type}")
    return fn(raw)
