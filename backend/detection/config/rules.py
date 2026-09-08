"""
SENTRY Detection Engine - Rule Configuration.

Contains all tunable thresholds and rule scores for deterministic rule evaluation.
Thresholds are softcoded here to allow easy environment-specific tuning.
"""

RULE_CONFIG = {
    "brute_force": {
        "failed_login_threshold": 5,
        "score": 90,
    },
    "failed_then_success": {
        "failed_login_threshold": 3,
        "success_login_threshold": 1,
        "score": 85,
    },
    "suspicious_process": {
        "score": 75,
    },
    "unusual_outbound": {
        "connection_rate_threshold": 15,
        "score": 70,
    },
    "api_abuse": {
        "auth_failure_rate_threshold": 0.7,
        "score": 70,
    },
    "privilege_escalation": {
        "score": 85,
    },
    "suspicious_parent_process": {
        "score": 75,
    },
    "suspicious_login_source": {
        "success_login_threshold": 1,
        "score": 75,
    },
    "suspicious_file_activity": {
        # Tunable threshold: set conservatively for demo; adjust based on environment baselines
        "file_change_rate_threshold": 50,
        "score": 80,
    },
    "network_scanning": {
        "unique_destinations_threshold": 20,
        "connection_rate_threshold": 15,
        "score": 80,
    },
    "credential_dumping": {
        "score": 95,
    },
    "data_exfiltration": {
        "bytes_threshold": 500000000,  # 500 MB
        "score": 85,
    },
    "scheduled_task_persistence": {
        "score": 80,
    },
    "defense_evasion": {
        "score": 85,
    },
    "lateral_movement": {
        "remote_session_threshold": 2,
        "score": 80,
    },
}

