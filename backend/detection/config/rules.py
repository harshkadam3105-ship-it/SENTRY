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
}