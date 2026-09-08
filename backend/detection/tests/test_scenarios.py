from backend.detection.detector import DetectionEngine


def baseline_event():
    return {
        "event_id": "normal-1",
        "host_id": "host-1",
        "user_id": "user-1",
        "features": {
            "packet_count": 100,
            "bytes": 10000,
            "bytes_per_second": 1000,
            "connection_rate": 5,
            "unique_destinations": 5,
            "dst_port": 443,
            "process_frequency": 10,
            "new_process": 0,
            "parent_process_change": 0,
            "privilege_change": 0,
            "file_change_rate": 2,
            "requests_per_minute": 30,
            "error_rate": 0.02,
            "auth_failure_rate": 0.03,
            "sensitive_endpoint_access": 0,
            "unique_endpoint_count": 5,
            "failed_login_count": 0,
            "success_count": 10,
            "failure_ratio": 0,
            "login_rate": 5,
            "source_ip_change": 0,
        },
    }


def train_engine():
    engine = DetectionEngine()

    baseline = []

    for i in range(100):
        event = baseline_event()
        event["event_id"] = f"baseline-{i}"

        features = event["features"]

        # Normal network variation
        features["packet_count"] = 80 + (i % 40)
        features["bytes"] = 8000 + (i % 40) * 200
        features["bytes_per_second"] = 800 + (i % 30) * 20
        features["connection_rate"] = 3 + (i % 8) * 0.5
        features["unique_destinations"] = 3 + (i % 6)

        # Normal endpoint variation
        features["process_frequency"] = 8 + (i % 8)
        features["file_change_rate"] = 1 + (i % 5) * 0.5

        # Normal application variation
        features["requests_per_minute"] = 20 + (i % 30)
        features["error_rate"] = 0.01 + (i % 5) * 0.005
        features["auth_failure_rate"] = 0.01 + (i % 4) * 0.01
        features["unique_endpoint_count"] = 3 + (i % 5)

        # Normal authentication variation
        features["success_count"] = 8 + (i % 8)
        features["login_rate"] = 3 + (i % 5) * 0.5

        baseline.append(event)

    engine.train(baseline)

    return engine


def test_brute_force_scenario():
    engine = train_engine()

    event = baseline_event()
    event["features"]["failed_login_count"] = 10

    result = engine.detect(event)

    assert result["rule_score"] == 90
    assert "Brute Force" in result["rule_tags"]
    assert result["detected"] is True


def test_failed_then_success_scenario():
    engine = train_engine()

    event = baseline_event()
    event["features"]["failed_login_count"] = 5
    event["features"]["success_count"] = 1

    result = engine.detect(event)

    assert result["rule_score"] == 90
    assert "Brute Force" in result["rule_tags"]
    assert "Possible Valid Accounts" in result["rule_tags"]


def test_suspicious_process_scenario():
    engine = train_engine()

    event = baseline_event()
    event["features"]["new_process"] = 1

    result = engine.detect(event)

    assert "Suspicious Process" in result["rule_tags"]
    assert result["detected"] is True


def test_unusual_outbound_scenario():
    engine = train_engine()

    event = baseline_event()
    event["features"]["connection_rate"] = 25

    result = engine.detect(event)

    assert "Unusual Outbound Activity" in result["rule_tags"]
    assert result["detected"] is True
