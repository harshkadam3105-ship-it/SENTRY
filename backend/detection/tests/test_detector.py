from backend.detection.detector import DetectionEngine


def make_baseline_events():
    events = []

    for i in range(10):
        events.append({
            "event_id": f"baseline-{i}",
            "host_id": "host-1",
            "user_id": "user-1",
            "features": {
                "packet_count": 10 + i,
                "bytes": 1000 + (i * 10),
                "bytes_per_second": 100,
                "connection_rate": 2,
                "unique_destinations": 2,
                "dst_port": 443,
                "process_frequency": 5,
                "new_process": 0,
                "parent_process_change": 0,
                "privilege_change": 0,
                "file_change_rate": 1,
                "requests_per_minute": 10,
                "error_rate": 0.01,
                "auth_failure_rate": 0.05,
                "sensitive_endpoint_access": 0,
                "unique_endpoint_count": 3,
                "failed_login_count": 0,
                "success_count": 5,
                "failure_ratio": 0,
                "login_rate": 5,
                "source_ip_change": 0
            }
        })

    return events


def test_detection_engine_normal_event():
    engine = DetectionEngine()
    engine.train(make_baseline_events())

    event = make_baseline_events()[0]
    result = engine.detect(event)

    assert "anomaly_score" in result
    assert "rule_score" in result
    assert "detected" in result
    assert "features" in result


def test_detection_engine_brute_force():
    engine = DetectionEngine()
    engine.train(make_baseline_events())

    event = make_baseline_events()[0]
    event["event_id"] = "attack-1"
    event["features"]["failed_login_count"] = 10

    result = engine.detect(event)

    assert result["rule_score"] == 90
    assert "Brute Force" in result["rule_tags"]
    assert result["detected"] is True
