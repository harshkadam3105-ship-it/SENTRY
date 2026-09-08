from backend.detection.rules.engine import RuleEngine


def test_brute_force_rule():
    engine = RuleEngine()

    event = {
        "event_type": "login",
        "features": {
            "failed_login_count": 8
        }
    }

    result = engine.evaluate(event)

    assert result["rule_score"] == 90
    assert "Brute Force" in result["tags"]


def test_failed_then_success_rule():
    engine = RuleEngine()

    event = {
        "event_type": "login",
        "features": {
            "failed_login_count": 3,
            "success_count": 1
        }
    }

    result = engine.evaluate(event)

    assert result["rule_score"] == 85
    assert "Possible Valid Accounts" in result["tags"]


def test_suspicious_process_rule():
    engine = RuleEngine()

    event = {
        "event_type": "process",
        "features": {
            "new_process": True
        }
    }

    result = engine.evaluate(event)

    assert result["rule_score"] == 75
    assert "Suspicious Process" in result["tags"]


def test_unusual_outbound_rule():
    engine = RuleEngine()

    event = {
        "event_type": "network",
        "features": {
            "connection_rate": 20
        }
    }

    result = engine.evaluate(event)

    assert result["rule_score"] == 70
    assert "Unusual Outbound Activity" in result["tags"]


def test_api_abuse_rule():
    engine = RuleEngine()

    event = {
        "event_type": "application",
        "features": {
            "auth_failure_rate": 0.8
        }
    }

    result = engine.evaluate(event)

    assert result["rule_score"] == 70
    assert "API Abuse" in result["tags"]


def test_normal_event():
    engine = RuleEngine()

    event = {
        "event_type": "login",
        "features": {
            "failed_login_count": 0
        }
    }

    result = engine.evaluate(event)

    assert result["rule_score"] == 0
    assert result["tags"] == []
    assert result["reasons"] == []
