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