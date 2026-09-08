from backend.detection.rules.engine import RuleEngine


# ---------------------------------------------------------------------------
# Existing Tests (Preserved)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Rule 1: Brute Force (Negative & Boundary Tests)
# ---------------------------------------------------------------------------

def test_brute_force_rule_boundary():
    engine = RuleEngine()

    # Boundary: failed_login_count == 5 should trigger (>= 5)
    event_at_boundary = {"features": {"failed_login_count": 5}}
    result_at = engine.evaluate(event_at_boundary)
    assert result_at["rule_score"] == 90
    assert "Brute Force" in result_at["tags"]
    assert "5 failed login attempts detected" in result_at["reasons"]

    # Boundary: failed_login_count == 4 should NOT trigger
    event_below = {"features": {"failed_login_count": 4}}
    result_below = engine.evaluate(event_below)
    assert result_below["rule_score"] == 0
    assert "Brute Force" not in result_below["tags"]


def test_brute_force_rule_negative():
    engine = RuleEngine()
    event = {"features": {"failed_login_count": 0}}
    result = engine.evaluate(event)
    assert result["rule_score"] == 0
    assert result["tags"] == []


# ---------------------------------------------------------------------------
# Rule 2: Possible Valid Accounts (Negative & Boundary Tests)
# ---------------------------------------------------------------------------

def test_failed_then_success_rule_boundary():
    engine = RuleEngine()

    # Exact threshold: failed=3 and success=1 triggers
    event_exact = {"features": {"failed_login_count": 3, "success_count": 1}}
    res_exact = engine.evaluate(event_exact)
    assert res_exact["rule_score"] == 85
    assert "Possible Valid Accounts" in res_exact["tags"]
    assert "Multiple failed logins followed by a successful login" in res_exact["reasons"]

    # Below failed threshold: failed=2, success=1 does NOT trigger
    event_low_fail = {"features": {"failed_login_count": 2, "success_count": 1}}
    res_low_fail = engine.evaluate(event_low_fail)
    assert "Possible Valid Accounts" not in res_low_fail["tags"]

    # Below success threshold: failed=3, success=0 does NOT trigger
    event_no_succ = {"features": {"failed_login_count": 3, "success_count": 0}}
    res_no_succ = engine.evaluate(event_no_succ)
    assert "Possible Valid Accounts" not in res_no_succ["tags"]


def test_failed_then_success_rule_negative():
    engine = RuleEngine()
    event = {"features": {"failed_login_count": 0, "success_count": 0}}
    result = engine.evaluate(event)
    assert "Possible Valid Accounts" not in result["tags"]


# ---------------------------------------------------------------------------
# Rule 3: Suspicious Process (Negative Test)
# ---------------------------------------------------------------------------

def test_suspicious_process_rule_negative():
    engine = RuleEngine()
    event = {"features": {"new_process": False}}
    result = engine.evaluate(event)
    assert "Suspicious Process" not in result["tags"]


# ---------------------------------------------------------------------------
# Rule 4: Unusual Outbound Activity (Negative & Boundary Tests)
# ---------------------------------------------------------------------------

def test_unusual_outbound_rule_boundary():
    engine = RuleEngine()

    # Boundary: connection_rate == 15 does NOT trigger (> 15)
    event_at = {"features": {"connection_rate": 15}}
    result_at = engine.evaluate(event_at)
    assert "Unusual Outbound Activity" not in result_at["tags"]

    # Boundary: connection_rate == 16 triggers
    event_above = {"features": {"connection_rate": 16}}
    result_above = engine.evaluate(event_above)
    assert result_above["rule_score"] == 70
    assert "Unusual Outbound Activity" in result_above["tags"]
    assert "High connection rate detected: 16" in result_above["reasons"]


def test_unusual_outbound_rule_negative():
    engine = RuleEngine()
    event = {"features": {"connection_rate": 5}}
    result = engine.evaluate(event)
    assert "Unusual Outbound Activity" not in result["tags"]


# ---------------------------------------------------------------------------
# Rule 5: API Abuse (Negative & Boundary Tests)
# ---------------------------------------------------------------------------

def test_api_abuse_rule_boundary():
    engine = RuleEngine()

    # Boundary: auth_failure_rate == 0.7 does NOT trigger (> 0.7)
    event_at = {"features": {"auth_failure_rate": 0.7}}
    result_at = engine.evaluate(event_at)
    assert "API Abuse" not in result_at["tags"]

    # Boundary: auth_failure_rate == 0.71 triggers
    event_above = {"features": {"auth_failure_rate": 0.71}}
    result_above = engine.evaluate(event_above)
    assert result_above["rule_score"] == 70
    assert "API Abuse" in result_above["tags"]
    assert "High authentication failure rate detected" in result_above["reasons"]


def test_api_abuse_rule_negative():
    engine = RuleEngine()
    event = {"features": {"auth_failure_rate": 0.2}}
    result = engine.evaluate(event)
    assert "API Abuse" not in result["tags"]


# ---------------------------------------------------------------------------
# Rule 6: Privilege Escalation (Positive & Negative Tests)
# ---------------------------------------------------------------------------

def test_privilege_escalation_rule_positive():
    engine = RuleEngine()
    event = {"features": {"privilege_change": True}}
    result = engine.evaluate(event)

    assert result["rule_score"] == 85
    assert "Privilege Escalation" in result["tags"]
    assert "Privilege level change detected" in result["reasons"]


def test_privilege_escalation_rule_negative():
    engine = RuleEngine()
    event = {"features": {"privilege_change": False}}
    result = engine.evaluate(event)

    assert "Privilege Escalation" not in result["tags"]
    assert result["rule_score"] == 0


# ---------------------------------------------------------------------------
# Rule 7: Suspicious Parent Process (Positive & Negative Tests)
# ---------------------------------------------------------------------------

def test_suspicious_parent_process_rule_positive():
    engine = RuleEngine()
    event = {"features": {"parent_process_change": True}}
    result = engine.evaluate(event)

    assert result["rule_score"] == 75
    assert "Suspicious Parent Process" in result["tags"]
    assert "Unexpected parent process change detected" in result["reasons"]


def test_suspicious_parent_process_rule_negative():
    engine = RuleEngine()
    event = {"features": {"parent_process_change": False}}
    result = engine.evaluate(event)

    assert "Suspicious Parent Process" not in result["tags"]
    assert result["rule_score"] == 0


# ---------------------------------------------------------------------------
# Rule 8: Suspicious Login Source (Positive, Boundary & Negative Tests)
# ---------------------------------------------------------------------------

def test_suspicious_login_source_rule_positive():
    engine = RuleEngine()
    event = {"features": {"source_ip_change": True, "success_count": 2}}
    result = engine.evaluate(event)

    assert result["rule_score"] == 75
    assert "Suspicious Login Source" in result["tags"]
    assert "Successful login detected after a source IP change" in result["reasons"]


def test_suspicious_login_source_rule_boundary():
    engine = RuleEngine()

    # Exact threshold: source_ip_change=True, success_count=1 triggers (>= 1)
    event_at = {"features": {"source_ip_change": True, "success_count": 1}}
    res_at = engine.evaluate(event_at)
    assert res_at["rule_score"] == 75
    assert "Suspicious Login Source" in res_at["tags"]

    # Boundary: source_ip_change=True, success_count=0 does NOT trigger
    event_zero = {"features": {"source_ip_change": True, "success_count": 0}}
    res_zero = engine.evaluate(event_zero)
    assert "Suspicious Login Source" not in res_zero["tags"]


def test_suspicious_login_source_rule_negative():
    engine = RuleEngine()
    # source_ip_change is False
    event = {"features": {"source_ip_change": False, "success_count": 5}}
    result = engine.evaluate(event)
    assert "Suspicious Login Source" not in result["tags"]


# ---------------------------------------------------------------------------
# Rule 9: Suspicious File Activity (Positive, Boundary & Negative Tests)
# ---------------------------------------------------------------------------

def test_suspicious_file_activity_rule_positive():
    engine = RuleEngine()
    event = {"features": {"file_change_rate": 80}}
    result = engine.evaluate(event)

    assert result["rule_score"] == 80
    assert "Suspicious File Activity" in result["tags"]
    assert "High file change rate detected: 80" in result["reasons"]


def test_suspicious_file_activity_rule_boundary():
    engine = RuleEngine()

    # Boundary: file_change_rate == 50 does NOT trigger (> 50)
    event_at = {"features": {"file_change_rate": 50}}
    res_at = engine.evaluate(event_at)
    assert "Suspicious File Activity" not in res_at["tags"]

    # Boundary: file_change_rate == 51 triggers
    event_above = {"features": {"file_change_rate": 51}}
    res_above = engine.evaluate(event_above)
    assert res_above["rule_score"] == 80
    assert "Suspicious File Activity" in res_above["tags"]


def test_suspicious_file_activity_rule_negative():
    engine = RuleEngine()
    event = {"features": {"file_change_rate": 10}}
    result = engine.evaluate(event)
    assert "Suspicious File Activity" not in result["tags"]


# ---------------------------------------------------------------------------
# Rule 10: Network Scanning (Positive, Boundary & Negative Tests)
# ---------------------------------------------------------------------------

def test_network_scanning_rule_positive():
    engine = RuleEngine()
    event = {"features": {"unique_destinations": 25, "connection_rate": 20}}
    result = engine.evaluate(event)

    assert result["rule_score"] == 80
    assert "Network Scanning" in result["tags"]
    assert "High connection rate to multiple destinations detected" in result["reasons"]


def test_network_scanning_rule_boundary():
    engine = RuleEngine()

    # Boundary: unique_destinations == 20 (not > 20), connection_rate == 25 -> does NOT trigger
    event_d20 = {"features": {"unique_destinations": 20, "connection_rate": 25}}
    assert "Network Scanning" not in engine.evaluate(event_d20)["tags"]

    # Boundary: unique_destinations == 25, connection_rate == 15 (not > 15) -> does NOT trigger
    event_c15 = {"features": {"unique_destinations": 25, "connection_rate": 15}}
    assert "Network Scanning" not in engine.evaluate(event_c15)["tags"]

    # Boundary: unique_destinations == 21, connection_rate == 16 -> triggers
    event_both = {"features": {"unique_destinations": 21, "connection_rate": 16}}
    res = engine.evaluate(event_both)
    assert res["rule_score"] == 80
    assert "Network Scanning" in res["tags"]


def test_network_scanning_rule_negative():
    engine = RuleEngine()
    event = {"features": {"unique_destinations": 5, "connection_rate": 5}}
    result = engine.evaluate(event)
    assert "Network Scanning" not in result["tags"]


# ---------------------------------------------------------------------------
# Multi-Rule Combinations
# ---------------------------------------------------------------------------

def test_multi_rule_login_attack():
    """
    Prompt requirement example:
    failed_login_count = 10
    success_count = 1
    source_ip_change = True

    Should trigger:
    - Brute Force (90)
    - Possible Valid Accounts (85)
    - Suspicious Login Source (75)

    Rule score should be the highest (90).
    """
    engine = RuleEngine()
    event = {
        "features": {
            "failed_login_count": 10,
            "success_count": 1,
            "source_ip_change": True,
        }
    }
    result = engine.evaluate(event)

    assert result["rule_score"] == 90
    assert "Brute Force" in result["tags"]
    assert "Possible Valid Accounts" in result["tags"]
    assert "Suspicious Login Source" in result["tags"]
    assert len(result["tags"]) == 3
    assert len(result["reasons"]) == 3


def test_multi_rule_endpoint_and_network_attack():
    """
    Simultaneously triggers Privilege Escalation (85), Suspicious Process (75),
    Network Scanning (80), and Unusual Outbound Activity (70).
    Rule score should be highest (85).
    """
    engine = RuleEngine()
    event = {
        "features": {
            "privilege_change": True,
            "new_process": True,
            "unique_destinations": 30,
            "connection_rate": 20,
        }
    }
    result = engine.evaluate(event)

    assert result["rule_score"] == 85
    assert "Privilege Escalation" in result["tags"]
    assert "Suspicious Process" in result["tags"]
    assert "Network Scanning" in result["tags"]
    assert "Unusual Outbound Activity" in result["tags"]
    assert len(result["tags"]) == 4



def test_custom_rule_config():
    """
    Verifies that passing a custom configuration to RuleEngine overrides defaults.
    """
    custom_config = {
        "brute_force": {"failed_login_threshold": 2, "score": 99},
        "failed_then_success": {"failed_login_threshold": 10, "success_login_threshold": 5, "score": 85},
        "suspicious_process": {"score": 60},
        "unusual_outbound": {"connection_rate_threshold": 50, "score": 70},
        "api_abuse": {"auth_failure_rate_threshold": 0.9, "score": 70},
        "privilege_escalation": {"score": 95},
        "suspicious_parent_process": {"score": 75},
        "suspicious_login_source": {"success_login_threshold": 1, "score": 75},
        "suspicious_file_activity": {"file_change_rate_threshold": 100, "score": 80},
        "network_scanning": {"unique_destinations_threshold": 50, "connection_rate_threshold": 50, "score": 80},
    }
    engine = RuleEngine(config=custom_config)

    # With custom threshold of 2, 2 failed logins should trigger Brute Force with score 99
    event = {"features": {"failed_login_count": 2}}
    result = engine.evaluate(event)
    assert result["rule_score"] == 99
    assert "Brute Force" in result["tags"]


# ---------------------------------------------------------------------------
# Additional Rules: Credential Dumping, Exfil, Persistence, Defense Evasion, Lateral Movement
# ---------------------------------------------------------------------------

def test_credential_dumping_rule():
    engine = RuleEngine()
    event = {"features": {"credential_dump_indicator": True}}
    result = engine.evaluate(event)
    assert result["rule_score"] == 95
    assert "Credential Dumping" in result["tags"]
    assert "Credential dumping or unauthorized memory access detected" in result["reasons"]


def test_data_exfiltration_rule():
    engine = RuleEngine()
    event = {"features": {"bytes_sent": 600000000}}
    result = engine.evaluate(event)
    assert result["rule_score"] == 85
    assert "Data Exfiltration" in result["tags"]


def test_scheduled_task_persistence_rule():
    engine = RuleEngine()
    event = {"features": {"scheduled_task_created": True}}
    result = engine.evaluate(event)
    assert result["rule_score"] == 80
    assert "Persistence Mechanism" in result["tags"]


def test_defense_evasion_rule():
    engine = RuleEngine()
    event = {"features": {"log_cleared": True}}
    result = engine.evaluate(event)
    assert result["rule_score"] == 85
    assert "Defense Evasion" in result["tags"]


def test_lateral_movement_rule():
    engine = RuleEngine()
    event = {"features": {"remote_session_count": 3}}
    result = engine.evaluate(event)
    assert result["rule_score"] == 80
    assert "Lateral Movement" in result["tags"]

