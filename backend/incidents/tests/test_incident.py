from uuid import uuid4

import pytest

from backend.incidents.generator import IncidentGenerator


def make_event(
    severity=4,
    host_id="HOST-01",
    user_id="admin",
):
    return {
        "event_id": uuid4(),
        "timestamp": "2026-09-08T12:00:00",
        "source_type": "endpoint",
        "host_id": host_id,
        "user_id": user_id,
        "event_type": "authentication",
        "severity": severity,
        "features": {},
        "raw_data": {},
    }


def make_detection(
    rule_tags=None,
    rule_score=0,
    anomaly_score=0,
):
    return {
        "rule_score": rule_score,
        "rule_tags": rule_tags or [],
        "rule_reasons": [],
        "anomaly_score": anomaly_score,
        "is_anomaly": anomaly_score >= 70,
        "detected": rule_score > 0 or anomaly_score >= 70,
    }


def test_single_event_creates_incident():
    generator = IncidentGenerator()

    event = make_event()

    incident = generator.generate(
        events=[event],
        detection_results=[
            make_detection(
                rule_tags=["Brute Force"],
                rule_score=90,
                anomaly_score=80,
            )
        ],
        risk_score=87,
    )

    assert incident["title"] == "Brute Force Attack Detected"
    assert incident["risk_score"] == 87
    assert incident["severity"] == 4
    assert incident["status"] == "open"
    assert len(incident["event_ids"]) == 1


def test_correlated_events_create_one_incident():
    generator = IncidentGenerator()

    events = [
        make_event(),
        make_event(),
        make_event(),
    ]

    detection_results = [
        make_detection(
            rule_tags=["Brute Force"],
            rule_score=90,
            anomaly_score=80,
        ),
        make_detection(
            rule_tags=["Brute Force"],
            rule_score=90,
            anomaly_score=75,
        ),
        make_detection(
            rule_tags=["Possible Valid Accounts"],
            rule_score=85,
            anomaly_score=82,
        ),
    ]

    incident = generator.generate(
        events=events,
        detection_results=detection_results,
        risk_score=91,
    )

    assert len(incident["event_ids"]) == 3
    assert incident["risk_score"] == 91
    assert incident["title"] == "Possible Account Compromise"


def test_brute_force_maps_to_t1110():
    generator = IncidentGenerator()

    incident = generator.generate(
        events=[make_event()],
        detection_results=[
            make_detection(
                rule_tags=["Brute Force"],
                rule_score=90,
            )
        ],
        risk_score=80,
    )

    assert incident["mitre_techniques"][0]["mitre_id"] == "T1110"
    assert (
        incident["mitre_techniques"][0]["technique"]
        == "Brute Force"
    )


def test_valid_accounts_maps_to_t1078():
    generator = IncidentGenerator()

    incident = generator.generate(
        events=[make_event()],
        detection_results=[
            make_detection(
                rule_tags=["Possible Valid Accounts"],
                rule_score=85,
            )
        ],
        risk_score=82,
    )

    assert incident["mitre_techniques"][0]["mitre_id"] == "T1078"


def test_incident_preserves_host_and_user():
    generator = IncidentGenerator()

    event = make_event(
        host_id="SERVER-01",
        user_id="admin",
    )

    incident = generator.generate(
        events=[event],
        detection_results=[
            make_detection(
                rule_tags=["Suspicious Process"],
                rule_score=75,
                anomaly_score=70,
            )
        ],
        risk_score=72,
    )

    assert incident["host_id"] == "SERVER-01"
    assert incident["user_id"] == "admin"


def test_confidence_is_between_zero_and_one():
    generator = IncidentGenerator()

    incident = generator.generate(
        events=[make_event()],
        detection_results=[
            make_detection(
                rule_tags=["Brute Force"],
                rule_score=90,
                anomaly_score=80,
            )
        ],
        risk_score=87,
    )

    assert 0.0 <= incident["confidence"] <= 1.0


def test_empty_events_are_rejected():
    generator = IncidentGenerator()

    with pytest.raises(ValueError):
        generator.generate(
            events=[],
            detection_results=[],
            risk_score=50,
        )


def test_mismatched_events_and_detection_results_are_rejected():
    generator = IncidentGenerator()

    with pytest.raises(ValueError):
        generator.generate(
            events=[make_event()],
            detection_results=[],
            risk_score=50,
        )