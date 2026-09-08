from backend.risks.scorer import RiskScorer


def test_zero_inputs_produce_zero_risk():
    scorer = RiskScorer()

    score = scorer.score(
        anomaly_score=0,
        rule_score=0,
        severity=0,
        correlation_score=0,
    )

    assert score == 0.0


def test_maximum_inputs_produce_maximum_risk():
    scorer = RiskScorer()

    score = scorer.score(
        anomaly_score=100,
        rule_score=100,
        severity=5,
        correlation_score=1.0,
    )

    assert score == 100.0


def test_risk_score_uses_expected_weights():
    scorer = RiskScorer()

    score = scorer.score(
        anomaly_score=80,
        rule_score=90,
        severity=4,
        correlation_score=1.0,
    )

    assert score == 87.0


def test_high_rule_score_increases_risk():
    scorer = RiskScorer()

    low_rule = scorer.score(
        anomaly_score=50,
        rule_score=20,
        severity=3,
        correlation_score=0.5,
    )

    high_rule = scorer.score(
        anomaly_score=50,
        rule_score=90,
        severity=3,
        correlation_score=0.5,
    )

    assert high_rule > low_rule


def test_high_correlation_increases_risk():
    scorer = RiskScorer()

    low_correlation = scorer.score(
        anomaly_score=60,
        rule_score=60,
        severity=3,
        correlation_score=0.0,
    )

    high_correlation = scorer.score(
        anomaly_score=60,
        rule_score=60,
        severity=3,
        correlation_score=1.0,
    )

    assert high_correlation > low_correlation


def test_severity_is_normalized_from_zero_to_five():
    scorer = RiskScorer()

    score = scorer.score(
        anomaly_score=0,
        rule_score=0,
        severity=5,
        correlation_score=0,
    )

    assert score == 20.0


def test_scores_are_clamped_to_valid_ranges():
    scorer = RiskScorer()

    score = scorer.score(
        anomaly_score=150,
        rule_score=-20,
        severity=10,
        correlation_score=2.0,
    )

    assert score == 70.0


def test_explanation_matches_risk_contributions():
    scorer = RiskScorer()

    explanation = scorer.explain(
        anomaly_score=80,
        rule_score=90,
        severity=4,
        correlation_score=1.0,
    )

    assert explanation["anomaly_contribution"] == 24.0
    assert explanation["rule_contribution"] == 27.0
    assert explanation["severity_contribution"] == 16.0
    assert explanation["correlation_contribution"] == 20.0

    assert sum(explanation.values()) == 87.0