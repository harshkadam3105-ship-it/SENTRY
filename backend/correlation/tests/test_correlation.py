from datetime import datetime, timedelta, timezone
from uuid import uuid4

from backend.correlation.engine import CorrelationEngine
from backend.models.schema import EventIn


def make_event(
    minutes_offset: int,
    host: str = "HOST-01",
    user_id: str | None = "admin",
    event_type: str = "authentication_failure",
) -> EventIn:
    """Create a test event matching the shared EventIn schema."""

    base_time = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    return EventIn(
        event_id=uuid4(),
        timestamp=base_time + timedelta(
            minutes=minutes_offset
        ),
        source_type="endpoint",
        host_id=f"{host}-ID",
        user_id=user_id,
        event_type=event_type,
        severity=5,
        features={},
        raw_data={},
    )


def test_same_host_and_user_are_strongly_correlated():
    engine = CorrelationEngine()

    current = make_event(5)
    previous = make_event(3)

    score = engine.relationship_score(
        current,
        previous,
    )

    assert score == 1.0


def test_same_host_only_is_partially_correlated():
    engine = CorrelationEngine()

    current = make_event(
        5,
        host="HOST-01",
        user_id="admin",
    )

    previous = make_event(
        3,
        host="HOST-01",
        user_id="guest",
    )

    score = engine.relationship_score(
        current,
        previous,
    )

    assert score == 0.5


def test_different_host_and_user_are_not_correlated():
    engine = CorrelationEngine()

    current = make_event(
        5,
        host="HOST-01",
        user_id="admin",
    )

    previous = make_event(
        3,
        host="HOST-02",
        user_id="guest",
    )

    score = engine.relationship_score(
        current,
        previous,
    )

    assert score == 0.0


def test_events_outside_five_minute_window_are_not_correlated():
    engine = CorrelationEngine()

    current = make_event(10)
    previous = make_event(4)

    score = engine.relationship_score(
        current,
        previous,
    )

    assert score == 0.0


def test_missing_users_do_not_count_as_user_match():
    engine = CorrelationEngine()

    current = make_event(
        5,
        host="HOST-01",
        user_id=None,
    )

    previous = make_event(
        3,
        host="HOST-01",
        user_id=None,
    )

    score = engine.relationship_score(
        current,
        previous,
    )

    assert score == 0.5


def test_correlate_event_returns_matching_events():
    engine = CorrelationEngine()

    current = make_event(5)

    previous_events = [
        make_event(3),
        make_event(
            4,
            host="HOST-02",
            user_id="guest",
        ),
        make_event(2),
    ]

    correlated = engine.correlate_event(
        current,
        previous_events,
    )

    assert len(correlated) == 2

    assert all(
        score > 0
        for _, score in correlated
    )


def test_correlation_score_uses_strongest_relationship():
    engine = CorrelationEngine()

    current = make_event(5)

    previous_events = [
        make_event(
            4,
            host="HOST-01",
            user_id="guest",
        ),
        make_event(
            3,
            host="HOST-01",
            user_id="admin",
        ),
    ]

    score = engine.correlation_score(
        current,
        previous_events,
    )

    assert score == 1.0