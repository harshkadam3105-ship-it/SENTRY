from datetime import timedelta
from typing import List, Tuple

from backend.models.schema import EventIn


class CorrelationEngine:
    """
    Correlates security events using:
    1. A five-minute time window
    2. Shared host
    3. Shared user

    The engine is intentionally explainable and deterministic.
    """

    WINDOW_MINUTES = 5

    def __init__(self, window_minutes: int = WINDOW_MINUTES):
        self.window = timedelta(minutes=window_minutes)

    def _within_time_window(
        self,
        event_a: EventIn,
        event_b: EventIn,
    ) -> bool:
        """Return True when two events are within the configured window."""

        time_difference = abs(
            event_a.timestamp - event_b.timestamp
        )

        return time_difference <= self.window

    def _entity_match_score(
        self,
        event_a: EventIn,
        event_b: EventIn,
    ) -> float:
        """
        Calculate relationship strength based on shared entities.

        Host match = 0.5
        User match = 0.5

        Therefore:
        1.0 = same host + same user
        0.5 = one shared entity
        0.0 = no shared entity
        """

        score = 0.0

        # Shared host
        if event_a.host_id == event_b.host_id:
            score += 0.5

        # Shared user
        # Only count a user match when both events have a user.
        if (
            event_a.user_id is not None
            and event_b.user_id is not None
            and event_a.user_id == event_b.user_id
        ):
            score += 0.5

        return score

    def relationship_score(
        self,
        event_a: EventIn,
        event_b: EventIn,
    ) -> float:
        """
        Calculate the correlation relationship between two events.

        Returns:
            0.0 -> not correlated
            0.5 -> partially correlated
            1.0 -> strongly correlated
        """

        if not self._within_time_window(event_a, event_b):
            return 0.0

        return self._entity_match_score(event_a, event_b)

    def correlate_event(
        self,
        event: EventIn,
        previous_events: List[EventIn],
    ) -> List[Tuple[EventIn, float]]:
        """
        Find previous events related to the incoming event.

        Returns a list of:
            (previous_event, relationship_score)
        """

        correlated = []

        for previous_event in previous_events:
            score = self.relationship_score(
                event,
                previous_event,
            )

            if score > 0:
                correlated.append(
                    (previous_event, score)
                )

        return correlated

    def correlation_score(
        self,
        event: EventIn,
        previous_events: List[EventIn],
    ) -> float:
        """
        Calculate an overall correlation score for an event.

        The strongest relationship found is used as the score.

        Returns:
            float from 0.0 to 1.0
        """

        relationships = self.correlate_event(
            event,
            previous_events,
        )

        if not relationships:
            return 0.0

        return max(
            score for _, score in relationships
        )