from typing import Any, Dict, List
from uuid import UUID, uuid4


class IncidentGenerator:
    """
    Converts detected/correlated security activity into
    a single explainable security incident.

    Multiple related events are represented as one incident.
    """

    MITRE_MAPPINGS = {
        "Brute Force": {
            "mitre_id": "T1110",
            "technique": "Brute Force",
            "confidence": 0.95,
        },
        "Possible Valid Accounts": {
            "mitre_id": "T1078",
            "technique": "Valid Accounts",
            "confidence": 0.90,
        },
        "Suspicious Process": {
            "mitre_id": "T1059",
            "technique": "Command and Scripting Interpreter",
            "confidence": 0.80,
        },
        "Unusual Outbound Activity": {
            "mitre_id": "T1071",
            "technique": "Application Layer Protocol",
            "confidence": 0.75,
        },
    }

    def generate(
        self,
        events: List[Dict[str, Any]],
        detection_results: List[Dict[str, Any]],
        risk_score: float,
    ) -> Dict[str, Any]:
        """
        Generate one incident from related security events.

        Args:
            events: Correlated events belonging to the same activity.
            detection_results: Detection output for those events.
            risk_score: Final 0-100 risk score.

        Returns:
            Incident dictionary suitable for API/dashboard integration.
        """

        if not events:
            raise ValueError("At least one event is required.")

        if len(events) != len(detection_results):
            raise ValueError(
                "events and detection_results must contain the same number "
                "of items."
            )

        event_ids = [
            self._event_id(event)
            for event in events
        ]

        severity = max(
            int(event.get("severity", 0))
            for event in events
        )

        host_id = self._first_non_empty(
            [event.get("host_id") for event in events]
        )

        user_id = self._first_non_empty(
            [event.get("user_id") for event in events]
        )

        rule_tags = self._collect_rule_tags(detection_results)

        mitre_techniques = self._map_mitre(rule_tags)

        title = self._generate_title(rule_tags)

        confidence = self._calculate_confidence(
            detection_results,
            risk_score,
        )

        return {
            "incident_id": str(uuid4()),
            "title": title,
            "severity": severity,
            "risk_score": round(float(risk_score), 2),
            "confidence": confidence,
            "status": "open",
            "host_id": host_id,
            "user_id": user_id,
            "event_ids": event_ids,
            "mitre_techniques": mitre_techniques,
        }

    def _collect_rule_tags(
        self,
        detection_results: List[Dict[str, Any]],
    ) -> List[str]:
        """Collect unique detection tags while preserving order."""

        tags = []

        for result in detection_results:
            for tag in result.get("rule_tags", []):
                if tag not in tags:
                    tags.append(tag)

        return tags

    def _map_mitre(
        self,
        rule_tags: List[str],
    ) -> List[Dict[str, Any]]:
        """Map detection tags to a small explainable MITRE set."""

        techniques = []

        for tag in rule_tags:
            mapping = self.MITRE_MAPPINGS.get(tag)

            if mapping:
                techniques.append(mapping.copy())

        return techniques

    def _generate_title(
        self,
        rule_tags: List[str],
    ) -> str:
        """Generate a human-readable incident title."""

        if "Possible Valid Accounts" in rule_tags:
            return "Possible Account Compromise"

        if "Brute Force" in rule_tags:
            return "Brute Force Attack Detected"

        if "Suspicious Process" in rule_tags:
            return "Suspicious Process Activity"

        if "Unusual Outbound Activity" in rule_tags:
            return "Unusual Outbound Network Activity"

        if rule_tags:
            return f"Suspicious Activity: {rule_tags[0]}"

        return "Suspicious Activity Detected"

    def _calculate_confidence(
        self,
        detection_results: List[Dict[str, Any]],
        risk_score: float,
    ) -> float:
        """
        Calculate a simple explainable confidence score.

        Rule detections and high risk increase confidence.
        """

        rule_scores = [
            float(result.get("rule_score", 0))
            for result in detection_results
        ]

        anomaly_scores = [
            float(result.get("anomaly_score", 0))
            for result in detection_results
        ]

        max_rule = max(rule_scores, default=0)
        max_anomaly = max(anomaly_scores, default=0)

        confidence = (
            max_rule * 0.50
            + max_anomaly * 0.30
            + min(max(float(risk_score), 0), 100) * 0.20
        ) / 100

        return round(
            min(max(confidence, 0.0), 1.0),
            2,
        )

    @staticmethod
    def _event_id(event: Dict[str, Any]) -> str:
        """Return an event ID as a string."""

        event_id = event.get("event_id")

        if event_id is None:
            return str(uuid4())

        if isinstance(event_id, UUID):
            return str(event_id)

        return str(event_id)

    @staticmethod
    def _first_non_empty(values: List[Any]) -> Any:
        """Return the first non-empty value."""

        for value in values:
            if value:
                return value

        return None