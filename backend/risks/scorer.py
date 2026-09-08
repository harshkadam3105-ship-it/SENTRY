from typing import Dict


class RiskScorer:
    """
    Calculate an explainable 0-100 risk score from:

    1. ML anomaly score
    2. Rule-based detection score
    3. Event severity
    4. Correlation score

    The scoring is deterministic and transparent.
    """

    ANOMALY_WEIGHT = 0.30
    RULE_WEIGHT = 0.30
    SEVERITY_WEIGHT = 0.20
    CORRELATION_WEIGHT = 0.20

    def score(
        self,
        anomaly_score: float,
        rule_score: float,
        severity: int,
        correlation_score: float,
    ) -> float:
        """
        Calculate the final risk score.

        Args:
            anomaly_score: ML anomaly score from 0 to 100.
            rule_score: Rule engine score from 0 to 100.
            severity: Event severity from 0 to 5.
            correlation_score: Correlation score from 0.0 to 1.0.

        Returns:
            Final risk score from 0.0 to 100.0.
        """

        anomaly = self._clamp(anomaly_score, 0.0, 100.0)
        rule = self._clamp(rule_score, 0.0, 100.0)
        severity_value = self._clamp(severity, 0, 5) * 20
        correlation = self._clamp(
            correlation_score,
            0.0,
            1.0,
        ) * 100

        risk_score = (
            anomaly * self.ANOMALY_WEIGHT
            + rule * self.RULE_WEIGHT
            + severity_value * self.SEVERITY_WEIGHT
            + correlation * self.CORRELATION_WEIGHT
        )

        return round(
            self._clamp(risk_score, 0.0, 100.0),
            2,
        )

    def explain(
        self,
        anomaly_score: float,
        rule_score: float,
        severity: int,
        correlation_score: float,
    ) -> Dict[str, float]:
        """
        Return the individual weighted contributions used
        to calculate the final risk score.

        This makes the risk decision explainable in the
        SOC dashboard and incident details.
        """

        anomaly = self._clamp(anomaly_score, 0.0, 100.0)
        rule = self._clamp(rule_score, 0.0, 100.0)
        severity_value = self._clamp(severity, 0, 5) * 20
        correlation = self._clamp(
            correlation_score,
            0.0,
            1.0,
        ) * 100

        return {
            "anomaly_contribution": round(
                anomaly * self.ANOMALY_WEIGHT,
                2,
            ),
            "rule_contribution": round(
                rule * self.RULE_WEIGHT,
                2,
            ),
            "severity_contribution": round(
                severity_value * self.SEVERITY_WEIGHT,
                2,
            ),
            "correlation_contribution": round(
                correlation * self.CORRELATION_WEIGHT,
                2,
            ),
        }

    @staticmethod
    def _clamp(
        value: float,
        minimum: float,
        maximum: float,
    ) -> float:
        """Keep a value within the specified range."""

        return max(
            minimum,
            min(float(value), maximum),
        )