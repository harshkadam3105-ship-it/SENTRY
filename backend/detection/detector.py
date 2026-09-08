from typing import Dict, Any

from backend.detection.features.extractor import FeatureExtractor
from backend.detection.ml.anomaly import AnomalyDetector
from backend.detection.rules.engine import RuleEngine


class DetectionEngine:
    """
    Combines deterministic rules and ML anomaly detection
    into a single explainable detection result.
    """

    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector()

    def train(self, baseline_events):
        """
        Train the Isolation Forest using normal baseline events.
        """
        baseline_vectors = [
            self.feature_extractor.to_vector(event)
            for event in baseline_events
        ]

        self.anomaly_detector.train(baseline_vectors)

    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run both rule-based and ML anomaly detection on an event.
        """

        # Extract features once
        features = self.feature_extractor.extract(event)

        feature_order = (
            self.feature_extractor.NETWORK_FEATURES
            + self.feature_extractor.ENDPOINT_FEATURES
            + self.feature_extractor.APPLICATION_FEATURES
            + self.feature_extractor.AUTH_FEATURES
        )

        vector = [features[name] for name in feature_order]

        # Run deterministic rules
        rule_result = self.rule_engine.evaluate(event)

        # Run ML anomaly detection
        anomaly_score = self.anomaly_detector.score(vector)
        prediction = self.anomaly_detector.predict(vector)

        is_anomaly = prediction == -1

        return {
            "event_id": event.get("event_id"),
            "host_id": event.get("host_id"),
            "user_id": event.get("user_id"),
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "rule_score": rule_result["rule_score"],
            "rule_tags": rule_result["tags"],
            "rule_reasons": rule_result["reasons"],
            "features": features,
            "detected": is_anomaly or rule_result["rule_score"] > 0,
        }