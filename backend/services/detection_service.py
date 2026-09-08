from typing import Any, Dict, List

from backend.detection.detector import DetectionEngine


class DetectionService:
    """
    Owns the DetectionEngine instance used by the backend.

    The service keeps the trained anomaly detector in memory so that
    baseline training and subsequent event detection use the same model.
    """

    def __init__(self):
        self.engine = DetectionEngine()
        self.is_trained = False

    def train_baseline(self, events: List[Dict[str, Any]]) -> None:
        if not events:
            raise ValueError("At least one baseline event is required.")

        self.engine.train(events)
        self.is_trained = True

    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not self.is_trained:
            raise RuntimeError(
                "Detection engine is not trained. "
                "Submit baseline events first."
            )

        return self.engine.detect(event)


detection_service = DetectionService()