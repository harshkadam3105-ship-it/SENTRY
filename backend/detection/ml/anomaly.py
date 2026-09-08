from sklearn.ensemble import IsolationForest
import numpy as np


class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.trained = False

    def train(self, baseline_data):
        """
        Train on normal/expected behavior.
        """
        self.model.fit(np.array(baseline_data))
        self.trained = True

    def score(self, features):
        """
        Return anomaly score from 0-100.
        Higher = more anomalous.
        """
        if not self.trained:
            raise RuntimeError("Model must be trained before scoring.")

        features = np.array(features).reshape(1, -1)

        raw_score = self.model.decision_function(features)[0]

        # Convert Isolation Forest score into 0-100 anomaly score
        anomaly_score = 50 - (raw_score * 50)

        return round(float(np.clip(anomaly_score, 0, 100)), 2)

    def predict(self, features):
        """
        Return -1 for anomaly, 1 for normal.
        """
        if not self.trained:
            raise RuntimeError("Model must be trained before prediction.")

        features = np.array(features).reshape(1, -1)

        return int(self.model.predict(features)[0])