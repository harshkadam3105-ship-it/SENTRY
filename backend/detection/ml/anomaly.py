from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np


class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.trained = False
        self.baseline_scores = None

    def train(self, baseline_data):
        """
        Train Isolation Forest on normal/expected behavior.
        """
        baseline_array = np.asarray(baseline_data, dtype=float)

        if baseline_array.ndim != 2 or len(baseline_array) < 2:
            raise ValueError(
                "baseline_data must contain at least two feature vectors."
            )

        scaled_baseline = self.scaler.fit_transform(baseline_array)

        self.model.fit(scaled_baseline)

        self.baseline_scores = self.model.decision_function(
            scaled_baseline
        )

        self.trained = True

    def score(self, features):
        """
        Return an anomaly score from 0-100.
        Higher values indicate greater deviation from the learned baseline.
        """
        if not self.trained:
            raise RuntimeError("Model must be trained before scoring.")

        features = np.asarray(features, dtype=float).reshape(1, -1)
        scaled_features = self.scaler.transform(features)

        raw_score = self.model.decision_function(scaled_features)[0]

        baseline_min = float(np.min(self.baseline_scores))
        baseline_max = float(np.max(self.baseline_scores))

        if baseline_max == baseline_min:
            anomaly_score = 0.0
        else:
            anomaly_score = (
                (baseline_max - raw_score)
                / (baseline_max - baseline_min)
            ) * 100

        return round(float(np.clip(anomaly_score, 0, 100)), 2)

    def predict(self, features):
        """
        Return -1 for anomaly, 1 for normal.
        """
        if not self.trained:
            raise RuntimeError("Model must be trained before prediction.")

        features = np.asarray(features, dtype=float).reshape(1, -1)
        scaled_features = self.scaler.transform(features)

        return int(self.model.predict(scaled_features)[0])
