from typing import Dict, Any


class FeatureExtractor:
    NETWORK_FEATURES = [
        "packet_count",
        "bytes",
        "bytes_per_second",
        "connection_rate",
        "unique_destinations",
        "dst_port",
    ]

    ENDPOINT_FEATURES = [
        "process_frequency",
        "new_process",
        "parent_process_change",
        "privilege_change",
        "file_change_rate",
    ]

    APPLICATION_FEATURES = [
        "requests_per_minute",
        "error_rate",
        "auth_failure_rate",
        "sensitive_endpoint_access",
        "unique_endpoint_count",
    ]

    AUTH_FEATURES = [
        "failed_login_count",
        "success_count",
        "failure_ratio",
        "login_rate",
        "source_ip_change",
    ]

    def extract(self, event: Dict[str, Any]) -> Dict[str, float]:
        features = event.get("features", {})

        extracted = {}

        all_features = (
            self.NETWORK_FEATURES
            + self.ENDPOINT_FEATURES
            + self.APPLICATION_FEATURES
            + self.AUTH_FEATURES
        )

        for feature in all_features:
            value = features.get(feature, 0)

            if isinstance(value, bool):
                value = int(value)

            try:
                extracted[feature] = float(value)
            except (TypeError, ValueError):
                extracted[feature] = 0.0

        return extracted

    def to_vector(self, event: Dict[str, Any]) -> list[float]:
        extracted = self.extract(event)

        feature_order = (
            self.NETWORK_FEATURES
            + self.ENDPOINT_FEATURES
            + self.APPLICATION_FEATURES
            + self.AUTH_FEATURES
        )

        return [extracted[feature] for feature in feature_order]