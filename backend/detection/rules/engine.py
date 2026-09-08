from typing import Any, Dict

from backend.detection.config.rules import RULE_CONFIG


class RuleEngine:
    def __init__(self):
        self.rules = [
            self.brute_force_rule,
            self.failed_then_success_rule,
            self.suspicious_process_rule,
            self.unusual_outbound_rule,
            self.api_abuse_rule,
        ]

    def evaluate(self, event: Dict[str, Any]) -> Dict[str, Any]:
        results = []

        for rule in self.rules:
            result = rule(event)

            if result:
                results.append(result)

        if not results:
            return {
                "rule_score": 0,
                "tags": [],
                "reasons": [],
            }

        return {
            "rule_score": min(max(r["score"] for r in results), 100),
            "tags": [r["tag"] for r in results],
            "reasons": [r["reason"] for r in results],
        }

    def brute_force_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        failed_logins = features.get("failed_login_count", 0)

        config = RULE_CONFIG["brute_force"]

        if failed_logins >= config["failed_login_threshold"]:
            return {
                "score": config["score"],
                "tag": "Brute Force",
                "reason": f"{failed_logins} failed login attempts detected",
            }

        return None

    def failed_then_success_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})

        failed_logins = features.get("failed_login_count", 0)
        successful_logins = features.get("success_count", 0)

        config = RULE_CONFIG["failed_then_success"]

        if (
            failed_logins >= config["failed_login_threshold"]
            and successful_logins >= config["success_login_threshold"]
        ):
            return {
                "score": config["score"],
                "tag": "Possible Valid Accounts",
                "reason": "Multiple failed logins followed by a successful login",
            }

        return None

    def suspicious_process_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        config = RULE_CONFIG["suspicious_process"]

        if features.get("new_process", False):
            return {
                "score": config["score"],
                "tag": "Suspicious Process",
                "reason": "Previously unseen process detected",
            }

        return None

    def unusual_outbound_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        connection_rate = features.get("connection_rate", 0)

        config = RULE_CONFIG["unusual_outbound"]

        if connection_rate > config["connection_rate_threshold"]:
            return {
                "score": config["score"],
                "tag": "Unusual Outbound Activity",
                "reason": f"High connection rate detected: {connection_rate}",
            }

        return None

    def api_abuse_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        auth_failure_rate = features.get("auth_failure_rate", 0)

        config = RULE_CONFIG["api_abuse"]

        if auth_failure_rate > config["auth_failure_rate_threshold"]:
            return {
                "score": config["score"],
                "tag": "API Abuse",
                "reason": "High authentication failure rate detected",
            }

        return None