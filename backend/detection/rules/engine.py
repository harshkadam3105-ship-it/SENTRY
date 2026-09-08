from typing import Any, Dict


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

        if failed_logins >= 5:
            return {
                "score": 90,
                "tag": "Brute Force",
                "reason": f"{failed_logins} failed login attempts detected",
            }

        return None

    def failed_then_success_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})

        if (
            features.get("failed_login_count", 0) >= 3
            and features.get("success_count", 0) >= 1
        ):
            return {
                "score": 85,
                "tag": "Possible Valid Accounts",
                "reason": "Multiple failed logins followed by a successful login",
            }

        return None

    def suspicious_process_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})

        if features.get("new_process", False):
            return {
                "score": 75,
                "tag": "Suspicious Process",
                "reason": "Previously unseen process detected",
            }

        return None

    def unusual_outbound_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})

        connection_rate = features.get("connection_rate", 0)

        if connection_rate > 15:
            return {
                "score": 70,
                "tag": "Unusual Outbound Activity",
                "reason": f"High connection rate detected: {connection_rate}",
            }

        return None

    def api_abuse_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})

        auth_failure_rate = features.get("auth_failure_rate", 0)

        if auth_failure_rate > 0.7:
            return {
                "score": 70,
                "tag": "API Abuse",
                "reason": "High authentication failure rate detected",
            }

        return None