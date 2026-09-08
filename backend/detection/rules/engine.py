from typing import Any, Dict, Optional

try:
    from backend.detection.config.rules import RULE_CONFIG
except ImportError:
    from detection.config.rules import RULE_CONFIG


class RuleEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config if config is not None else RULE_CONFIG
        self.rules = [
            self.brute_force_rule,
            self.failed_then_success_rule,
            self.suspicious_process_rule,
            self.unusual_outbound_rule,
            self.api_abuse_rule,
            self.privilege_escalation_rule,
            self.suspicious_parent_process_rule,
            self.suspicious_login_source_rule,
            self.suspicious_file_activity_rule,
            self.network_scanning_rule,
            self.credential_dumping_rule,
            self.data_exfiltration_rule,
            self.scheduled_task_persistence_rule,
            self.defense_evasion_rule,
            self.lateral_movement_rule,
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
        cfg = self.config["brute_force"]

        if failed_logins >= cfg["failed_login_threshold"]:
            return {
                "score": cfg["score"],
                "tag": "Brute Force",
                "reason": f"{failed_logins} failed login attempts detected",
            }

        return None

    def failed_then_success_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config["failed_then_success"]

        if (
            features.get("failed_login_count", 0) >= cfg["failed_login_threshold"]
            and features.get("success_count", 0) >= cfg["success_login_threshold"]
        ):
            return {
                "score": cfg["score"],
                "tag": "Possible Valid Accounts",
                "reason": "Multiple failed logins followed by a successful login",
            }

        return None

    def suspicious_process_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config["suspicious_process"]

        if features.get("new_process", False):
            return {
                "score": cfg["score"],
                "tag": "Suspicious Process",
                "reason": "Previously unseen process detected",
            }

        return None

    def unusual_outbound_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        connection_rate = features.get("connection_rate", 0)
        cfg = self.config["unusual_outbound"]

        if connection_rate > cfg["connection_rate_threshold"]:
            return {
                "score": cfg["score"],
                "tag": "Unusual Outbound Activity",
                "reason": f"High connection rate detected: {connection_rate}",
            }

        return None

    def api_abuse_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        auth_failure_rate = features.get("auth_failure_rate", 0)
        cfg = self.config["api_abuse"]

        if auth_failure_rate > cfg["auth_failure_rate_threshold"]:
            return {
                "score": cfg["score"],
                "tag": "API Abuse",
                "reason": "High authentication failure rate detected",
            }

        return None

    def privilege_escalation_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config["privilege_escalation"]

        if features.get("privilege_change") == True:
            return {
                "score": cfg["score"],
                "tag": "Privilege Escalation",
                "reason": "Privilege level change detected",
            }

        return None

    def suspicious_parent_process_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config["suspicious_parent_process"]

        if features.get("parent_process_change") == True:
            return {
                "score": cfg["score"],
                "tag": "Suspicious Parent Process",
                "reason": "Unexpected parent process change detected",
            }

        return None

    def suspicious_login_source_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config["suspicious_login_source"]

        if (
            features.get("source_ip_change") == True
            and features.get("success_count", 0) >= cfg["success_login_threshold"]
        ):
            return {
                "score": cfg["score"],
                "tag": "Suspicious Login Source",
                "reason": "Successful login detected after a source IP change",
            }

        return None

    def suspicious_file_activity_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        file_change_rate = features.get("file_change_rate", 0)
        cfg = self.config["suspicious_file_activity"]

        if file_change_rate > cfg["file_change_rate_threshold"]:
            return {
                "score": cfg["score"],
                "tag": "Suspicious File Activity",
                "reason": f"High file change rate detected: {file_change_rate}",
            }

        return None

    def network_scanning_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        unique_destinations = features.get("unique_destinations", 0)
        connection_rate = features.get("connection_rate", 0)
        cfg = self.config["network_scanning"]

        if (
            unique_destinations > cfg["unique_destinations_threshold"]
            and connection_rate > cfg["connection_rate_threshold"]
        ):
            return {
                "score": cfg["score"],
                "tag": "Network Scanning",
                "reason": "High connection rate to multiple destinations detected",
            }

        return None

    def credential_dumping_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config.get("credential_dumping")
        if not cfg:
            return None

        if features.get("credential_dump_indicator") == True or features.get("lsass_access") == True:
            return {
                "score": cfg["score"],
                "tag": "Credential Dumping",
                "reason": "Credential dumping or unauthorized memory access detected",
            }

        return None

    def data_exfiltration_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config.get("data_exfiltration")
        if not cfg:
            return None

        bytes_sent = features.get("bytes_sent") or features.get("bytes") or 0
        if bytes_sent >= cfg["bytes_threshold"]:
            mb = bytes_sent / (1024 * 1024)
            return {
                "score": cfg["score"],
                "tag": "Data Exfiltration",
                "reason": f"High-volume outbound data transfer detected: {mb:.1f} MB",
            }

        return None

    def scheduled_task_persistence_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config.get("scheduled_task_persistence")
        if not cfg:
            return None

        if features.get("scheduled_task_created") == True or features.get("persistence_created") == True:
            return {
                "score": cfg["score"],
                "tag": "Persistence Mechanism",
                "reason": "Unauthorized scheduled task or startup persistence created",
            }

        return None

    def defense_evasion_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config.get("defense_evasion")
        if not cfg:
            return None

        if features.get("log_cleared") == True or features.get("security_agent_stopped") == True:
            return {
                "score": cfg["score"],
                "tag": "Defense Evasion",
                "reason": "Security event audit log cleared or EDR agent tampering detected",
            }

        return None

    def lateral_movement_rule(self, event: Dict[str, Any]):
        features = event.get("features", {})
        cfg = self.config.get("lateral_movement")
        if not cfg:
            return None

        if (
            features.get("remote_session_count", 0) >= cfg["remote_session_threshold"]
            or features.get("lateral_movement") == True
        ):
            return {
                "score": cfg["score"],
                "tag": "Lateral Movement",
                "reason": "Rapid internal lateral movement across hosts detected",
            }

        return None

