#!/usr/bin/env python3
"""
SENTRY Autonomous Agent / Attack Generator
Run this script on ANY secondary laptop connected to the hotspot.
Zero external dependencies required (pure standard Python library).
"""

import sys
import json
import uuid
import socket
import platform
from datetime import datetime, timezone
import urllib.request
import urllib.error

# DEFAULT SERVER IP (This SENTRY Server on hotspot "Harsh K")
DEFAULT_SERVER = "http://10.211.2.190:8000"

HOSTNAME = socket.gethostname()
OS_INFO = f"{platform.system()} {platform.release()}"

SCENARIOS = {
    "1": {
        "title": "SSH / Remote Login Brute Force Attack",
        "description": "Simulates 18 failed login attempts followed by credential cracking",
        "event": {
            "source_type": "endpoint",
            "user_id": "root",
            "event_type": "failed_login",
            "severity": 4,
            "features": {
                "failed_login_count": 18,
                "login_speed_sec": 0.4,
                "attacker_country": "UNKNOWN"
            },
            "raw_data": {
                "log": "sshd[4921]: 18 consecutive PAM authentication failures for invalid user root",
                "attack_vector": "T1110 - Brute Force",
                "target_service": "OpenSSH 8.9p1"
            }
        }
    },
    "2": {
        "title": "Privilege Escalation (Sudo / Admin Abuse)",
        "description": "Simulates root access escalation attempt via vulnerable process",
        "event": {
            "source_type": "endpoint",
            "user_id": "standard_user",
            "event_type": "privilege_escalation",
            "severity": 4,
            "features": {
                "failed_login_count": 0,
                "elevated_to": "root",
                "sudo_nopasswd": True
            },
            "raw_data": {
                "log": "sudo: pam_authenticate failed: User standard_user attempted sudo -i without permissions",
                "command": "sudo -i /bin/bash",
                "attack_vector": "T1068 - Exploitation for Privilege Escalation"
            }
        }
    },
    "3": {
        "title": "Credential Access (LSASS / SAM Memory Dump)",
        "description": "Mimikatz-style process memory injection targeting LSASS",
        "event": {
            "source_type": "endpoint",
            "user_id": "SYSTEM",
            "event_type": "credential_access",
            "severity": 5,
            "features": {
                "failed_login_count": 0,
                "process_name": "mimikatz.exe",
                "target_process": "lsass.exe",
                "granted_access": "0x1010"
            },
            "raw_data": {
                "log": "Sysmon Event 10: Process OpenProcess called by untrusted binary targeting lsass.exe",
                "attack_vector": "T1003.001 - OS Credential Dumping: LSASS Memory",
                "technique": "Sekurlsa::logonpasswords"
            }
        }
    },
    "4": {
        "title": "Data Exfiltration via Encrypted C2 Tunnel",
        "description": "High-volume compressed data transfer out to external suspicious IP",
        "event": {
            "source_type": "network",
            "user_id": "backup_service",
            "event_type": "data_exfiltration",
            "severity": 5,
            "features": {
                "bytes_transferred": 850000000,
                "bytes_sent": 850000000,
                "destination_port": 443,
                "connection_rate": 35.0,
                "unusual_protocol": "DNS-Tunneling"
            },
            "raw_data": {
                "log": "Zeek conn.log: 850MB encrypted payload dispatched to 185.220.101.5 in under 30 seconds",
                "attack_vector": "T1048 - Exfiltration Over Alternative Protocol",
                "payload_size_mb": 850
            }
        }
    },
    "5": {
        "title": "Ransomware Mass File Modification",
        "description": "Rapid encryption of enterprise files and shadow copy destruction",
        "event": {
            "source_type": "endpoint",
            "user_id": "administrator",
            "event_type": "ransomware_activity",
            "severity": 5,
            "features": {
                "files_modified_per_min": 1420,
                "vssadmin_delete": True,
                "entropy": 7.98
            },
            "raw_data": {
                "log": "vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled No",
                "attack_vector": "T1486 - Data Encrypted for Impact",
                "extension": ".locked"
            }
        }
    },
    "6": {
        "title": "Normal Benign User Activity (Clean Baseline)",
        "description": "Regular developer Git clone, code editing and standard HTTP traffic",
        "event": {
            "source_type": "endpoint",
            "user_id": "developer",
            "event_type": "normal_login",
            "severity": 1,
            "features": {
                "failed_login_count": 0,
                "status": "SUCCESS"
            },
            "raw_data": {
                "log": "git checkout -b feature/auth && npm run dev",
                "status": "BENIGN_TELEMETRY"
            }
        }
    }
}

def _dispatch_payload(server_url, event_data, attack_title):
    endpoint = f"{server_url.rstrip('/')}/events"
    payload = json.dumps(event_data).encode("utf-8")
    
    print(f"[*] Sending payload to SENTRY Server: {endpoint}")
    print(f"    Host: {event_data.get('host_id')} ({OS_INFO})")
    print(f"    Event: {attack_title}")
    if event_data.get("features"):
        print(f"    Features: {json.dumps(event_data['features'])}")

    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "SENTRY-Agent/2.0"}
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] HTTP {resp.status} OK - Event Delivered into SENTRY!")
            print(f"    * Rules Matched    : {resp_data.get('rule_tags', [])}")
            print(f"    * Rule Reasons     : {resp_data.get('rule_reasons', [])}")
            print(f"    * ML Anomaly Score : {resp_data.get('anomaly_score', 'N/A')}")
            print(f"    * Unified Risk     : {resp_data.get('risk_score', 'N/A')}/100")
            print(f"    * Incident Created : {resp_data.get('incident_generated', False)}")
            ai = resp_data.get("ai_analysis") or {}
            if ai:
                print(f"    * AI Threat Actor  : {ai.get('threat_actor_profile')}")
                print(f"    * AI Kill-Chain    : {ai.get('kill_chain_stage')}")
                print(f"    * AI Blast Radius  : {ai.get('blast_radius')}")
                if ai.get('executive_summary'):
                    print(f"    * AI Narrative     : {ai.get('executive_summary')}")
            print("[+] Check the primary SENTRY dashboard screen - updated live in real time!")
            return True
    except urllib.error.URLError as e:
        print(f"[-] FAILED to connect to SENTRY Server at {endpoint}")
        print(f"    Reason: {e.reason}")
        print(f"    Tip: Verify both laptops are connected to hotspot 'Harsh K' and server IP is correct.")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def send_event(server_url, scenario_key):
    if scenario_key not in SCENARIOS:
        print(f"[-] Invalid scenario '{scenario_key}'. Choose 1-6.")
        return False
        
    sc = SCENARIOS[scenario_key]
    event_data = dict(sc["event"])
    event_data["event_id"] = str(uuid.uuid4())
    event_data["timestamp"] = datetime.now(timezone.utc).isoformat()
    event_data["host_id"] = HOSTNAME
    return _dispatch_payload(server_url, event_data, sc["title"])

def send_custom_event(server_url, log_text, user="admin"):
    event_data = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "endpoint",
        "host_id": HOSTNAME,
        "user_id": user,
        "event_type": "security_event",
        "severity": 4,
        "features": {},
        "raw_data": {
            "log": log_text,
            "host": HOSTNAME,
            "user": user,
            "os": OS_INFO,
        }
    }
    return _dispatch_payload(server_url, event_data, f"Custom Event: {log_text}")

def main():
    server = DEFAULT_SERVER
    
    # Check CLI arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg in SCENARIOS:
            srv = sys.argv[2] if len(sys.argv) > 2 else server
            send_event(srv, arg)
            return
        elif arg.startswith("--"):
            # Custom argument e.g. python sentry_agent.py --log "..."
            log_text = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else arg
            send_custom_event(server, log_text)
            return
        else:
            # Custom free-text string passed directly: python sentry_agent.py "15 failed ssh attempts"
            send_custom_event(server, " ".join(sys.argv[1:]))
            return

    print("=" * 65)
    print(f"   SENTRY Real-Time Attack Agent - Laptop: {HOSTNAME}")
    print(f"   Target Server: {server}")
    print("=" * 65)
    print("Select an option:")
    for k, v in SCENARIOS.items():
        tag = "[CLEAN]" if k == "6" else "[ATTACK]"
        print(f"  [{k}] {tag} {v['title']}")
        print(f"      -> {v['description']}")
    print("  [7] [CUSTOM] Type what actually happened on this computer right now")
    print("  [q] Quit")
    print("-" * 65)

    try:
        choice = input("Enter choice (1-7) [default: 7]: ").strip()
        if not choice:
            choice = "7"
        if choice.lower() == "q":
            return
        if choice == "7":
            custom_log = input("Enter what actually happened (e.g. 10 failed logins, sudo abuse, 2GB transfer): ").strip()
            if not custom_log:
                print("Empty input. Cancelled.")
                return
            custom_user = input("Enter user account [default: admin]: ").strip() or "admin"
            send_custom_event(server, custom_log, custom_user)
        elif choice in SCENARIOS:
            send_event(server, choice)
        else:
            print(f"[-] Invalid choice '{choice}'.")
    except KeyboardInterrupt:
        print("\nExiting.")

if __name__ == "__main__":
    main()
