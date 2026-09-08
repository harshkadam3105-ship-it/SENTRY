"""
Demo attack trigger script.
Sends synthetic events to the backend /ingest endpoint.
Run with: python trigger.py [--loop]
"""
import httpx
import asyncio
import os
import sys
import json
from datetime import datetime, timezone
import random

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")

ATTACK_PAYLOADS = [
    {
        "source": "trigger-script",
        "event_type": "brute_force",
        "host": "workstation-99.corp",
        "user": "target.user",
        "detail": "SSH brute force from 10.0.0.55",
        "timestamp": None
    },
    {
        "source": "trigger-script",
        "event_type": "lateral_movement",
        "host": "server-db-99.corp",
        "user": "attacker",
        "detail": "RDP pivot from compromised host",
        "timestamp": None
    },
    {
        "source": "trigger-script",
        "event_type": "data_exfil",
        "host": "laptop-fin-99.corp",
        "user": "insider.threat",
        "detail": "Large DNS query volume to external resolver",
        "timestamp": None
    }
]


async def trigger_attack(payload: dict):
    payload["timestamp"] = datetime.now(timezone.utc).isoformat()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{BACKEND_URL}/ingest", json=payload, timeout=5.0)
            print(f"[{payload['timestamp']}] Triggered {payload['event_type']} → {resp.status_code}")
        except Exception as e:
            print(f"[ERROR] Could not reach backend: {e}")


async def main():
    loop_mode = "--loop" in sys.argv
    print(f"SentinelX Demo Trigger — backend: {BACKEND_URL}")

    if loop_mode:
        print("Loop mode: triggering every 20s. Press Ctrl+C to stop.")
        while True:
            payload = random.choice(ATTACK_PAYLOADS).copy()
            await trigger_attack(payload)
            await asyncio.sleep(20)
    else:
        for payload in ATTACK_PAYLOADS:
            await trigger_attack(payload.copy())
            await asyncio.sleep(2)
        print("Done. Run with --loop for continuous demo mode.")


if __name__ == "__main__":
    asyncio.run(main())
