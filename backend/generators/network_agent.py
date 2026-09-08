import requests
import uuid
import random
import time
from datetime import datetime

API_URL = "http://127.0.0.1:8000/events"

def generate_event():
    event_type = random.choice(["connection_attempt", "packet_drop", "suspicious_flow"])
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "source_type": "network",
        "host_id": "demo-net-1",
        "event_type": event_type,
        "severity": random.randint(1, 5),
        "features": {
            "src_ip": f"10.0.0.{random.randint(1, 50)}",
            "dst_ip": f"10.0.1.{random.randint(1, 50)}",
            "src_port": random.choice([22, 80, 443, 8080]),
            "dst_port": random.choice([22, 80, 443, 8080]),
            "protocol": random.choice(["TCP", "UDP"]),
            "packet_size": random.randint(64, 1500)
        },
        "raw_data": {
            "log": f"Simulated {event_type} event"
        }
    }
    return event

def main():
    while True:
        event = generate_event()
        try:
            resp = requests.post(API_URL, json=event)
            print(f"Sent {event['event_type']} → {resp.status_code}")
        except Exception as e:
            print("Error sending event:", e)
        time.sleep(5)

if __name__ == "__main__":
    main()
