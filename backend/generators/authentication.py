import requests
import uuid
import random
import time
from datetime import datetime

API_URL = "http://127.0.0.1:8000/events"

def generate_event():
    # Randomly choose event type
    event_type = random.choice(["failed_login", "new_process"])
    
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "source_type": "endpoint",  # auth/process events are endpoint-sourced
        "host_id": "demo-host-1",
        "user_id": random.choice(["alice", "bob", "charlie"]),
        "src_ip": "192.168.1." + str(random.randint(10, 50)),
        "dst_ip": "192.168.1." + str(random.randint(60, 100)),
        "src_port": random.choice([22, 443, 8080]),
        "dst_port": random.choice([22, 443, 8080]),
        "protocol": "TCP",
        "event_type": event_type,
        "severity": random.randint(1, 5),
        "features": {
            "failed_logins": random.randint(0, 10) if event_type == "failed_login" else None,
            "process_name": random.choice(["nginx", "python", "ssh"]) if event_type == "new_process" else None
        },
        "raw_data": {
            "log": f"Simulated {event_type} event for user"
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
        time.sleep(5)  # wait 5 seconds before next event

if __name__ == "__main__":
    main()
