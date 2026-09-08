import requests
import uuid
import random
import time
from datetime import datetime

API_URL = "http://127.0.0.1:8000/events"

def generate_event():
    log_level = random.choice(["INFO", "WARNING", "ERROR"])
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "source_type": "application",
        "host_id": "demo-app-1",
        "event_type": "app_log",
        "severity": {"INFO":1,"WARNING":3,"ERROR":5}[log_level],
        "features": {
            "log_level": log_level,
            "message": random.choice([
                "User session started",
                "Cache miss on key",
                "Database connection failed",
                "Unhandled exception in module"
            ])
        },
        "raw_data": {
            "log": f"[{log_level}] simulated application log"
        }
    }
    return event

def main():
    while True:
        event = generate_event()
        try:
            resp = requests.post(API_URL, json=event)
            print(f"Sent {event['features']['log_level']} log → {resp.status_code}")
        except Exception as e:
            print("Error sending event:", e)
        time.sleep(5)

if __name__ == "__main__":
    main()
