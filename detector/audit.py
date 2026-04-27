"""
audit.py — Writes structured log entries for every ban, unban,
and baseline recalculation.
Format: [timestamp] ACTION ip | condition | rate | baseline | duration
"""
import os
import time
from datetime import datetime
import threading


class AuditLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self.lock = threading.Lock()

    def log(self, action: str, ip: str, condition: str,
            rate: float, baseline: float, duration: str):
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        line = (f"[{ts}] {action} {ip} | "
                f"condition={condition} | "
                f"rate={rate:.2f} | "
                f"baseline={baseline:.2f} | "
                f"duration={duration}\n")
        with self.lock:
            with open(self.log_path, "a") as f:
                f.write(line)
        print(f"[audit] {line.strip()}")
