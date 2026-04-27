"""
monitor.py — Continuously tails the Nginx JSON access log.
Uses seek-to-end on startup so we only process new lines.
Yields parsed log entries as dictionaries.
"""
import json
import time
import os


def tail_log(log_path: str):
    """
    Generator that yields parsed JSON log lines from the Nginx access log.
    Waits for the file to exist, then seeks to the end and yields new lines.
    """
    # Wait for the log file to exist (Nginx may not have written yet)
    while not os.path.exists(log_path):
        print(f"[monitor] Waiting for log file: {log_path}")
        time.sleep(2)

    print(f"[monitor] Tailing log: {log_path}")

    with open(log_path, "r") as f:
        # Seek to end — we only care about new lines, not historical ones
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                # No new data — sleep briefly and try again
                time.sleep(0.1)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
                yield entry
            except json.JSONDecodeError:
                # Skip malformed lines silently
                continue
