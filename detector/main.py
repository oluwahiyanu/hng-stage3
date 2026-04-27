"""
main.py — Entry point. Wires all components together and runs the main loop.

Flow:
1. Load config
2. Start baseline tracker
3. Start blocker + unbanner
4. Start Slack notifier
5. Start web dashboard
6. Tail Nginx log → feed entries to detector → act on anomalies
"""
import time
import yaml
import threading
import os
from collections import defaultdict

from monitor import tail_log
from baseline import Baseline
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import start_dashboard
from audit import AuditLogger


def load_config(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    print("[main] HNG Anomaly Detection Engine starting...")
    config = load_config()

    # Initialise components
    audit = AuditLogger(config["audit_log"])
    notifier = Notifier(config)
    blocker = Blocker(config, audit)
    unbanner = Unbanner(blocker, notifier, audit)
    baseline = Baseline(config)
    detector = AnomalyDetector(config, baseline, blocker.get_blocked_set())

    # Start background threads
    unbanner.start()

    # Start dashboard
    start_dashboard(detector, blocker, baseline, config["dashboard_port"])

    # Per-second counter for baseline recording
    second_bucket = defaultdict(int)   # timestamp_floor -> count
    second_errors = defaultdict(int)

    print(f"[main] Tailing log: {config['log_path']}")
    last_baseline_record = time.time()

    # Main log processing loop
    for entry in tail_log(config["log_path"]):
        now = time.time()
        ts_floor = int(now)
        status = int(entry.get("status", 200))
        is_error = status >= 400

        # Accumulate per-second counts for baseline
        second_bucket[ts_floor] += 1
        if is_error:
            second_errors[ts_floor] += 1

        # Feed completed seconds into baseline
        for ts in list(second_bucket.keys()):
            if ts < ts_floor:
                baseline.record(float(ts), second_bucket.pop(ts),
                                second_errors.pop(ts, 0))

        # Run anomaly detection
        anomalies = detector.record(entry)

        for anomaly in anomalies:
            atype = anomaly["type"]
            ip = anomaly.get("ip")
            rate = anomaly["rate"]
            mean = anomaly["mean"]
            stddev = anomaly["stddev"]
            condition = anomaly["condition"]

            if atype == "ip" and ip:
                # Check it is not already blocked
                if ip not in blocker.get_blocked_set():
                    blocked = blocker.block(ip, condition, rate, mean)
                    if blocked:
                        info = blocker.get_blocked().get(ip, {})
                        offense = info.get("offense_count", 1)
                        schedule = config["ban_schedule_minutes"]
                        if offense <= len(schedule):
                            duration_str = f"{schedule[offense-1]}min"
                        else:
                            duration_str = "permanent"
                        notifier.send_ban(ip, condition, rate, mean, stddev, duration_str)

            elif atype == "global":
                notifier.send_global_alert(condition, rate, mean, stddev)
                audit.log("GLOBAL_ANOMALY", "ALL", condition, rate, mean, "alert-only")

    print("[main] Log tail ended — exiting")


if __name__ == "__main__":
    main()
