"""
detector.py — Anomaly detection using z-score and rate multiplier.

Two detection modes:
1. Per-IP: monitors each source IP's request rate in a 60s sliding window
2. Global: monitors total traffic rate across all IPs

Detection fires if EITHER condition is true:
- z-score > threshold (configurable, default 3.0)
- rate > N * baseline_mean (configurable, default 5x)

Error surge: if an IP's error rate is 3x baseline error rate,
tighten its z-score threshold by 50%.
"""
import time
import math
from collections import deque, defaultdict
import threading


class SlidingWindow:
    """
    Tracks request timestamps in a deque.
    Evicts entries older than window_seconds on every access.
    Returns current rate (requests per second).
    """
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.timestamps = deque()
        self.error_timestamps = deque()
        self.lock = threading.Lock()

    def add(self, timestamp: float, is_error: bool = False):
        """Record a new request."""
        with self.lock:
            self.timestamps.append(timestamp)
            if is_error:
                self.error_timestamps.append(timestamp)
            self._evict(timestamp)

    def _evict(self, now: float):
        """Remove entries outside the window — called on every add."""
        cutoff = now - self.window_seconds
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()
        while self.error_timestamps and self.error_timestamps[0] < cutoff:
            self.error_timestamps.popleft()

    def rate(self, now: float = None) -> float:
        """Return requests per second over the window."""
        if now is None:
            now = time.time()
        with self.lock:
            self._evict(now)
            return len(self.timestamps) / self.window_seconds

    def error_rate(self, now: float = None) -> float:
        """Return errors per second over the window."""
        if now is None:
            now = time.time()
        with self.lock:
            self._evict(now)
            return len(self.error_timestamps) / self.window_seconds

    def count(self) -> int:
        """Return raw request count in window."""
        with self.lock:
            return len(self.timestamps)


class AnomalyDetector:
    def __init__(self, config: dict, baseline, blocked_ips: set):
        self.config = config
        self.baseline = baseline
        self.blocked_ips = blocked_ips
        self.window_seconds = config["sliding_window_seconds"]
        self.zscore_threshold = config["zscore_threshold"]
        self.rate_multiplier = config["rate_multiplier_threshold"]
        self.error_multiplier = config["error_rate_multiplier"]

        # Per-IP sliding windows
        self.ip_windows = defaultdict(lambda: SlidingWindow(self.window_seconds))

        # Global sliding window
        self.global_window = SlidingWindow(self.window_seconds)

        self.lock = threading.Lock()

    def record(self, entry: dict) -> list:
        """
        Process one log entry.
        Returns list of anomaly dicts (may be empty).
        """
        now = time.time()
        ip = entry.get("source_ip", "unknown")
        status = int(entry.get("status", 200))
        is_error = status >= 400

        # Skip already-blocked IPs
        if ip in self.blocked_ips:
            return []

        # Record in per-IP and global windows
        self.ip_windows[ip].add(now, is_error)
        self.global_window.add(now, is_error)

        anomalies = []

        # Check per-IP anomaly
        ip_anomaly = self._check_ip(ip, now)
        if ip_anomaly:
            anomalies.append(ip_anomaly)

        # Check global anomaly
        global_anomaly = self._check_global(now)
        if global_anomaly:
            anomalies.append(global_anomaly)

        return anomalies

    def _check_ip(self, ip: str, now: float) -> dict | None:
        """Check if a single IP is anomalous."""
        mean, stddev = self.baseline.get()
        ip_rate = self.ip_windows[ip].rate(now)

        # Check error surge — tighten threshold if errors are high
        error_mean, error_stddev = self.baseline.get_error_baseline()
        ip_error_rate = self.ip_windows[ip].error_rate(now)
        threshold = self.zscore_threshold

        if error_mean > 0 and ip_error_rate > self.error_multiplier * error_mean:
            threshold = threshold * 0.5  # tighten threshold by 50%

        # Z-score detection
        if stddev > 0:
            zscore = (ip_rate - mean) / stddev
        else:
            zscore = 0

        fired = False
        condition = None

        if zscore > threshold:
            fired = True
            condition = f"zscore={zscore:.2f} > threshold={threshold:.2f}"
        elif mean > 0 and ip_rate > self.rate_multiplier * mean:
            fired = True
            condition = f"rate={ip_rate:.2f} > {self.rate_multiplier}x mean={mean:.2f}"

        if fired:
            return {
                "type": "ip",
                "ip": ip,
                "rate": ip_rate,
                "mean": mean,
                "stddev": stddev,
                "zscore": zscore,
                "condition": condition,
                "timestamp": now,
            }
        return None

    def _check_global(self, now: float) -> dict | None:
        """Check if global traffic rate is anomalous."""
        mean, stddev = self.baseline.get()
        global_rate = self.global_window.rate(now)

        if stddev > 0:
            zscore = (global_rate - mean) / stddev
        else:
            zscore = 0

        fired = False
        condition = None

        if zscore > self.zscore_threshold:
            fired = True
            condition = f"global zscore={zscore:.2f} > {self.zscore_threshold}"
        elif mean > 0 and global_rate > self.rate_multiplier * mean:
            fired = True
            condition = f"global rate={global_rate:.2f} > {self.rate_multiplier}x mean={mean:.2f}"

        if fired:
            return {
                "type": "global",
                "ip": None,
                "rate": global_rate,
                "mean": mean,
                "stddev": stddev,
                "zscore": zscore,
                "condition": condition,
                "timestamp": now,
            }
        return None

    def get_top_ips(self, n: int = 10) -> list:
        """Return top N IPs by current request rate."""
        now = time.time()
        rates = []
        for ip, window in self.ip_windows.items():
            rates.append((ip, window.rate(now)))
        rates.sort(key=lambda x: x[1], reverse=True)
        return rates[:n]

    def get_global_rate(self) -> float:
        return self.global_window.rate()
