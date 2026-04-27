"""
baseline.py — Maintains a rolling 30-minute baseline of per-second request rates.
Recalculates mean and stddev every 60 seconds.
Prefers the current hour's data when it has enough samples.

Structure:
- per_second_counts: deque of (timestamp, count) tuples covering 30 minutes
- hourly_slots: dict of hour -> list of per-second counts
- effective_mean, effective_stddev: current baseline values
"""
import time
import math
from collections import deque
from datetime import datetime
import threading
import yaml


def load_config(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)


class Baseline:
    def __init__(self, config: dict):
        self.config = config
        self.window_seconds = config["baseline_window_minutes"] * 60
        self.recalc_interval = config["baseline_recalc_interval"]
        self.floor_mean = config["baseline_floor_mean"]
        self.floor_stddev = config["baseline_floor_stddev"]
        self.min_samples = config["baseline_min_samples"]

        # Rolling window: stores (timestamp, count) for last 30 minutes
        self.per_second_counts = deque()

        # Per-hour slots: hour (0-23) -> list of per-second counts
        self.hourly_slots = {}

        # Current computed baseline
        self.effective_mean = self.floor_mean
        self.effective_stddev = self.floor_stddev

        # Error baseline (4xx/5xx rates)
        self.error_mean = self.floor_mean
        self.error_stddev = self.floor_stddev
        self.per_second_errors = deque()

        self.lock = threading.Lock()
        self.last_recalc = time.time()

    def record(self, timestamp: float, count: int, error_count: int = 0):
        """Record a per-second request count into the rolling window."""
        with self.lock:
            now = timestamp
            cutoff = now - self.window_seconds

            # Add new data point
            self.per_second_counts.append((now, count))
            self.per_second_errors.append((now, error_count))

            # Evict entries older than the window
            while self.per_second_counts and self.per_second_counts[0][0] < cutoff:
                self.per_second_counts.popleft()
            while self.per_second_errors and self.per_second_errors[0][0] < cutoff:
                self.per_second_errors.popleft()

            # Add to hourly slot
            hour = datetime.fromtimestamp(now).hour
            if hour not in self.hourly_slots:
                self.hourly_slots[hour] = []
            self.hourly_slots[hour].append(count)

            # Recalculate every recalc_interval seconds
            if now - self.last_recalc >= self.recalc_interval:
                self._recalculate()
                self.last_recalc = now

    def _recalculate(self):
        """
        Recompute effective_mean and effective_stddev.
        Prefers current hour's data if it has enough samples.
        Falls back to full 30-minute window.
        """
        current_hour = datetime.now().hour
        hour_data = self.hourly_slots.get(current_hour, [])

        # Use current hour data if it has enough samples
        if len(hour_data) >= self.min_samples:
            counts = hour_data
            source = f"hour-{current_hour}"
        else:
            counts = [c for _, c in self.per_second_counts]
            source = "30min-window"

        if len(counts) < 2:
            return

        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        stddev = math.sqrt(variance)

        # Apply floor values to prevent false positives at very low traffic
        self.effective_mean = max(mean, self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)

        # Error baseline
        error_counts = [c for _, c in self.per_second_errors]
        if len(error_counts) >= 2:
            emean = sum(error_counts) / len(error_counts)
            evar = sum((x - emean) ** 2 for x in error_counts) / len(error_counts)
            self.error_mean = max(emean, self.floor_mean)
            self.error_stddev = max(math.sqrt(evar), self.floor_stddev)

        print(f"[baseline] Recalculated from {source}: "
              f"mean={self.effective_mean:.2f} stddev={self.effective_stddev:.2f}")

        return source

    def get(self):
        """Return current baseline values."""
        with self.lock:
            return self.effective_mean, self.effective_stddev

    def get_error_baseline(self):
        """Return error rate baseline."""
        with self.lock:
            return self.error_mean, self.error_stddev
