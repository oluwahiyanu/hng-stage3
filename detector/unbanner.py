"""
unbanner.py — Automatically releases bans on a backoff schedule.
Runs as a background thread, checks every 30 seconds.
Backoff: 10min → 30min → 2hours → permanent.
"""
import subprocess
import time
import threading


class Unbanner:
    def __init__(self, blocker, notifier, audit_logger):
        self.blocker = blocker
        self.notifier = notifier
        self.audit = audit_logger
        self._stop = threading.Event()

    def start(self):
        """Start the unbanner background thread."""
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        print("[unbanner] Started background unban checker")

    def _run(self):
        while not self._stop.is_set():
            self._check_unbans()
            time.sleep(30)  # check every 30 seconds

    def _check_unbans(self):
        now = time.time()
        to_unban = []

        with self.blocker.lock:
            for ip, info in self.blocker.blocked_ips.items():
                if info.get("permanent"):
                    continue
                duration_minutes = info.get("ban_duration_minutes", 10)
                unban_at = info["blocked_at"] + (duration_minutes * 60)
                if now >= unban_at:
                    to_unban.append(ip)

        for ip in to_unban:
            self._unban(ip)

    def _unban(self, ip: str):
        """Remove iptables rule and update blocker state."""
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
        except subprocess.CalledProcessError as e:
            print(f"[unbanner] iptables remove error for {ip}: {e.stderr}")
            return

        with self.blocker.lock:
            info = self.blocker.blocked_ips.pop(ip, {})

        offense = info.get("offense_count", 1)
        schedule = self.blocker.ban_schedule
        condition = info.get("condition", "unknown")
        rate = info.get("rate", 0)
        prev_duration = info.get("ban_duration_minutes", 0)

        # Notify Slack about unban
        self.notifier.send_unban(ip, offense, prev_duration)
        self.audit.log("UNBAN", ip, condition, rate, 0, f"after {prev_duration}min")
        print(f"[unbanner] Unbanned {ip} after {prev_duration}min (offense #{offense})")

    def stop(self):
        self._stop.set()
