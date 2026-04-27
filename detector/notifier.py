"""
notifier.py — Sends Slack webhook alerts for bans, unbans, and global anomalies.
All alerts include: condition, rate, baseline, timestamp, and ban duration.
"""
import requests
import time
from datetime import datetime


class Notifier:
    def __init__(self, config: dict):
        self.webhook_url = config["slack_webhook_url"]
        self.enabled = self.webhook_url and "hooks.slack.com" in self.webhook_url

    def _send(self, payload: dict):
        """Send a payload to the Slack webhook."""
        if not self.enabled:
            print(f"[notifier] Slack not configured — would have sent: {payload['text'][:80]}")
            return
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=5)
            if resp.status_code != 200:
                print(f"[notifier] Slack error {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"[notifier] Slack request failed: {e}")

    def send_ban(self, ip: str, condition: str, rate: float,
                 mean: float, stddev: float, duration: str):
        """Send a ban alert."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        text = (
            f":rotating_light: *IP BANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Rate:* {rate:.2f} req/s\n"
            f"*Baseline:* mean={mean:.2f} stddev={stddev:.2f}\n"
            f"*Ban Duration:* {duration}\n"
            f"*Timestamp:* {ts}"
        )
        self._send({"text": text})

    def send_unban(self, ip: str, offense_count: int, prev_duration: int):
        """Send an unban alert."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        text = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Offense Count:* {offense_count}\n"
            f"*Was Banned For:* {prev_duration} minutes\n"
            f"*Timestamp:* {ts}"
        )
        self._send({"text": text})

    def send_global_alert(self, condition: str, rate: float, mean: float, stddev: float):
        """Send a global anomaly alert (no ban — alert only)."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Condition:* {condition}\n"
            f"*Global Rate:* {rate:.2f} req/s\n"
            f"*Baseline:* mean={mean:.2f} stddev={stddev:.2f}\n"
            f"*Action:* Alert only (no IP to block)\n"
            f"*Timestamp:* {ts}"
        )
        self._send({"text": text})
