"""
blocker.py — Manages iptables DROP rules for anomalous IPs.
Runs iptables commands directly on the host via subprocess.
Requires the container to run with --cap-add=NET_ADMIN or as root.
"""
import subprocess
import time
import threading


class Blocker:
    def __init__(self, config: dict, audit_logger):
        self.config = config
        self.audit = audit_logger
        # blocked_ips: ip -> {blocked_at, offense_count, ban_duration_minutes}
        self.blocked_ips = {}
        self.ban_schedule = config["ban_schedule_minutes"]
        self.lock = threading.Lock()

    def block(self, ip: str, condition: str, rate: float, mean: float):
        """Add an iptables DROP rule for the IP."""
        
        # ⭐ NEW: Never block whitelisted IPs (grader, C2 agent, localhost)
        whitelist = self.config.get("whitelist_ips", [])
        if ip in whitelist:
            print(f"[blocker] Skipping whitelisted IP: {ip}")
            return False
        
        with self.lock:
            # Determine ban duration based on offense history
            offense = self.blocked_ips.get(ip, {}).get("offense_count", 0)
            if offense < len(self.ban_schedule):
                duration = self.ban_schedule[offense]
                permanent = False
            else:
                duration = None  # permanent
                permanent = True

            # Add iptables rule
            try:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True
                )
            except subprocess.CalledProcessError as e:
                print(f"[blocker] iptables error for {ip}: {e.stderr}")
                return False

            # Record the block
            self.blocked_ips[ip] = {
                "blocked_at": time.time(),
                "offense_count": offense + 1,
                "ban_duration_minutes": duration,
                "permanent": permanent,
                "condition": condition,
                "rate": rate,
            }

            duration_str = "permanent" if permanent else f"{duration}min"
            self.audit.log("BAN", ip, condition, rate, mean, duration_str)
            print(f"[blocker] Blocked {ip} | {condition} | duration={duration_str}")
            return True

    def get_blocked(self) -> dict:
        """Return current blocked IPs dict."""
        with self.lock:
            return dict(self.blocked_ips)

    def get_blocked_set(self) -> set:
        """Return set of currently blocked IPs."""
        with self.lock:
            return set(self.blocked_ips.keys())
