"""
ResponseEngine: takes automated action against malicious IPs.
Uses iptables on Linux. Runs in DRY_RUN mode by default (config.DRY_RUN = True)
so nothing is actually blocked until you explicitly enable it.
"""

import subprocess
import threading
import time
import shutil

import config


class ResponseEngine:
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self._blocked = {}   # ip -> unblock_time (0 = permanent)
        self._lock = threading.Lock()
        self._has_iptables = shutil.which("iptables") is not None
        self._expiry_thread = threading.Thread(target=self._expiry_loop, daemon=True)
        self._expiry_thread.start()

    def handle_alert(self, alert):
        if alert is None:
            return
        if alert.src_ip in config.WHITELIST:
            return
        if not config.AUTO_BLOCK_ENABLED:
            return
        if alert.severity not in config.BLOCK_SEVERITIES:
            return
        self.block_ip(alert.src_ip)
        action = "dry_run_block" if config.DRY_RUN else "blocked"
        self.alert_manager.mark_action(alert, action)

    def block_ip(self, ip: str):
        with self._lock:
            already = ip in self._blocked
        if already:
            return

        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        if config.DRY_RUN or not self._has_iptables:
            print(f"[DRY RUN] Would block IP: {' '.join(cmd)}")
        else:
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=5)
                print(f"[BLOCKED] {ip} via iptables")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                print(f"[ERROR] Failed to block {ip}: {e}")
                return

        unblock_time = 0
        if config.BLOCK_DURATION_SECONDS > 0:
            unblock_time = time.time() + config.BLOCK_DURATION_SECONDS
        with self._lock:
            self._blocked[ip] = unblock_time

    def unblock_ip(self, ip: str):
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        if config.DRY_RUN or not self._has_iptables:
            print(f"[DRY RUN] Would unblock IP: {' '.join(cmd)}")
        else:
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=5)
                print(f"[UNBLOCKED] {ip}")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                print(f"[ERROR] Failed to unblock {ip}: {e}")
        with self._lock:
            self._blocked.pop(ip, None)

    def _expiry_loop(self):
        while True:
            time.sleep(5)
            now = time.time()
            with self._lock:
                expired = [ip for ip, t in self._blocked.items() if t and t <= now]
            for ip in expired:
                self.unblock_ip(ip)

    def blocked_ips(self):
        with self._lock:
            return dict(self._blocked)
