"""
DetectionEngine: stateless-in / stateful-out. Feed it parsed packet events
(a lightweight dict, not raw scapy packets, so it's easy to unit test)
and it raises alerts through AlertManager based on the rules in config.py.
"""

import re
import time
import os
from collections import defaultdict, deque

import config
from alert_manager import AlertManager


class DetectionEngine:
    def __init__(self, alert_manager: AlertManager):
        self.alert_manager = alert_manager

        # src_ip -> deque[(timestamp, dst_port)]  for port scan detection
        self._port_history = defaultdict(deque)
        # src_ip -> deque[timestamp] for SYN flood
        self._syn_history = defaultdict(deque)
        # src_ip -> deque[timestamp] for generic connection flood
        self._conn_history = defaultdict(deque)

        self._blacklist = self._load_blacklist()
        self._signatures = [(name, re.compile(pattern), sev)
                             for name, pattern, sev in config.PAYLOAD_SIGNATURES]

    def _load_blacklist(self):
        ips = set()
        if os.path.exists(config.BLACKLIST_FILE):
            with open(config.BLACKLIST_FILE) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips.add(line)
        return ips

    def process_packet(self, event: dict):
        """
        event schema (all keys except src_ip optional):
        {
            "src_ip": str,
            "dst_ip": str,
            "dst_port": int,
            "proto": "TCP" | "UDP" | "ICMP" | ...,
            "flags": str,          # e.g. "S", "SA", "PA" for TCP flags
            "payload": bytes,      # raw payload, may be empty
            "timestamp": float,    # defaults to now
        }
        """
        src_ip = event.get("src_ip")
        if not src_ip or src_ip in config.WHITELIST:
            return

        now = event.get("timestamp", time.time())

        self._check_blacklist(src_ip, event, now)
        self._check_conn_flood(src_ip, event, now)
        if event.get("proto") == "TCP":
            self._check_port_scan(src_ip, event, now)
            if "S" in (event.get("flags") or "") and "A" not in (event.get("flags") or ""):
                self._check_syn_flood(src_ip, event, now)
        self._check_signatures(src_ip, event, now)

    # ---- individual rules ----

    def _check_blacklist(self, src_ip, event, now):
        if src_ip in self._blacklist:
            alert = self.alert_manager.raise_alert(
                rule="blacklisted_ip", severity="high", src_ip=src_ip,
                dst_ip=event.get("dst_ip"), dst_port=event.get("dst_port"),
                detail="Source IP is in static blacklist",
            )
            return alert

    def _check_port_scan(self, src_ip, event, now):
        dst_port = event.get("dst_port")
        if dst_port is None:
            return
        hist = self._port_history[src_ip]
        hist.append((now, dst_port))
        cutoff = now - config.PORT_SCAN_WINDOW_SECONDS
        while hist and hist[0][0] < cutoff:
            hist.popleft()

        unique_ports = {p for _, p in hist}
        if len(unique_ports) >= config.PORT_SCAN_UNIQUE_PORT_THRESHOLD:
            self.alert_manager.raise_alert(
                rule="port_scan", severity="high", src_ip=src_ip,
                dst_ip=event.get("dst_ip"),
                detail=f"{len(unique_ports)} unique dest ports in "
                       f"{config.PORT_SCAN_WINDOW_SECONDS}s window",
            )

    def _check_syn_flood(self, src_ip, event, now):
        hist = self._syn_history[src_ip]
        hist.append(now)
        cutoff = now - config.SYN_FLOOD_WINDOW_SECONDS
        while hist and hist[0] < cutoff:
            hist.popleft()

        if len(hist) >= config.SYN_FLOOD_COUNT_THRESHOLD:
            self.alert_manager.raise_alert(
                rule="syn_flood", severity="critical", src_ip=src_ip,
                dst_ip=event.get("dst_ip"), dst_port=event.get("dst_port"),
                detail=f"{len(hist)} SYNs in {config.SYN_FLOOD_WINDOW_SECONDS}s window",
            )

    def _check_conn_flood(self, src_ip, event, now):
        hist = self._conn_history[src_ip]
        hist.append(now)
        cutoff = now - config.CONN_WINDOW_SECONDS
        while hist and hist[0] < cutoff:
            hist.popleft()

        if len(hist) >= config.CONN_COUNT_THRESHOLD:
            self.alert_manager.raise_alert(
                rule="connection_flood", severity="medium", src_ip=src_ip,
                dst_ip=event.get("dst_ip"),
                detail=f"{len(hist)} packets in {config.CONN_WINDOW_SECONDS}s window",
            )

    def _check_signatures(self, src_ip, event, now):
        payload = event.get("payload")
        if not payload:
            return
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return
        for name, pattern, sev in self._signatures:
            if pattern.search(text):
                self.alert_manager.raise_alert(
                    rule=f"signature:{name}", severity=sev, src_ip=src_ip,
                    dst_ip=event.get("dst_ip"), dst_port=event.get("dst_port"),
                    detail=f"Payload matched signature '{name}'",
                )
