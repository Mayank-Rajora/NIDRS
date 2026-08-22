

import json
import time
import threading
from collections import deque
from dataclasses import dataclass, asdict, field
from typing import Optional

import config


@dataclass
class Alert:
    timestamp: float
    rule: str            
    severity: str             
    src_ip: str
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    detail: str = ""
    action_taken: str = "none"   

    def to_dict(self):
        return asdict(self)


class AlertManager:
    def __init__(self, max_recent=500):
        self._lock = threading.Lock()
        self._recent = deque(maxlen=max_recent)
        
        self._last_seen = {}
        self._dedupe_window = 30

    def raise_alert(self, rule: str, severity: str, src_ip: str,
                     dst_ip: str = None, dst_port: int = None, detail: str = "") -> Optional[Alert]:
        now = time.time()
        key = (src_ip, rule)
        with self._lock:
            last = self._last_seen.get(key, 0)
            if now - last < self._dedupe_window:
                return None
            self._last_seen[key] = now

        alert = Alert(
            timestamp=now,
            rule=rule,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            detail=detail,
        )
        self._store(alert)
        return alert

    def mark_action(self, alert: Alert, action: str):
        alert.action_taken = action
       
        self._append_log(f"[ACTION] {alert.src_ip} rule={alert.rule} action={action}")

    def _store(self, alert: Alert):
        with self._lock:
            self._recent.append(alert)
        line = (f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.timestamp))}] "
                f"{alert.severity.upper():8s} {alert.rule:30s} src={alert.src_ip} "
                f"dst={alert.dst_ip}:{alert.dst_port} - {alert.detail}")
        self._append_log(line)
        self._append_json(alert)

    def _append_log(self, line: str):
        try:
            with open(config.ALERT_LOG_FILE, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def _append_json(self, alert: Alert):
        try:
            with open(config.ALERT_LOG_JSON, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except OSError:
            pass

    def recent(self, limit=100):
        with self._lock:
            items = list(self._recent)[-limit:]
        return [a.to_dict() for a in reversed(items)]
