
"""
NIDRS - Network Intrusion Detection & Response System
Entry point. Run with: sudo python3 main.py

Requires root (for packet capture + iptables) on Linux, and the `scapy` package.
Starts:
  1. A background Flask dashboard (http://127.0.0.1:8899 by default)
  2. Live packet capture on the main thread, feeding the detection engine

Edit config.py to tune thresholds, enable/disable auto-blocking, and set DRY_RUN.
"""

import os
import sys
import threading

import config
from alert_manager import AlertManager
from detection_engine import DetectionEngine
from response_engine import ResponseEngine
from packet_capture import PacketCapture
from dashboard import run_dashboard


def check_privileges():
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("WARNING: not running as root. Live packet capture and iptables")
        print("         blocking require root privileges (sudo python3 main.py).")
        print("         Continuing anyway - capture will likely fail.\n")


def main():
    check_privileges()

    alert_manager = AlertManager()
    detection_engine = DetectionEngine(alert_manager)
    response_engine = ResponseEngine(alert_manager)

    # Wrap raise_alert so every alert also gets passed to the response engine.
    original_raise = alert_manager.raise_alert

    def raise_and_respond(*args, **kwargs):
        alert = original_raise(*args, **kwargs)
        if alert:
            response_engine.handle_alert(alert)
        return alert

    alert_manager.raise_alert = raise_and_respond

    dash_thread = threading.Thread(
        target=run_dashboard, args=(alert_manager, response_engine), daemon=True
    )
    dash_thread.start()
    print(f"[*] Dashboard running at http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    print(f"[*] Mode: {'DRY RUN (no real blocking)' if config.DRY_RUN else 'LIVE BLOCKING'}")

    capture = PacketCapture(detection_engine)
    try:
        capture.start()
    except PermissionError:
        print("\nERROR: Permission denied opening a raw socket.")
        print("Run this script with sudo: sudo python3 main.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down NIDRS.")


if __name__ == "__main__":
    main()
