# NIDRS — Network Intrusion Detection & Response System

A working, self-contained Python NIDRS: live packet capture, rule-based detection,
automatic response (IP blocking), alert logging, and a real-time web dashboard.

## What it detects

| Rule | Logic |
|---|---|
| **Port scan** | ≥15 unique dest ports from one source IP within 10s |
| **SYN flood** | ≥100 SYN packets from one source IP within 5s |
| **Connection flood** | ≥40 packets from one source IP within 30s (generic brute-force/DoS) |
| **Blacklisted IP** | Source IP matches `blacklist.txt` |
| **Payload signatures** | Regex match on packet payload — SQL injection, path traversal, shell injection, Log4Shell JNDI, XSS |

All thresholds live in `config.py`.

## What it does when it detects something

Alerts of severity `high`/`critical` trigger an automatic `iptables -I INPUT -s <ip> -j DROP`,
with a configurable auto-expiry (default 15 min). **Ships in `DRY_RUN = True` mode** — it will
log exactly what it *would* block without touching your firewall, until you flip that off.

## Setup

```bash
pip install -r requirements.txt
```

## Run the tests (no root/network needed)

Proves every detection rule fires correctly against synthetic and real scapy-crafted packets:

```bash
python3 test_nidrs.py
```

## Run it live

Packet capture and iptables both need root:

```bash
sudo python3 main.py
```

Then open the dashboard: **http://127.0.0.1:8899**

## Going from dry-run to real blocking

In `config.py`:
```python
DRY_RUN = False           # actually run iptables commands
AUTO_BLOCK_ENABLED = True # keep alerts triggering responses
```
Only do this on a machine you're allowed to firewall, and consider adding your own
management IP to `WHITELIST` first so you can't lock yourself out.

## Files

- `main.py` — entry point, wires everything together
- `packet_capture.py` — scapy sniffing → event dicts
- `detection_engine.py` — stateful sliding-window rules
- `response_engine.py` — iptables blocking + auto-expiry
- `alert_manager.py` — structured alerts, dedupe, logging (`alerts.log` / `alerts.jsonl`)
- `dashboard.py` — Flask live-updating web UI
- `config.py` — every tunable in one place
- `test_nidrs.py` — synthetic-traffic + real-scapy-packet test suite (8/8 passing)

## Limitations / honest caveats

- This is a signature + heuristic NIDS, not a commercial-grade ML-based system —
  it will miss slow/low-and-slow scans and novel attacks with no signature.
- Payload signature matching only works on unencrypted traffic (won't see inside TLS).
- Single-process, single-host: no distributed correlation across multiple sensors.
- Tune the thresholds in `config.py` for your actual network — defaults are reasonable
  starting points, not universal truths.
