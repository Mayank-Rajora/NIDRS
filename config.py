"""
NIDRS Configuration
Edit these values to tune detection sensitivity and response behavior.
"""

# --- Capture ---
INTERFACE = None          # e.g. "eth0"; None = scapy auto-picks default interface
BPF_FILTER = "ip"         # Berkeley Packet Filter applied at capture time

# --- Port scan detection ---
PORT_SCAN_WINDOW_SECONDS = 5     # sliding window to look at
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 20   # distinct dest ports from one src IP in window -> alert

# --- SYN flood detection ---
SYN_FLOOD_WINDOW_SECONDS = 5
SYN_FLOOD_COUNT_THRESHOLD = 10   # SYNs from one src IP in window -> alert

# --- Repeated connection / brute force detection ---
CONN_WINDOW_SECONDS = 10
CONN_COUNT_THRESHOLD = 10          # total packets from one src IP in window -> alert

# --- Signature-based payload detection (simple substrings/regex, ASCII payload) ---
# Each entry: (name, regex pattern, severity)
PAYLOAD_SIGNATURES = [
    ("sql_injection_union_select", r"(?i)union(\s+all)?\s+select", "high"),
    ("sql_injection_or_1eq1",      r"(?i)or\s+1\s*=\s*1", "high"),
    ("path_traversal",             r"\.\./\.\./", "medium"),
    ("shell_injection_cmd",        r"(?i)(;|\|)\s*(nc|netcat|bash|/bin/sh)\b", "high"),
    ("log4shell_jndi",             r"(?i)\$\{jndi:", "critical"),
    ("xss_script_tag",             r"(?i)<script[^>]*>", "medium"),
]

# --- IP blacklist / whitelist ---
BLACKLIST_FILE = "blacklist.txt"   # one IP per line, static known-bad IPs
WHITELIST = {"127.0.0.1"}          # never alert/block these, e.g. your own management IP

# --- Response ---
AUTO_BLOCK_ENABLED = True          # if False, alerts are raised but nothing is blocked (detect-only mode)
BLOCK_SEVERITIES = {"high", "critical", "block"}  # which severities trigger an automatic block
BLOCK_DURATION_SECONDS = 900       # 15 min temporary block; 0 = permanent until manually unblocked
DRY_RUN = True                     # if True, log the iptables command instead of executing it (safe default)

# --- Alerting / logging ---
ALERT_LOG_FILE = "alerts.log"
ALERT_LOG_JSON = "alerts.jsonl"    # machine-readable, one JSON object per line, used by the dashboard

# --- Dashboard ---
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8899
DASHBOARD_REFRESH_SECONDS = 3
