"""
Lightweight Flask dashboard: shows recent alerts and currently blocked IPs.
Runs on config.DASHBOARD_HOST:DASHBOARD_PORT. Read-only, no external deps beyond Flask.
"""

from flask import Flask, jsonify, render_template_string
import time

import config

PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>NIDRS Dashboard</title>
<meta charset="utf-8">
<style>
  :root { color-scheme: dark; }
  body { background:#0d1117; color:#c9d1d9; font-family: -apple-system, "Segoe UI", sans-serif; margin:0; padding:24px; }
  h1 { color:#58a6ff; font-size:20px; margin-bottom:4px;}
  .sub { color:#8b949e; font-size:13px; margin-bottom:20px;}
  .stats { display:flex; gap:16px; margin-bottom:24px; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:14px 20px; }
  .card .num { font-size:26px; font-weight:700; }
  .card .label { font-size:12px; color:#8b949e; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #21262d; }
  th { color:#8b949e; font-weight:600; text-transform:uppercase; font-size:11px; }
  .sev-critical { color:#f85149; font-weight:700; }
  .sev-high { color:#ff7b72; font-weight:600; }
  .sev-medium { color:#d29922; }
  .sev-low { color:#8b949e; }
  .badge { padding:2px 8px; border-radius:10px; font-size:11px; }
  .badge-blocked { background:#3d1418; color:#f85149; }
  .badge-none { background:#21262d; color:#8b949e; }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:#3fb950; margin-right:6px; }
  code { background:#21262d; padding:2px 5px; border-radius:4px; }
</style>
</head>
<body>
  <h1><span class="dot"></span>NIDRS &mdash; Network Intrusion Detection &amp; Response</h1>
  <div class="sub" id="mode">loading...</div>
  <div class="stats">
    <div class="card"><div class="num" id="alert-count">0</div><div class="label">Alerts (recent)</div></div>
    <div class="card"><div class="num" id="blocked-count">0</div><div class="label">Blocked IPs</div></div>
  </div>
  <h2 style="font-size:14px;color:#8b949e;">Recent Alerts</h2>
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source IP</th><th>Target</th><th>Action</th><th>Detail</th></tr></thead>
    <tbody id="alert-body"></tbody>
  </table>

  <h2 style="font-size:14px;color:#8b949e;margin-top:24px;">Blocked IPs</h2>
  <table>
    <thead><tr><th>IP</th><th>Unblocks At</th></tr></thead>
    <tbody id="blocked-body"></tbody>
  </table>

<script>
async function refresh() {
  const res = await fetch('/api/status');
  const data = await res.json();
  document.getElementById('mode').textContent =
      (data.dry_run ? 'DRY RUN mode (no real blocking)' : 'LIVE blocking enabled') +
      ' \u2022 auto-refresh every ' + data.refresh_seconds + 's';
  document.getElementById('alert-count').textContent = data.alerts.length;
  document.getElementById('blocked-count').textContent = Object.keys(data.blocked).length;

  const abody = document.getElementById('alert-body');
  abody.innerHTML = data.alerts.map(a => `
    <tr>
      <td>${new Date(a.timestamp*1000).toLocaleTimeString()}</td>
      <td class="sev-${a.severity}">${a.severity.toUpperCase()}</td>
      <td>${a.rule}</td>
      <td><code>${a.src_ip}</code></td>
      <td>${a.dst_ip ? a.dst_ip + (a.dst_port ? ':' + a.dst_port : '') : '-'}</td>
      <td><span class="badge ${a.action_taken.includes('block') ? 'badge-blocked' : 'badge-none'}">${a.action_taken}</span></td>
      <td>${a.detail}</td>
    </tr>`).join('');

  const bbody = document.getElementById('blocked-body');
  const entries = Object.entries(data.blocked);
  bbody.innerHTML = entries.length ? entries.map(([ip, t]) => `
    <tr><td><code>${ip}</code></td><td>${t ? new Date(t*1000).toLocaleTimeString() : 'permanent'}</td></tr>
  `).join('') : '<tr><td colspan="2" style="color:#8b949e;">No IPs currently blocked</td></tr>';
}
refresh();
setInterval(refresh, {{ refresh_ms }});
</script>
</body>
</html>
"""


def create_app(alert_manager, response_engine):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(PAGE, refresh_ms=config.DASHBOARD_REFRESH_SECONDS * 1000)

    @app.route("/api/status")
    def status():
        return jsonify({
            "alerts": alert_manager.recent(200),
            "blocked": response_engine.blocked_ips(),
            "dry_run": config.DRY_RUN,
            "refresh_seconds": config.DASHBOARD_REFRESH_SECONDS,
            "server_time": time.time(),
        })

    return app


def run_dashboard(alert_manager, response_engine):
    app = create_app(alert_manager, response_engine)
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=False)
