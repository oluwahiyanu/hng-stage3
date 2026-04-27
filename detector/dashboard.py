"""
dashboard.py — Flask web dashboard refreshing every 3 seconds.
Shows: banned IPs, global req/s, top 10 IPs, CPU/memory, baseline, uptime.
"""
from flask import Flask, render_template_string
import psutil
import time

app = Flask(__name__)

# These are set by main.py after all components are initialised
_detector = None
_blocker = None
_baseline = None
_start_time = time.time()

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector — Live Dashboard</title>
    <meta http-equiv="refresh" content="3">
    <style>
        body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
        h1   { color: #58a6ff; }
        h2   { color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th   { background: #161b22; color: #58a6ff; padding: 8px 12px; text-align: left; }
        td   { padding: 8px 12px; border-bottom: 1px solid #21262d; }
        tr:hover td { background: #161b22; }
        .badge-ban  { background: #da3633; color: white; padding: 2px 8px; border-radius: 4px; }
        .badge-ok   { background: #238636; color: white; padding: 2px 8px; border-radius: 4px; }
        .metric     { display: inline-block; background: #161b22; border: 1px solid #30363d;
                      border-radius: 6px; padding: 12px 20px; margin: 5px; min-width: 140px; }
        .metric-val { font-size: 1.8em; color: #58a6ff; font-weight: bold; }
        .metric-lbl { color: #8b949e; font-size: 0.8em; }
        .alert      { background: #3d1f1f; border: 1px solid #da3633; border-radius: 6px;
                      padding: 10px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <h1>🛡️ HNG Anomaly Detection Engine</h1>
    <p style="color:#8b949e">Uptime: {{ uptime }} | Last refresh: {{ now }}</p>

    <div>
        <div class="metric">
            <div class="metric-val">{{ global_rate }}</div>
            <div class="metric-lbl">Global req/s</div>
        </div>
        <div class="metric">
            <div class="metric-val">{{ banned_count }}</div>
            <div class="metric-lbl">Banned IPs</div>
        </div>
        <div class="metric">
            <div class="metric-val">{{ cpu }}%</div>
            <div class="metric-lbl">CPU Usage</div>
        </div>
        <div class="metric">
            <div class="metric-val">{{ mem }}%</div>
            <div class="metric-lbl">Memory Usage</div>
        </div>
        <div class="metric">
            <div class="metric-val">{{ mean }}</div>
            <div class="metric-lbl">Baseline Mean</div>
        </div>
        <div class="metric">
            <div class="metric-val">{{ stddev }}</div>
            <div class="metric-lbl">Baseline StdDev</div>
        </div>
    </div>

    <h2>🚫 Banned IPs</h2>
    {% if banned %}
    <table>
        <tr><th>IP</th><th>Condition</th><th>Rate</th><th>Offense #</th><th>Duration</th><th>Expires</th></tr>
        {% for ip, info in banned.items() %}
        <tr>
            <td><span class="badge-ban">{{ ip }}</span></td>
            <td>{{ info.condition }}</td>
            <td>{{ "%.2f"|format(info.rate) }} req/s</td>
            <td>{{ info.offense_count }}</td>
            <td>{{ info.ban_duration_minutes or "permanent" }} min</td>
            <td>{{ info.expires }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <p style="color:#238636">✅ No IPs currently banned</p>
    {% endif %}

    <h2>📊 Top 10 Source IPs</h2>
    <table>
        <tr><th>Rank</th><th>IP</th><th>Rate (req/s)</th><th>Status</th></tr>
        {% for rank, (ip, rate) in enumerate(top_ips, 1) %}
        <tr>
            <td>{{ rank }}</td>
            <td>{{ ip }}</td>
            <td>{{ "%.3f"|format(rate) }}</td>
            <td>{% if ip in banned %}<span class="badge-ban">BANNED</span>
                {% else %}<span class="badge-ok">OK</span>{% endif %}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""


def format_uptime(seconds):
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h}h {m}m {s}s"


def format_expires(info):
    if info.get("permanent"):
        return "permanent"
    duration = info.get("ban_duration_minutes", 0)
    unban_at = info["blocked_at"] + duration * 60
    remaining = max(0, unban_at - time.time())
    m = int(remaining // 60)
    s = int(remaining % 60)
    return f"{m}m {s}s"


@app.route("/")
def index():
    from datetime import datetime

    mean, stddev = _baseline.get() if _baseline else (0, 0)
    banned = _blocker.get_blocked() if _blocker else {}
    top_ips = _detector.get_top_ips(10) if _detector else []
    global_rate = _detector.get_global_rate() if _detector else 0

    # Add expires field to banned info
    for ip, info in banned.items():
        info["expires"] = format_expires(info)

    return render_template_string(
        TEMPLATE,
        uptime=format_uptime(time.time() - _start_time),
        now=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        global_rate=f"{global_rate:.2f}",
        banned_count=len(banned),
        cpu=f"{psutil.cpu_percent():.1f}",
        mem=f"{psutil.virtual_memory().percent:.1f}",
        mean=f"{mean:.2f}",
        stddev=f"{stddev:.2f}",
        banned=banned,
        top_ips=top_ips,
        enumerate=enumerate,
    )


def start_dashboard(detector, blocker, baseline, port=8080):
    global _detector, _blocker, _baseline
    _detector = detector
    _blocker = blocker
    _baseline = baseline
    t = __import__("threading").Thread(
        target=lambda: app.run(host="0.0.0.0", port=port, debug=False),
        daemon=True
    )
    t.start()
    print(f"[dashboard] Running on port {port}")
