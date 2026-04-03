#!/usr/bin/env python3
"""
Shared constants for X-Skill-Scanner v6.0

Centralizes magic numbers and configuration values.
"""

# ─── Risk Scoring ─────────────────────────────────────────────────
MAX_RISK_SCORE = 100
MIN_RISK_SCORE = 0

# Severity weights for risk calculation
SEVERITY_WEIGHTS = {
    'CRITICAL': 25,
    'HIGH': 15,
    'MEDIUM': 8,
    'LOW': 3,
    'INFO': 1,
    'SAFE': 0,
}

# ─── Trust Score Thresholds ───────────────────────────────────────
TRUST_THRESHOLD_QUICK = 70      # ≥70 → Quick mode
TRUST_THRESHOLD_STANDARD = 40   # ≥40 → Standard mode
                                # <40 → Full mode

DEFAULT_TRUST_SCORE = 50

# ─── File Limits ──────────────────────────────────────────────────
MAX_FILES_QUICK_MODE = 20
MAX_FILES_STANDARD_MODE = 100
MAX_FILE_SIZE_MB = 10

# ─── Network Defaults ─────────────────────────────────────────────
DEFAULT_TIMEOUT_SECONDS = 30
LLM_REVIEW_TIMEOUT_SECONDS = 60

# ─── Report Formats ───────────────────────────────────────────────
SUPPORTED_FORMATS = ['text', 'html', 'json', 'md', 'sarif']
DEFAULT_REPORT_FORMAT = 'text'

# ─── Version ──────────────────────────────────────────────────────
SCANNER_VERSION = "6.0.0"

# ─── HTML Report CSS (minified for embedding) ─────────────────────
# Split into multi-line strings to avoid >120 char lines
HTML_CSS_BASE = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:20px;
    background:#f0f2f5;color:#333;line-height:1.6}
.ctn{max-width:960px;margin:0 auto;background:#fff;padding:32px;border-radius:12px;
    box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{color:#1a1a2e;border-bottom:3px solid #007bff;padding-bottom:12px;margin-bottom:20px;font-size:24px}
h2{color:#1a1a2e;font-size:18px;margin:24px 0 12px;padding-bottom:6px;border-bottom:1px solid #eee}
.meta{color:#666;font-size:14px;margin-bottom:20px}.meta p{margin:4px 0}
.sts{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}
.st{background:linear-gradient(135deg,#f8f9fa,#e9ecef);padding:16px;border-radius:8px;text-align:center}
.sv{font-size:28px;font-weight:700;color:#007bff}
.sl{font-size:12px;color:#666;margin-top:4px}
.bg{display:inline-block;padding:8px 16px;border-radius:6px;font-weight:700;font-size:16px}
.bl{background:#28a745;color:#fff}.bm{background:#ffc107;color:#000}
.bh{background:#fd7e14;color:#fff}.be{background:#dc3545;color:#fff}
.vd{font-size:22px;font-weight:700;margin:20px 0;padding:16px;border-radius:8px;text-align:center}
.vs{background:#d4edda;color:#155724}.vc{background:#fff3cd;color:#856404}
.vdg{background:#f8d7da;color:#721c24}
table{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px;table-layout:fixed}
html{scroll-behavior:smooth}
.src-hdr td{background:#e9ecef!important;font-weight:700;font-size:12px;color:#495057;
    text-transform:uppercase;letter-spacing:.5px;padding:6px 10px;border-bottom:2px solid #dee2e6}
.clickable{cursor:pointer;transition:background .15s}.clickable:hover{background:#f0f4ff}
.nav-float{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:8px;z-index:999}
.nav-btn{width:44px;height:44px;border-radius:50%;border:none;background:#007bff;color:#fff;
    font-size:20px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.2);
    display:flex;align-items:center;justify-content:center;text-decoration:none;
    transition:background .2s,transform .15s}
.nav-btn:hover{background:#0056b3;transform:scale(1.1)}
th{background:#f8f9fa;font-weight:600;padding:8px 10px;text-align:left;
    border-bottom:2px solid #dee2e6;white-space:normal;line-height:1.4}
td{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top;
    overflow-wrap:break-word;word-break:break-word;max-width:0}
.cs{width:75px;white-space:nowrap}.ci{min-width:0}
.cl{width:160px;overflow:hidden}.cr{width:120px;overflow:hidden}
.cr code,.cl code{font-size:12px;word-break:break-all;overflow-wrap:break-word;
    max-width:100%;display:inline-block}
.cr small,.cl small{font-size:11px;display:block;margin-top:2px}
.sc{color:#dc3545;font-weight:700}.sh{color:#fd7e14;font-weight:600}
.sm{color:#e6a800;font-weight:600}.slo{color:#28a745}
.mbadge{display:inline-block;background:#6c757d;color:#fff;font-size:11px;
    padding:2px 6px;border-radius:10px;margin-left:6px;vertical-align:middle}
.cb{background:#1e1e1e;color:#d4d4d4;padding:10px 14px;border-radius:6px;margin:8px 0;
    overflow-x:auto;font-family:"SF Mono","Fira Code",monospace;font-size:13px;
    line-height:1.5;white-space:pre-wrap;word-break:break-all;max-height:180px;max-width:100%}
.ds{color:#333;font-size:14px;line-height:1.6;margin:6px 0;overflow-wrap:break-word;word-break:break-word}
.smry{background:#f8f9fa;padding:16px;border-radius:8px;margin-top:20px;font-size:15px;line-height:1.8}
.sumbox{font-size:14px}.sumrow{display:flex;justify-content:space-between;padding:4px 0;gap:16px}
.sumlbl{font-weight:600;white-space:nowrap;flex-shrink:0}
@media(max-width:768px){.ctn{padding:16px}table{font-size:12px}th,td{padding:8px 6px}
    .cl{display:none}.sts{grid-template-columns:repeat(2,1fr)}}
"""

# ─── HTML Report Templates ────────────────────────────────────────
# Common HTML snippets for report generation (avoid long inline strings)
HTML_SUMROW = '<div class="sumrow"><span class="sumlbl">{label}</span><span>{value}</span></div>'
HTML_FINDING_ROW = '<tr class="{cls}"><td>{label}</td><td style="color:{color};font-weight:700">{val}</td></tr>'
HTML_CODE_BLOCK = '<pre style="background:#1a1a2e;color:#e9456e;padding:10px;border-radius:4px;overflow-x:auto"><code>{code}</code></pre>'
HTML_FINDING_CARD = '<div style="background:#fff;border-left:4px solid {color};padding:16px;border-radius:4px;margin:8px 0">'
HTML_FINDING_META = '<p style="margin:4px 0;font-size:13px"><b>Type:</b> {type} | <b>Severity:</b> {sev}</p>'
HTML_FINDING_DESC = '<p style="margin:8px 0 4px;font-size:14px;line-height:1.5">{desc}</p>'
HTML_INLINE_CODE = '<pre style="background:#f8f9fa;padding:8px;border-radius:4px;font-size:12px;overflow-x:auto"><code>{code}</code></pre>'
