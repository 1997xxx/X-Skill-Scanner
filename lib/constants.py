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
