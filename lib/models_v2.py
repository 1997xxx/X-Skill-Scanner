#!/usr/bin/env python3
"""
Backward compatibility shim for models_v2.py.

All imports are redirected to the unified models.py.
New code should import directly from models.py.
"""

from models import (
    Severity,
    ThreatCategory,
    Finding,
    SkillFile,
    ScanResult,
    max_severity,
    get_findings_by_severity,
    get_findings_by_category,
)

__all__ = [
    'Severity',
    'ThreatCategory',
    'Finding',
    'SkillFile', 
    'ScanResult',
    'max_severity',
    'get_findings_by_severity',
    'get_findings_by_category',
]
