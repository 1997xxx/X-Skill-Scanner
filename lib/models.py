#!/usr/bin/env python3
"""
Unified Data Models for X-Skill-Scanner v6.0

Combines models.py and models_v2.py into a single consistent schema.
All modules should import from this file.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ─── Severity Levels ──────────────────────────────────────────────

class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    SAFE = "SAFE"  # v6.0: Added for explicit safe findings
    
    @classmethod
    def rank(cls, severity: str) -> int:
        """Return numeric rank for comparison (higher = more severe)."""
        ranks = {
            cls.SAFE: 0,
            cls.INFO: 1,
            cls.LOW: 2,
            cls.MEDIUM: 3,
            cls.HIGH: 4,
            cls.CRITICAL: 5,
        }
        return ranks.get(cls(severity), 0)
    
    def __gt__(self, other):
        if isinstance(other, Severity):
            return self.rank(self) > self.rank(other)
        return NotImplemented
    
    def __ge__(self, other):
        if isinstance(other, Severity):
            return self.rank(self) >= self.rank(other)
        return NotImplemented


# ─── Finding Categories (replaces FindingType) ────────────────────

class ThreatCategory(str, Enum):
    """Threat categories for findings."""
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    OBFUSCATION = "obfuscation"
    CREDENTIAL_THEFT = "credential_theft"
    SUPPLY_CHAIN = "supply_chain"
    PERSISTENCE = "persistence"
    RECONNAISSANCE = "reconnaissance"
    SOCIAL_ENGINEERING = "social_engineering"
    CONFIG_ISSUE = "config_issue"
    OTHER = "other"


# ─── Legacy FindingType alias for backward compatibility ──────────

class FindingType(str, Enum):
    """Legacy finding types - deprecated, use ThreatCategory instead."""
    INDIRECT_EXECUTION = "indirect_execution"
    ADVANCED_ENCODING = "advanced_encoding"
    SUBPROCESS_INJECTION = "subprocess_injection"
    YAML_UNSAFE_LOAD = "yaml_unsafe_load"
    TYPOSQUATTING = "typosquatting"
    TIME_BOMB = "time_bomb"
    ENV_MANIPULATION = "env_manipulation"
    NETWORK_ACCESS = "network_access"
    FILE_ACCESS = "file_access"
    CODE_OBFUSCATION = "code_obfuscation"
    SUSPICIOUS_IMPORT = "suspicious_import"
    HARDCODED_SECRET = "hardcoded_secret"
    EVAL_EXEC = "eval_exec"
    MALICIOUS_PATTERN = "malicious_pattern"
    CONFIG_ISSUE = "config_issue"
    OTHER = "other"


# ─── Core Finding Model ──────────────────────────────────────────

@dataclass
class Finding:
    """
    Unified security finding model.
    
    Combines fields from both legacy models.py and models_v2.py.
    All new code should use this model.
    """
    # Core identification
    title: str
    description: str
    severity: Severity
    category: ThreatCategory = ThreatCategory.OTHER
    
    # Location
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    # Evidence & context
    snippet: Optional[str] = None          # v6.0: Code snippet (was in models_v2)
    evidence: str = ""                      # Legacy: Raw evidence text
    matched_text: str = ""                  # Legacy: Matched pattern text
    cwe_id: str = ""                        # Legacy: CWE identifier
    
    # Remediation
    remediation: Optional[str] = None
    
    # Metadata
    rule_id: str = ""
    analyzer: Optional[str] = None          # v6.0: Which analyzer found this
    confidence: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # v6.0: Unique ID (auto-generated if not provided)
    id: Optional[str] = None
    
    def __post_init__(self):
        """Generate ID if not provided."""
        if self.id is None and self.rule_id and self.file_path:
            self.id = f"{self.rule_id}:{self.file_path}:{self.line_number}"
        elif self.id is None:
            self.id = f"finding_{id(self)}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'category': self.category.value if isinstance(self.category, ThreatCategory) else self.category,
            'severity': self.severity.value if isinstance(self.severity, Severity) else self.severity,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'snippet': self.snippet,
            'remediation': self.remediation,
            'analyzer': self.analyzer,
            'confidence': self.confidence,
            'metadata': self.metadata,
            # Legacy fields for backward compatibility
            'evidence': self.evidence,
            'matched_text': self.matched_text,
            'cwe_id': self.cwe_id,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create Finding from dictionary."""
        # Handle severity conversion
        severity = data.get('severity', 'INFO')
        if isinstance(severity, str):
            try:
                severity = Severity(severity)
            except ValueError:
                severity = Severity.INFO
        
        # Handle category conversion
        category = data.get('category', 'other')
        if isinstance(category, str):
            try:
                category = ThreatCategory(category)
            except ValueError:
                category = ThreatCategory.OTHER
        
        return cls(
            id=data.get('id'),
            rule_id=data.get('rule_id', ''),
            category=category,
            severity=severity,
            title=data.get('title', ''),
            description=data.get('description', ''),
            file_path=data.get('file_path'),
            line_number=data.get('line_number'),
            snippet=data.get('snippet'),
            remediation=data.get('remediation'),
            analyzer=data.get('analyzer'),
            confidence=data.get('confidence', 0.8),
            metadata=data.get('metadata', {}),
            evidence=data.get('evidence', ''),
            matched_text=data.get('matched_text', ''),
            cwe_id=data.get('cwe_id', ''),
        )


# ─── Skill File Model ────────────────────────────────────────────

@dataclass
class SkillFile:
    """Represents a file within a skill."""
    path: str
    size: int
    content_hash: str = ""
    language: str = ""
    is_hidden: bool = False
    
    def read_content(self, encoding: str = 'utf-8') -> str:
        """Read file content."""
        from pathlib import Path
        return Path(self.path).read_text(encoding=encoding, errors='ignore')
    
    def is_safe(self) -> bool:
        """Check if file type is generally safe."""
        safe_extensions = {'.md', '.txt', '.json', '.yaml', '.yml', '.toml'}
        ext = Path(self.path).suffix.lower() if '.' in self.path else ''
        return ext in safe_extensions


# ─── Scan Result Model ───────────────────────────────────────────

@dataclass
class ScanResult:
    """Complete scan result."""
    skill_name: str
    risk_score: int
    risk_level: str
    verdict: str
    findings: List[Finding] = field(default_factory=list)
    scan_time: str = ""
    total_files: int = 0
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Filter findings by severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_category(self, category: ThreatCategory) -> List[Finding]:
        """Filter findings by category."""
        return [f for f in self.findings if f.category == category]
    
    def max_severity(self) -> Optional[Severity]:
        """Return highest severity found."""
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: Severity.rank(f.severity)).severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'skill_name': self.skill_name,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'verdict': self.verdict,
            'findings': [f.to_dict() for f in self.findings],
            'scan_time': self.scan_time,
            'total_files': self.total_files,
        }


# ─── Module-level helper functions ───────────────────────────────

def max_severity(findings: List[Finding]) -> Optional[Severity]:
    """Get maximum severity from a list of findings."""
    if not findings:
        return None
    return max(findings, key=lambda f: Severity.rank(f.severity)).severity


def get_findings_by_severity(findings: List[Finding], severity: Severity) -> List[Finding]:
    """Filter findings by severity."""
    return [f for f in findings if f.severity == severity]


def get_findings_by_category(findings: List[Finding], category: ThreatCategory) -> List[Finding]:
    """Filter findings by category."""
    return [f for f in findings if f.category == category]


# ─── Backward compatibility aliases ──────────────────────────────

get = lambda d, k, default=None: d.get(k, default)
to_dict = lambda obj: obj.to_dict() if hasattr(obj, 'to_dict') else obj

__all__ = [
    'Severity',
    'ThreatCategory', 
    'FindingType',  # Legacy
    'Finding',
    'SkillFile',
    'ScanResult',
    'max_severity',
    'get_findings_by_severity',
    'get_findings_by_category',
]
