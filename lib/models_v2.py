#!/usr/bin/env python3
"""
增强版数据模型 — v5.5 参考 CoPaw 设计
向后兼容旧版 models.py，新代码优先使用此模块
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


# ─── Enums ──────────────────────────────────────────────────────

class Severity(str, Enum):
    """严重性级别"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    SAFE = "SAFE"


class ThreatCategory(str, Enum):
    """威胁分类 — 扩展自 CoPaw taxonomy"""
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    OBFUSCATION = "obfuscation"
    HARDCODED_SECRETS = "hardcoded_secrets"
    SOCIAL_ENGINEERING = "social_engineering"
    RESOURCE_ABUSE = "resource_abuse"
    POLICY_VIOLATION = "policy_violation"
    MALWARE = "malware"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    CREDENTIAL_THEFT = "credential_theft"
    PATH_TRAVERSAL = "path_traversal"
    DEPENDENCY_RISK = "dependency_risk"
    CONFIG_ISSUE = "config_issue"
    UNICODE_STEGANOGRAPHY = "unicode_steganography"
    TOOL_CHAINING_ABUSE = "tool_chaining_abuse"


# ─── SkillFile ─────────────────────────────────────────────────

_FILE_TYPE_MAP: Dict[str, str] = {
    ".md": "markdown",
    ".markdown": "markdown",
    ".py": "python",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".js": "javascript",
    ".ts": "typescript",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
}


@dataclass
class SkillFile:
    """技能包中的文件"""
    path: Path
    relative_path: str
    file_type: str  # 'markdown', 'python', 'bash', etc.
    content: Optional[str] = None
    size_bytes: int = 0

    def read_content(self) -> str:
        """读取文件内容（如未加载）"""
        if self.content is None and self.path.exists():
            try:
                with open(self.path, encoding="utf-8") as f:
                    self.content = f.read()
            except (OSError, UnicodeDecodeError):
                self.content = ""
        return self.content or ""

    @property
    def is_hidden(self) -> bool:
        """检查是否为隐藏文件或位于隐藏目录中"""
        parts = Path(self.relative_path).parts
        return any(part.startswith(".") and part != "." for part in parts)

    @classmethod
    def from_path(cls, path: Path, base_dir: Path) -> "SkillFile":
        """从路径创建 SkillFile"""
        rel = str(path.relative_to(base_dir))
        suffix = path.suffix.lower()
        file_type = _FILE_TYPE_MAP.get(suffix, "other")
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        return cls(
            path=path,
            relative_path=rel,
            file_type=file_type,
            size_bytes=size,
        )


# ─── Finding ───────────────────────────────────────────────────

@dataclass
class Finding:
    """安全发现"""
    id: str
    rule_id: str
    category: ThreatCategory
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    remediation: Optional[str] = None
    analyzer: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "analyzer": self.analyzer,
            "metadata": self.metadata,
        }


# ─── ScanResult ────────────────────────────────────────────────

@dataclass
class ScanResult:
    """扫描结果聚合"""
    skill_name: str
    skill_directory: str
    findings: List[Finding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    analyzers_used: List[str] = field(default_factory=list)
    analyzers_failed: List[Dict[str, str]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_safe(self) -> bool:
        """无 CRITICAL/HIGH 发现即为安全"""
        return not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )

    @property
    def max_severity(self) -> Severity:
        """最高严重性"""
        if not self.findings:
            return Severity.SAFE
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return Severity.SAFE

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: ThreatCategory) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "skill_name": self.skill_name,
            "skill_path": self.skill_directory,
            "is_safe": self.is_safe,
            "max_severity": self.max_severity.value,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration_seconds": self.scan_duration_seconds,
            "analyzers_used": self.analyzers_used,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.analyzers_failed:
            result["analyzers_failed"] = self.analyzers_failed
        return result


__all__ = ["Severity", "ThreatCategory", "SkillFile", "Finding", "ScanResult"]
