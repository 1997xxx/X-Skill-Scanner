#!/usr/bin/env python3
"""
数据模型定义
Finding, Severity, FindingType
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from enum import Enum


class Severity(str, Enum):
    """严重性级别"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingType(str, Enum):
    """发现类型"""
    INDIRECT_EXECUTION = "INDIRECT_EXECUTION"
    ADVANCED_ENCODING = "ADVANCED_ENCODING"
    SUBPROCESS_INJECTION = "SUBPROCESS_INJECTION"
    YAML_UNSAFE_LOAD = "YAML_UNSAFE_LOAD"
    TYPOSQUATTING = "TYPOSQUATTING"
    TIME_BOMB = "TIME_BOMB"
    ENV_MANIPULATION = "ENV_MANIPULATION"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    FILE_ACCESS = "FILE_ACCESS"
    CODE_OBFUSCATION = "CODE_OBFUSCATION"
    SUSPICIOUS_IMPORT = "SUSPICIOUS_IMPORT"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    EVAL_EXEC = "EVAL_EXEC"
    MALICIOUS_PATTERN = "MALICIOUS_PATTERN"
    CONFIG_ISSUE = "CONFIG_ISSUE"
    OTHER = "OTHER"


@dataclass
class Finding:
    """安全发现"""
    title: str
    description: str
    file_path: str
    line_number: int
    severity: Severity
    finding_type: FindingType
    remediation: str = ""
    confidence: float = 0.8
    evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    # 兼容旧版参数
    rule_id: str = ""
    category: str = ""
    matched_text: str = ""
    cwe_id: str = ""
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'severity': self.severity.value if isinstance(self.severity, Severity) else self.severity,
            'finding_type': self.finding_type.value if isinstance(self.finding_type, FindingType) else self.finding_type,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'metadata': self.metadata
        }
    
    def __getitem__(self, key: str) -> Any:
        """支持字典式访问"""
        return self.to_dict().get(key)
    
    def get(self, key: str, default: Any = None) -> Any:
        """安全的字典式访问"""
        return self.to_dict().get(key, default)