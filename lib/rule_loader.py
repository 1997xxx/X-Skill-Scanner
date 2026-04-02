#!/usr/bin/env python3
"""
YAML 签名规则加载器 — 参考 CoPaw 的 RuleLoader 设计
从 YAML 文件加载安全规则，支持按类别分离、排除模式、文件类型过滤
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    from .models_v2 import Finding, Severity, SkillFile, ThreatCategory
except ImportError:
    from models_v2 import Finding, Severity, SkillFile, ThreatCategory

logger = logging.getLogger(__name__)

# 默认签名目录
_DEFAULT_SIGNATURES_DIR = Path(__file__).resolve().parent.parent / "rules" / "signatures"


class SecurityRule:
    """单条 YAML 安全规则"""
    
    __slots__ = (
        "id", "category", "severity", "patterns", "exclude_patterns",
        "file_types", "description", "remediation",
        "compiled_patterns", "compiled_exclude_patterns",
    )
    
    def __init__(self, rule_data: Dict[str, Any]) -> None:
        self.id: str = rule_data["id"]
        self.category = ThreatCategory(rule_data["category"])
        self.severity = Severity(rule_data["severity"])
        self.patterns: List[str] = rule_data.get("patterns", [])
        self.exclude_patterns: List[str] = rule_data.get("exclude_patterns", [])
        self.file_types: List[str] = rule_data.get("file_types", [])
        self.description: str = rule_data.get("description", "")
        self.remediation: str = rule_data.get("remediation", "")
        
        # 预编译正则
        self.compiled_patterns: List[re.Pattern] = []
        for pat in self.patterns:
            try:
                self.compiled_patterns.append(re.compile(pat))
            except re.error as exc:
                logger.warning("Bad regex in rule %s: %s", self.id, exc)
        
        self.compiled_exclude_patterns: List[re.Pattern] = []
        for pat in self.exclude_patterns:
            try:
                self.compiled_exclude_patterns.append(re.compile(pat))
            except re.error as exc:
                logger.warning("Bad exclude regex in rule %s: %s", self.id, exc)
    
    def matches_file_type(self, file_type: str) -> bool:
        """检查规则是否适用于指定文件类型"""
        if not self.file_types:
            return True  # 无限制则适用于所有类型
        return file_type in self.file_types
    
    def scan_content(
        self,
        content: str,
        file_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """扫描内容匹配规则
        
        Returns:
            匹配项列表，每项包含 line_number, line_content, matched_pattern, matched_text, file_path
        """
        matches: List[Dict[str, Any]] = []
        lines = content.split("\n")
        
        # Pass 1: 逐行匹配（快速）
        for line_num, line in enumerate(lines, start=1):
            excluded = any(
                ep.search(line) for ep in self.compiled_exclude_patterns
            )
            if excluded:
                continue
            for pattern in self.compiled_patterns:
                m = pattern.search(line)
                if m:
                    matches.append({
                        "line_number": line_num,
                        "line_content": line.strip(),
                        "matched_pattern": pattern.pattern,
                        "matched_text": m.group(0),
                        "file_path": file_path,
                    })
        
        return matches


class RuleLoader:
    """从 YAML 文件加载安全规则"""
    
    def __init__(self, rules_path: Optional[Path] = None) -> None:
        self.rules_path = rules_path or _DEFAULT_SIGNATURES_DIR
        self.rules: List[SecurityRule] = []
        self.rules_by_id: Dict[str, SecurityRule] = {}
        self.rules_by_category: Dict[ThreatCategory, List[SecurityRule]] = {}
    
    def load_rules(self) -> List[SecurityRule]:
        """加载并索引所有规则"""
        path = Path(self.rules_path)
        if path.is_dir():
            raw: List[Dict[str, Any]] = []
            for yaml_file in sorted(path.glob("*.yaml")):
                try:
                    with open(yaml_file, encoding="utf-8") as fh:
                        data = yaml.safe_load(fh)
                except Exception as exc:
                    logger.error("Failed to load %s: %s", yaml_file, exc)
                    continue
                if isinstance(data, list):
                    raw.extend(data)
                elif isinstance(data, dict):
                    raw.append(data)
        else:
            try:
                with open(path, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                if isinstance(data, list):
                    raw = data
                elif isinstance(data, dict):
                    raw = [data]
                else:
                    raw = []
            except Exception as exc:
                logger.error("Failed to load %s: %s", path, exc)
                return []
        
        self.rules = []
        self.rules_by_id = {}
        self.rules_by_category = {}
        
        for entry in raw:
            try:
                rule = SecurityRule(entry)
                self.rules.append(rule)
                self.rules_by_id[rule.id] = rule
                self.rules_by_category.setdefault(rule.category, []).append(rule)
            except Exception as exc:
                logger.warning("Skipping rule %s: %s", entry.get("id", "?"), exc)
        
        return self.rules
    
    def get_rule(self, rule_id: str) -> Optional[SecurityRule]:
        return self.rules_by_id.get(rule_id)
    
    def get_rules_for_file_type(self, file_type: str) -> List[SecurityRule]:
        return [r for r in self.rules if r.matches_file_type(file_type)]
