#!/usr/bin/env python3
"""
YAML 签名模式匹配分析器 — 参考 CoPaw PatternAnalyzer 设计
从 YAML 文件加载规则，执行快速逐行正则匹配，支持排除模式和文件类型过滤
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

try:
    from ..models_v2 import Finding, Severity, SkillFile, ThreatCategory
    from ..rule_loader import RuleLoader, SecurityRule
except ImportError:
    from models_v2 import Finding, Severity, SkillFile, ThreatCategory
    from rule_loader import RuleLoader, SecurityRule
from . import BaseAnalyzer

logger = logging.getLogger(__name__)


class PatternAnalyzer(BaseAnalyzer):
    """基于 YAML 签名的模式匹配分析器
    
    Parameters
    ----------
    rules_path : Path, optional
        YAML 规则文件或目录路径。默认为 rules/signatures/ 目录
    """
    
    def __init__(self, rules_path: Optional[Path] = None) -> None:
        super().__init__(name="pattern")
        loader = RuleLoader(rules_path)
        self._rules = loader.load_rules()
        self._rules_by_file_type: dict[str, List[SecurityRule]] = {}
        logger.debug("PatternAnalyzer loaded %d rules", len(self._rules))
    
    def analyze(
        self,
        skill_dir: Path,
        files: List["SkillFile"],
        *,
        skill_name: str | None = None,
    ) -> List["Finding"]:
        """分析技能包中的文件
        
        对每个文件应用适用的规则，生成标准化 Finding 列表
        """
        findings: List[Finding] = []
        
        # 可信企业域名（用于上下文感知降级）
        TRUSTED_DOMAINS = [
            'alibaba-inc.com', 'aliyun.com', 'antgroup.com', 'antgroup-inc.cn',
            'alipay.com', 'taobao.com', 'tmall.com', 'dingtalk.com',
            'localhost', '127.0.0.1',
        ]
        
        for sf in files:
            content = sf.read_content()
            if not content:
                continue
            
            # 【v5.5】上下文感知：检查整个文件是否包含可信域名
            has_trusted_domain = any(domain in content for domain in TRUSTED_DOMAINS)
            
            applicable = self._get_rules(sf.file_type)
            for rule in applicable:
                matches = rule.scan_content(content, file_path=sf.relative_path)
                for match in matches:
                    line_content = match.get('line_content', '')
                    
                    # 【v5.5】精准降级逻辑
                    if has_trusted_domain and rule.id.startswith('EXFIL'):
                        # 策略 A: 匹配行本身包含可信域名 → 安全
                        line_is_trusted = any(domain in line_content for domain in TRUSTED_DOMAINS)
                        
                        # 策略 B: 匹配行不包含域名但使用变量，而文件中有可信域名 + 标准认证模式
                        # e.g., url = SERVER_DOMAIN + "..."; requests.post(url, ...)
                        uses_variable_url = any(kw in line_content for kw in [
                            'requests.post(', 'requests.get(', 'fetch(',
                            'httpx.post(', 'httpx.get(',
                        ])
                        has_auth_pattern = any(kw in content for kw in [
                            'Authorization', 'access_token', 'api_key',
                        ])
                        
                        if line_is_trusted or (uses_variable_url and has_auth_pattern):
                            continue  # 跳过 — 正常的企业 API 集成
                    
                    findings.append(Finding(
                        id=f"{rule.id}:{sf.relative_path}:{match['line_number']}",
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        title=rule.description,
                        description=rule.description,
                        file_path=sf.relative_path,
                        line_number=match["line_number"],
                        snippet=match["line_content"],
                        remediation=rule.remediation,
                        analyzer=self.name,
                        metadata={
                            "matched_pattern": match["matched_pattern"],
                            "matched_text": match["matched_text"],
                        },
                    ))
        
        # 去重
        findings = self._dedupe_findings(findings)
        return findings
    
    def _get_rules(self, file_type: str) -> List[SecurityRule]:
        """获取适用于指定文件类型的规则（缓存）"""
        if file_type not in self._rules_by_file_type:
            self._rules_by_file_type[file_type] = [
                r for r in self._rules if r.matches_file_type(file_type)
            ]
        return self._rules_by_file_type[file_type]
    
    @staticmethod
    def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
        """按 rule_id + file_path + line_number 去重"""
        seen: set[str] = set()
        unique: List[Finding] = []
        for f in findings:
            key = f"{f.rule_id}:{f.file_path}:{f.line_number}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
