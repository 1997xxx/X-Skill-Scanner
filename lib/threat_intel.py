#!/usr/bin/env python3
"""
威胁情报引擎 v3.1 - 基于 ClawHavoc/Snyk ToxicSkills/SkillJect 分析
加载和匹配威胁情报数据，支持技能名称、域名、IP、代码模式匹配
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class ThreatIntelligence:
    """威胁情报匹配引擎"""
    
    def __init__(self, data_path: Optional[str] = None):
        if data_path is None:
            data_path = Path(__file__).parent / 'threat_intel.json'
        self.data_path = Path(data_path)
        self.intel_data = self._load_intel()
    
    def _load_intel(self) -> Dict:
        """加载威胁情报数据"""
        if not self.data_path.exists():
            return self._empty_intel()
        
        with open(self.data_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _empty_intel(self) -> Dict:
        """返回空情报数据结构"""
        return {
            'version': '3.1.0',
            'updated': datetime.now().strftime('%Y-%m-%d'),
            'sources': ['Local Database'],
            'known_malicious_names': [],
            'typosquat_patterns': [],
            'attack_patterns': {},
            'ioc_domains': [],
            'malicious_authors': []
        }
    
    def check_skill_name(self, name: str) -> Tuple[bool, Optional[str], str]:
        """
        检查技能名称是否在已知恶意列表中
        
        Returns:
            (is_malicious, matched_name, risk_category)
        """
        name_lower = name.lower()
        
        # 防御：空名称直接跳过（扫描当前目录时 target.name 为 ''）
        if not name_lower.strip():
            return False, None, ''
        
        # 精确匹配 - 已知恶意技能名
        known_malicious = self.intel_data.get('known_malicious_names', [])
        for malicious_name in known_malicious:
            if malicious_name.lower() == name_lower:
                return True, malicious_name, 'KNOWN_MALICIOUS'
        
        # Typosquat 模糊匹配 - 基于 ClawHavoc/Snyk 报告的模式
        typosquat_patterns = self.intel_data.get('typosquat_patterns', [])
        for pattern in typosquat_patterns:
            pattern_lower = pattern.lower()
            # 前缀匹配或包含匹配
            # 注意：pattern_lower.startswith(name_lower) 在 name_lower 为空时会永远返回 True
            # 所以必须确保 name_lower 非空（已在上面检查）
            if name_lower.startswith(pattern_lower + '-') or \
               name_lower.startswith(pattern_lower) or \
               (len(name_lower) > 0 and pattern_lower.startswith(name_lower)) or \
               name_lower.replace('-', '') == pattern_lower.replace('-', ''):
                return True, pattern, 'TYPOSQUAT'
        
        return False, None, ''
    
    def check_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        检查域名/IP 是否在 IOC 列表中（支持精确域名 + CIDR IP 段匹配）
        
        Returns:
            (is_blacklisted, matched_ioc)
        """
        import ipaddress
        
        domain_lower = domain.lower().strip()
        
        # ── 1. 精确域名/IP 匹配 ────────────────────────
        for ioc in self.intel_data.get('ioc_domains', []):
            if ioc.lower() in domain_lower or domain_lower == ioc.lower():
                return True, ioc
        
        # ── 2. CIDR 网段匹配（Spamhaus DROP / Firehol）──
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_lower):
            try:
                target_ip = ipaddress.ip_address(domain_lower)
                for cidr in self.intel_data.get('cidr_ranges', []):
                    network = ipaddress.ip_network(cidr, strict=False)
                    if target_ip in network:
                        return True, cidr
            except ValueError:
                pass
        
        return False, None
    
    def check_author(self, author: str) -> Tuple[bool, Optional[str]]:
        """
        检查作者是否在已知恶意作者列表中
        
        Returns:
            (is_malicious, matched_author)
        """
        author_lower = author.lower()
        for mal_author in self.intel_data.get('malicious_authors', []):
            if mal_author.lower() == author_lower:
                return True, mal_author
        return False, None
    
    def get_attack_patterns(self) -> Dict:
        """获取所有攻击模式"""
        return self.intel_data.get('attack_patterns', {})
    
    @staticmethod
    def _is_rule_definition_line(line: str) -> bool:
        """判断一行是否处于规则定义上下文中（非实际恶意行为）"""
        stripped = line.strip()
        markers = [
            r'"?pattern"?\s*[:=]', r'"?regex"?\s*[:=]',
            r'"?indicator"?\s*[:=]', r'"?rule"?\s*[:=]',
            r'"name"\s*:', r'"description"\s*:', r'"severity"\s*:',
            r'rules\s*:', r'-\s*cwe\s*:',
            r'THREAT_PATTERNS', r'attack_patterns',
            r'r["\']',           # raw string regex literal
        ]
        return any(re.search(m, stripped, re.IGNORECASE) for m in markers)

    @staticmethod
    def _is_non_executable_context(line: str) -> bool:
        """
        判断一行是否处于非可执行上下文中。
        包括：UI 标签、描述字符串、Markdown 内容等。
        这些上下文中的关键词通常只是说明性文字，不代表实际恶意行为。
        """
        stripped = line.strip()
        
        # 1. 注释行
        if stripped.startswith('#') or stripped.startswith('//'):
            return True
        
        # 2. Markdown 列表项或标题
        if stripped.startswith('- ') or stripped.startswith('* ') or stripped.startswith('#'):
            return True
        
        # 3. Streamlit / Gradio 等 UI 框架的文本参数
        ui_markers = [
            r'st\.(markdown|text|header|subheader|caption)\s*\(',
            r'label\s*=\s*["\']',
            r'desc(?:ription)?\s*=\s*["\']',
            r'help\s*=\s*["\']',
            r'placeholder\s*=\s*["\']',
            r'title\s*=\s*["\']',
        ]
        if any(re.search(m, stripped) for m in ui_markers):
            return True
        
        # 4. 纯字符串字面量（无函数调用/赋值逻辑）
        if (stripped.startswith('"') or stripped.startswith("'")):
            if not any(kw in stripped for kw in ['def ', 'class ', 'import ', 'return ', 'if ', 'for ', 'while ']):
                return True
        
        # 5. Shell 脚本中的配置检查逻辑（非凭证窃取）
        # 例如: auth_config.get('token', '') 或 echo "clientSecret": "app_secret"
        if '.get(' in stripped and any(kw in stripped for kw in ["'token'", "'secret'", "'key'", "'auth'"]):
            return True
        if stripped.startswith('echo ') and any(kw in stripped for kw in ['Secret', 'secret', 'token']):
            return True
        if "'item':" in stripped or "'status':" in stripped or "'action':" in stripped:
            return True
        # 安全审计/合规脚本中的描述文本（如 'risk': '...credentials...'）
        if "'risk':" in stripped or "'fix_cmd':" in stripped or "'required':" in stripped:
            return True
        
        return False

    @staticmethod
    def _is_json_data_file(file_path) -> bool:
        """判断文件是否为 JSON 参考数据文件"""
        fp = Path(file_path) if not isinstance(file_path, Path) else file_path
        if fp.suffix.lower() != '.json':
            return False
        fname_lower = fp.name.lower()
        patterns = ['high-risk-skills', 'malicious', 'known-', 'threat-', 'ioc',
                     'blocklist', 'blacklist', 'whitelist', 'reference', 'database']
        return any(p in fname_lower for p in patterns)

    def check_code_patterns(self, code: str, file_path=None) -> List[Dict]:
        """
        检查代码是否匹配已知攻击模式 — 增强版：排除规则定义/JSON数据/Shell注释
        
        Args:
            code: 源代码内容
            file_path: 文件路径（用于判断是否为 JSON 参考数据或 Shell 脚本）
        
        Returns:
            匹配的攻击模式列表
        """
        # JSON 参考数据文件直接跳过
        if file_path and self._is_json_data_file(file_path):
            return []
        
        matches = []
        patterns = self.get_attack_patterns()
        lines = code.split('\n')
        
        # 判断是否为 Shell 脚本
        is_shell = False
        if file_path:
            fp = Path(file_path) if not isinstance(file_path, Path) else file_path
            is_shell = fp.suffix.lower() in ('.sh', '.bash', '.zsh')
        
        for pattern_id, pattern_info in patterns.items():
            indicators = pattern_info.get('indicators', [])
            severity = pattern_info.get('severity', 'HIGH')
            
            for indicator in indicators:
                try:
                    escaped = re.escape(indicator)
                    found_real_usage = False
                    for line in lines:
                        stripped = line.strip()
                        
                        # 跳过规则定义行
                        if self._is_rule_definition_line(stripped):
                            continue
                        
                        # 跳过非可执行上下文（注释、UI 标签、文档字符串等）
                        if self._is_non_executable_context(stripped):
                            continue
                        
                        # Shell 脚本注释行跳过
                        if is_shell and stripped.startswith('#'):
                            continue
                        
                        if re.search(escaped, line, re.IGNORECASE):
                            found_real_usage = True
                            break
                    
                    if found_real_usage:
                        matches.append({
                            'pattern_id': pattern_id,
                            'description': pattern_info.get('description', ''),
                            'indicator': indicator,
                            'severity': severity
                        })
                        break  # One match per pattern is enough
                except re.error:
                    continue
        
        return matches
    
    def get_statistics(self) -> Dict:
        """获取情报统计信息"""
        stats = self.intel_data.get('statistics', {})
        return {
            'total_known_malicious': len(self.intel_data.get('known_malicious_names', [])),
            'typosquat_variants': len(self.intel_data.get('typosquat_patterns', [])),
            'attack_patterns': len(self.get_attack_patterns()),
            'ioc_domains': len(self.intel_data.get('ioc_domains', [])),
            'malicious_authors': len(self.intel_data.get('malicious_authors', [])),
            **stats
        }
    
    def get_version(self) -> str:
        """获取情报库版本"""
        return self.intel_data.get('version', 'unknown')
    
    def get_updated(self) -> str:
        """获取最后更新时间"""
        return self.intel_data.get('updated', 'unknown')
    
    def get_sources(self) -> List[str]:
        """获取情报来源"""
        return self.intel_data.get('sources', [])