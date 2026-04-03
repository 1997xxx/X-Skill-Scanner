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
    
    # ── Trusted Enterprise Domains ───────────────────────────────
    TRUSTED_DOMAINS = [
        'alibaba-inc.com', 'aliyun.com', 'antgroup.com', 'antgroup-inc.cn',
        'alipay.com', 'taobao.com', 'tmall.com', 'dingtalk.com',
        'googleapis.com', 'github.com', 'api.github.com',
        'openai.com', 'api.openai.com', 'anthropic.com',
        'amazonaws.com', 'azure.com', 'microsoft.com',
        'localhost', '127.0.0.1', '0.0.0.0',
    ]

    @classmethod
    def _is_trusted_domain(cls, line: str) -> bool:
        """检查一行中是否包含可信企业域名"""
        line_lower = line.lower()
        return any(domain in line_lower for domain in cls.TRUSTED_DOMAINS)

    @classmethod
    def _is_env_variable_access(cls, line: str) -> bool:
        """检查是否是安全的环境变量读取操作"""
        stripped = line.strip()
        safe_patterns = [
            r'os\.environ\.get\(',      # Python: os.environ.get('TOKEN')
            r'os\.environ\[',             # Python: os.environ['TOKEN']
            r'process\.env\.',            # Node: process.env.TOKEN
            r'getenv\(',                  # C/Python: getenv('TOKEN')
            r'get_env\(',                 # Rust: std::env::var
            r'System\.getenv',            # Java: System.getenv()
            r'ENV\[',                     # Ruby: ENV['TOKEN']
            r'config\.from_env',          # Common config pattern
        ]
        return any(re.search(p, stripped) for p in safe_patterns)

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
            r'class\s+\w+.*Rule',  # Rule class definitions
            r'def\s+test_',       # Test functions
        ]
        return any(re.search(m, stripped, re.IGNORECASE) for m in markers)

    @classmethod
    def _is_non_executable_context(cls, line: str) -> bool:
        """
        判断一行是否处于非可执行上下文中。
        包括：UI 标签、描述字符串、Markdown 内容等。
        这些上下文中的关键词通常只是说明性文字，不代表实际恶意行为。
        """
        stripped = line.strip()
        
        # 0. 【新增】可信企业域名 + 环境变量读取 → 安全上下文
        if cls._is_trusted_domain(stripped) and cls._is_env_variable_access(stripped):
            return True  # e.g., token from env sent to alibaba-inc.com
        
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
        
        # v5.5.2: Markdown 表格单元格（如 "| `$N` | Shorthand ..."）
        if stripped.startswith('| ') and '`' in stripped:
            return True
        
        # v5.5.2: OpenClaw 工具权限声明（如 "allowed-tools: Read, Bash"）
        if re.search(r'allowed-tools|forbidden-tools', stripped):
            return True
        
        # v5.5.2: npm postinstall 脚本（OpenClaw 标准安装机制）
        if 'postinstall' in stripped.lower() and ('npm' in stripped.lower() or 'node_modules' in stripped.lower()):
            return True
        
        # v5.5.2: .env.example 或 .env.sample 中的示例配置（非真实凭证）
        if '.env.example' in stripped or '.env.sample' in stripped:
            return True
        
        # v5.5.2: os.environ.items() — 安全的环境变量遍历（非凭证窃取）
        if 'os.environ.items()' in stripped or 'os.environ.copy()' in stripped:
            return True
        # Safe env filtering: {k: v for k, v in os.environ.items() if ...}
        if re.search(r'os\.environ\.items\(\)', stripped):
            return True
        
        # v5.5.2: 跳过函数定义行 — 函数定义本身不是攻击行为
        if re.match(r'^(async\s+)?function\s+\w+\s*\(', stripped):
            return True
        
        # v5.5.2: Markdown 表格单元格（如 "| `$N` | Shorthand ..."）
        if stripped.startswith('| ') and '`' in stripped:
            return True
        
        # 4. 纯字符串字面量（无函数调用/赋值逻辑）
        if (stripped.startswith('"') or stripped.startswith("'")):
            if not any(kw in stripped for kw in ['def ', 'class ', 'import ', 'return ', 'if ', 'for ', 'while ']):
                return True
        
        # v5.5.2: OpenClaw 工具权限声明（如 "allowed-tools: Read, Bash"）
        if re.search(r'allowed-tools|forbidden-tools', stripped):
            return True
        
        # v5.5.2: npm postinstall 脚本（OpenClaw 标准安装机制）
        if 'postinstall' in stripped.lower() and ('npm' in stripped.lower() or 'node_modules' in stripped.lower()):
            return True
        
        # v5.5.2: .env.example 或 .env.sample 中的示例配置（非真实凭证）
        if '.env.example' in stripped or '.env.sample' in stripped:
            return True
        
        # v5.5.2: os.environ.items() / os.environ.copy() — 安全的环境变量遍历
        if re.search(r'os\.environ\.(items|copy|keys|values)\s*\(', stripped):
            return True
        
        # v5.5.2: 跳过函数定义行 — 函数定义本身不是攻击行为
        if re.match(r'^(async\s+)?function\s+\w+\s*\(', stripped):
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
        
        # 6. 【新增】正常的数据访问模式（dict.get() 用于配置提取）
        # e.g., json.loads(token).get('fbi_app_secret', '')
        if re.search(r'\.get\([\'"]\w+_?(?:secret|token|key|api)[\'"]', stripped):
            # 如果是从已解析的 JSON/dict 中提取字段，不是凭证收集
            if any(ctx in stripped for ctx in ['json.loads', 'json.load', 'yaml.load', 'config[', 'data[']):
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
        检查代码是否匹配已知攻击模式 — v5.3 增强版：
        - 排除规则定义/JSON数据/Shell注释
        - 可信域名 + 环境变量读取 → 自动降级为 INFO
        - 正常 dict.get() 配置提取不标记
        
        Args:
            code: 源代码内容
            file_path: 文件路径（用于判断是否为 JSON 参考数据或 Shell 脚本）
        
        Returns:
            匹配的攻击模式列表
        """
        # JSON 参考数据文件直接跳过
        if file_path and self._is_json_data_file(file_path):
            return []
        
        # v5.2.1: Skip scanner's own documentation files
        # These contain IOC examples and attack descriptions for reference purposes
        self_doc_files = {'changelog.md', 'readme.md', 'readme_ch.md', 'skill.md'}
        if file_path:
            fname_lower = Path(file_path).name.lower()
            if fname_lower in self_doc_files:
                return []
        
        matches = []
        patterns = self.get_attack_patterns()
        lines = code.split('\n')
        
        # 判断是否为 Shell 脚本
        is_shell = False
        if file_path:
            fp = Path(file_path) if not isinstance(file_path, Path) else file_path
            is_shell = fp.suffix.lower() in ('.sh', '.bash', '.zsh')
        
        # 【v5.3】全局可信域检测：如果整个文件中包含可信企业域名，降低误报敏感度
        has_trusted_domain = any(
            self._is_trusted_domain(line) for line in lines
        )
        
        for pattern_id, pattern_info in patterns.items():
            indicators = pattern_info.get('indicators', [])
            severity = pattern_info.get('severity', 'HIGH')
            
            for indicator in indicators:
                try:
                    escaped = re.escape(indicator)
                    found_real_usage = False
                    matched_line = ''
                    matched_stripped = ''
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
                            matched_line = line
                            matched_stripped = stripped
                            break
                    
                    if found_real_usage:
                        # 【v5.3】上下文感知降级
                        effective_severity = severity
                        downgrade_reason = None
                        
                        # 规则 A: 可信域名 + 环境变量读取 → 安全上下文
                        if has_trusted_domain and self._is_env_variable_access(matched_stripped):
                            effective_severity = 'INFO'
                            downgrade_reason = 'trusted_domain_with_env_access'
                        
                        # 规则 B: 单独的可信域名 → 降级外传类检测
                        elif has_trusted_domain and pattern_id in ('config_exfiltration', 'credential_harvesting', 'webhook_exfiltration'):
                            effective_severity = 'INFO'
                            downgrade_reason = 'trusted_domain_context'
                        
                        # 规则 C: 正常的 dict.get() 配置提取
                        elif re.search(r'\.get\([\'"]\w+_?(?:secret|token|key|api|id)[\'"]', matched_stripped):
                            if any(ctx in matched_stripped for ctx in ['json.loads', 'json.load', 'yaml.safe_load', 'config[', 'data[', 'response[']):
                                effective_severity = 'INFO'
                                downgrade_reason = 'safe_config_extraction'
                        
                        # 规则 D: 单独的 `.env` / `token` / `secret` 关键词太宽泛
                        # 仅当没有其他安全上下文时才保留原始严重度
                        elif indicator in ('.env', 'password', 'secret', 'token', 'API_KEY'):
                            # v5.5.2: 跳过 LLM token 计数上下文
                            is_llm_token = False
                            if indicator == 'token':
                                llm_patterns = [
                                    r'\d+\s*[KkMm]?\s*tokens?',     # 100 tokens, ~1K tokens
                                    r'token.*\d+[KkMm+]',              # Token | 52K+
                                    r'\d+[KkMm+].*token',              # 52K+ ... token
                                    r'total_tokens|prompt_tokens|completion_tokens',
                                    r'token_usage|token_count|token_savings|estimated_tokens',
                                    r'_tokens["\s:]',                  # _tokens suffix
                                    r'tokenize',                         # tokenize function
                                    r'Token\s*节[省耗]',                # Chinese: token savings
                                    r'"token"\s*\|',                   # Markdown table header
                                    r'\|\s*Token\b',                  # | Token |
                                    r'max_tokens|budget_tokens|min_tokens|top_tokens',  # LLM API params
                                    r'\btime_seconds,\s*tokens,\s*tool_calls',  # Metric lists
                                    r'\btokens,\s*tool_calls',         # metric listing
                                    r'_tokens"',                         # JSON key suffix

                                ]
                                is_llm_token = any(re.search(p, matched_stripped, re.I) for p in llm_patterns)
                                if is_llm_token:
                                    effective_severity = 'INFO'
                                    downgrade_reason = 'llm_token_count_not_credential'
                            
                            # ⚠️ 如果已经是 INFO (LLM token)，不要再覆盖
                            if not is_llm_token:
                                has_file_read = any(re.search(r'(?:open|readFile|cat|fs\.read)', l) for l in lines)
                                has_net_send = any(re.search(r'(?:requests\.|fetch\(|urllib|httpx|curl|wget)', l) for l in lines)
                                if not (has_file_read and has_net_send):
                                    effective_severity = 'MEDIUM' if severity in ('CRITICAL', 'HIGH') else severity
                                    downgrade_reason = 'broad_indicator_no_attack_chain'
                        
                        match_info = {
                            'pattern_id': pattern_id,
                            'description': pattern_info.get('description', ''),
                            'indicator': indicator,
                            'severity': effective_severity,
                            'original_severity': severity,
                        }
                        if downgrade_reason:
                            match_info['downgrade_reason'] = downgrade_reason
                        
                        matches.append(match_info)
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