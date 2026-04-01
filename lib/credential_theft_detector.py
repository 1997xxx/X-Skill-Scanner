#!/usr/bin/env python3
"""
凭证窃取检测引擎 v1.1 — Credential Theft Detection Engine
v3.6 新增：参考 SmartChainArk / 慢雾安全 / 腾讯科恩实验室报告
v3.7 优化：规则定义上下文过滤，避免安全工具自扫误报

检测技能试图窃取用户凭证的行为：
- macOS osascript 伪造系统密码弹窗（Nova Stealer 经典手法）
- SSH 私钥读取 (~/.ssh/id_rsa, ~/.ssh/id_ed25519)
- AWS/GCP/Azure 凭证文件访问
- Keychain 访问操作
- 浏览器 Cookie/密码提取
- .env 文件读取 + 外传组合
- 加密货币钱包文件扫描
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CredentialFinding:
    """凭证窃取发现项"""
    rule_id: str
    title: str
    severity: str
    description: str
    file_path: str
    line_number: int
    category: str
    confidence: float = 0.85
    remediation: str = "需要人工审查"


# ─── macOS 伪造密码弹窗检测 ──────────────────────────────────────
OSASCRIPT_PASSWORD_DIALOG_PATTERNS = [
    (r'osascript\s+-e\s+.*display\s+dialog.*password', 
     'CRITICAL', 'CRED_OSASCRIPT_001',
     'macOS osascript 密码弹窗',
     '检测到使用 osascript 创建密码输入对话框。这是 Nova Stealer 等恶意软件的经典手法。'),
    (r'osascript\s+-e\s+.*System\s+Preferences.*password',
     'CRITICAL', 'CRED_OSASCRIPT_002',
     '伪装系统偏好设置的密码弹窗',
     '检测到 osascript 弹窗伪装成 System Preferences 请求密码。'),
    (r'osascript\s+-e\s+.*with\s+hidden\s+answer',
     'CRITICAL', 'CRED_OSASCRIPT_003',
     '隐藏式密码输入对话框',
     '检测到 osascript 使用 hidden answer 属性创建密码输入框。'),
    (r'do\s+shell\s+script.*administrator\s+privileges',
     'HIGH', 'CRED_OSASCRIPT_004',
     'AppleScript 管理员权限提升',
     '检测到 AppleScript 尝试以管理员权限执行 shell 命令。'),
]

# ─── SSH/凭证文件路径检测 ────────────────────────────────────────
SENSITIVE_FILE_PATHS = [
    (r'~\/\.ssh\/id_rsa', 'CRITICAL', 'CRED_SSH_001', 'SSH RSA 私钥路径引用'),
    (r'~\/\.ssh\/id_ed25519', 'CRITICAL', 'CRED_SSH_002', 'SSH Ed25519 私钥路径引用'),
    (r'~\/\.ssh\/id_ecdsa', 'CRITICAL', 'CRED_SSH_003', 'SSH ECDSA 私钥路径引用'),
    (r'~\/\.ssh\/config', 'HIGH', 'CRED_SSH_004', 'SSH 配置文件路径引用'),
    (r'\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa)', 'CRITICAL', 'CRED_SSH_006', 'SSH 私钥相对路径引用'),
    (r'~\/\.aws\/credentials', 'CRITICAL', 'CRED_AWS_001', 'AWS 凭证文件路径引用'),
    (r'~\/\.aws\/config', 'HIGH', 'CRED_AWS_002', 'AWS 配置文件路径引用'),
    (r'~\/\.config\/gcloud', 'CRITICAL', 'CRED_GCP_001', 'GCP 凭证目录引用'),
    (r'~\/\.azure', 'CRITICAL', 'CRED_AZURE_001', 'Azure 凭证目录引用'),
    (r'~\/\.(?:bashrc|zshrc|profile)', 'HIGH', 'CRED_SHELL_001', 'Shell 配置文件路径引用'),
    (r'~\/\.netrc', 'CRITICAL', 'CRED_NETRC_001', '.netrc 文件路径引用'),
    (r'~\/\.git-credentials', 'CRITICAL', 'CRED_GIT_001', 'Git 凭证文件路径引用'),
    (r'~\/\.npmrc', 'HIGH', 'CRED_NPM_001', 'npm 配置文件路径引用'),
    (r'~\/Library\/Keychains', 'CRITICAL', 'CRED_KEYCHAIN_001', 'macOS Keychain 路径引用'),
]

# ─── 浏览器数据窃取检测 ──────────────────────────────────────────
BROWSER_THEFT_PATTERNS = [
    (r'document\.cookie', 'CRITICAL', 'CRED_BROWSER_003', 'Cookie 读取操作'),
    (r'localStorage\.getItem', 'HIGH', 'CRED_BROWSER_001', 'localStorage 数据读取'),
    (r'sessionStorage\.getItem', 'HIGH', 'CRED_BROWSER_002', 'sessionStorage 数据读取'),
    (r'document\.body\.innerText', 'MEDIUM', 'CRED_BROWSER_004', '页面全文内容读取'),
    (r'logins\.json', 'CRITICAL', 'CRED_BROWSER_008', 'Firefox 登录数据引用'),
    (r'key4\.db', 'CRITICAL', 'CRED_BROWSER_009', 'Firefox 主密钥数据库引用'),
]

# ─── 凭证外传组合模式 ────────────────────────────────────────────
EXFIL_COMBINATION_PATTERNS = [
    (r'(?:readFile|open|cat)\s*\(?.*(?:\.env|\.ssh|credentials|secret|token|password)',
     'CRITICAL', 'CRED_EXFIL_001',
     '读取敏感凭证文件',
     '检测到代码尝试读取包含敏感信息的文件。'),
    (r'webhook\.site', 'CRITICAL', 'CRED_EXFIL_002',
     'webhook.site 外传端点',
     '检测到使用 webhook.site 作为数据外传端点。'),
    (r'discord(?:app)?\.com\/api\/webhooks', 'HIGH', 'CRED_EXFIL_003',
     'Discord Webhook 数据外传',
     '检测到使用 Discord Webhook 作为数据传输通道。'),
    (r'api\.telegram\.org\/bot.*\/sendMessage', 'HIGH', 'CRED_EXFIL_004',
     'Telegram Bot 数据外传',
     '检测到使用 Telegram Bot API 发送消息。'),
    (r'(?:zip|tar|compress).*(?:upload|post|send|curl|fetch|requests)', 'CRITICAL', 'CRED_EXFIL_005',
     '打包压缩并上传',
     '检测到将文件打包压缩后上传的行为。'),
]

# ─── Keychain 操作检测 ──────────────────────────────────────────
KEYCHAIN_PATTERNS = [
    (r'security\s+(?:find-generic-password|find-internet-password)', 'CRITICAL', 'CRED_KEYCHAIN_002',
     'macOS Keychain 密码查询'),
    (r'security\s+dump-keychain', 'CRITICAL', 'CRED_KEYCHAIN_003',
     'macOS Keychain 完整导出'),
    (r'SecItemCopyMatching', 'HIGH', 'CRED_KEYCHAIN_004',
     'macOS Security Framework Keychain 查询 API'),
]


class CredentialTheftDetector:
    """
    凭证窃取检测引擎
    
    检测维度:
    1. macOS osascript 伪造密码弹窗（Nova Stealer 手法）
    2. SSH/Cloud/钱包凭证文件路径引用
    3. 浏览器 Cookie/密码/LocalStorage 窃取
    4. Keychain 访问操作
    5. 凭证外传组合模式（读取 + 上传）
    
    v3.7 优化: _is_rule_definition_line() 过滤安全工具中的规则定义字符串
    v5.1 优化: Markdown fenced code block / YAML frontmatter / 教学示例精确过滤
    """

    def __init__(self):
        self.findings: List[CredentialFinding] = []

    @staticmethod
    def _is_rule_definition_line(line: str) -> bool:
        """判断一行是否处于规则定义上下文中（非实际恶意行为）"""
        stripped = line.strip()
        markers = [
            r'"?pattern"?\s*[:=]', r'"?regex"?\s*[:=]',
            r'"?indicator"?\s*[:=]', r'"name"\s*:',
            r'"description"\s*:', r'"severity"\s*:',
            r'rules\s*:', r'THREAT_PATTERNS',
            r'r["\']',
            r'"reason"\s*:',          # JSON reference data (high-risk-skills.json)
            r'"category"\s*:',        # JSON category field
        ]
        return any(re.search(m, stripped, re.IGNORECASE) for m in markers)

    @staticmethod
    def _is_json_data_file(file_path: Path) -> bool:
        """判断文件是否为 JSON 参考数据文件"""
        if file_path.suffix.lower() != '.json':
            return False
        fname_lower = file_path.name.lower()
        patterns = ['high-risk-skills', 'malicious', 'known-', 'threat-', 'ioc',
                     'blocklist', 'blacklist', 'whitelist', 'reference', 'database']
        return any(p in fname_lower for p in patterns)

    @staticmethod
    def _find_md_code_block_ranges(lines: List[str]) -> List[Tuple[int, int]]:
        """扫描 Markdown 文件，找出所有 fenced code block 的行范围（0-based, inclusive）"""
        ranges = []
        in_block = False
        block_start = -1
        fence_pattern = re.compile(r'^(`{3,}|~{3,})')
        
        for i, line in enumerate(lines):
            m = fence_pattern.match(line.strip())
            if m:
                fence_char = m.group(1)[0]
                fence_len = len(m.group(1))
                if not in_block:
                    in_block = True
                    block_start = i
                else:
                    if line.strip().startswith(fence_char * min(fence_len, 3)):
                        ranges.append((block_start, i))
                        in_block = False
                        block_start = -1
        return ranges

    @staticmethod
    def _in_md_code_block(line_idx: int, blocks: List[Tuple[int, int]]) -> bool:
        """精确判断某行是否在 fenced code block 内部"""
        for start, end in blocks:
            if start < line_idx < end:
                return True
        return False

    @staticmethod
    def _is_yaml_frontmatter_range(lines: List[str]) -> Tuple[int, int]:
        """检测 YAML frontmatter 范围"""
        if lines and lines[0].strip() == '---':
            for i in range(1, min(len(lines), 100)):
                if lines[i].strip() == '---':
                    return (0, i)
        return (-1, -1)

    @staticmethod
    def _in_yaml_frontmatter(line_idx: int, fm: Tuple[int, int]) -> bool:
        """判断某行是否在 YAML frontmatter 内部"""
        s, e = fm
        if s >= 0:
            return s <= line_idx <= e
        return False

    @staticmethod
    def _has_teaching_marker_preceding(lines_around: List[str], mid_offset: int) -> bool:
        """检查匹配行之前的行是否有 ❌ BAD / ✅ GOOD 等教学标记"""
        preceding = '\n'.join(lines_around[:mid_offset])
        teaching_markers = [
            r'❌\s*(?:BAD|INSECURE|VULNERABLE|WRONG)',
            r'✅\s*(?:GOOD|SECURE|SAFE|CORRECT|BEST)',
            r'🚫\s*',
            r'//\s*❌',
            r'#\s*❌',
        ]
        return any(re.search(m, preceding, re.IGNORECASE) for m in teaching_markers)

    def analyze_directory(self, dir_path: Path, recursive: bool = True,
                           path_filter=None) -> List[CredentialFinding]:
        """分析目录中所有文件的凭证窃取行为"""
        from path_filter import PathFilter as PF
        pf = path_filter or PF()
        all_findings = []
        extensions = {'.py', '.js', '.ts', '.sh', '.bash', '.zsh', '.md', '.json'}
        files = dir_path.rglob('*') if recursive else dir_path.glob('*')
        for fp in files:
            if not fp.is_file():
                continue
            if fp.suffix.lower() not in extensions:
                continue
            if pf.should_ignore(fp, dir_path):
                continue
            findings = self._analyze_file(fp)
            all_findings.extend(findings)
        return all_findings

    def _analyze_file(self, file_path: Path) -> List[CredentialFinding]:
        """分析单个文件 — 预计算代码块范围，精确过滤误报"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return []
        
        # 优化：JSON 参考数据文件直接跳过
        if self._is_json_data_file(file_path):
            return []
        
        lines = content.split('\n')
        is_md = file_path.suffix.lower() in ('.md', '.txt', '.rst')
        
        # ⭐ 预计算 Markdown 结构信息
        md_code_blocks: List[Tuple[int, int]] = []
        fm_range: Tuple[int, int] = (-1, -1)
        if is_md:
            md_code_blocks = self._find_md_code_block_ranges(lines)
            fm_range = self._is_yaml_frontmatter_range(lines)
        
        fname_lower = file_path.name.lower()
        is_security_tool = any(kw in fname_lower for kw in ['scanner', 'analyzer', 'detector', 'audit', 'security'])
        is_shell_script = file_path.suffix.lower() in ('.sh', '.bash', '.zsh')
        
        findings = []
        findings.extend(self._check_osascript(content, file_path, is_security_tool, is_shell_script,
                                               md_code_blocks, fm_range, lines))
        findings.extend(self._check_sensitive_paths(content, file_path, is_security_tool, is_shell_script,
                                                     md_code_blocks, fm_range, lines))
        findings.extend(self._check_browser_theft(content, file_path, is_security_tool, is_shell_script,
                                                   md_code_blocks, fm_range, lines))
        findings.extend(self._check_keychain(content, file_path, is_security_tool, is_shell_script,
                                              md_code_blocks, fm_range, lines))
        findings.extend(self._check_exfil_combinations(content, file_path, is_security_tool, is_shell_script,
                                                        md_code_blocks, fm_range, lines))
        self.findings.extend(findings)
        return findings

    def _build_cred_description(self, desc: str, line: str, line_num: int, 
                                  context_lines: list = None) -> str:
        """构建结构化的凭证窃取描述"""
        parts = [desc]
        parts.append(f'\n📁 文件位置: 第 {line_num} 行')
        
        # 提取匹配的关键词
        kw_patterns = ['.env', 'password', 'secret', 'token', 'key', 'credential',
                       'ssh', 'private_key', 'api_key', 'access_token']
        matched_kws = [kw for kw in kw_patterns if kw.lower() in line.lower()]
        if matched_kws:
            parts.append(f'🎯 敏感关键词: {", ".join(matched_kws)}')
        
        parts.append(f'\n📋 可疑代码:')
        parts.append(f'  {line.strip()[:200]}')
        
        return '\n'.join(parts)

    def _check_osascript(self, content, file_path, is_sec, is_shell=False,
                          md_blocks=None, fm=None, full_lines=None):
        findings = []
        md_blocks = md_blocks or []
        fm = fm or (-1, -1)
        is_md = file_path.suffix.lower() in ('.md', '.txt', '.rst')
        for pattern, severity, rule_id, title, desc in OSASCRIPT_PASSWORD_DIALOG_PATTERNS:
            for line_num, line in enumerate(content.split('\n'), 1):
                idx = line_num - 1
                # ⭐ Markdown code block 过滤
                if is_md and self._in_md_code_block(idx, md_blocks):
                    continue
                # ⭐ YAML frontmatter 过滤
                if is_md and self._in_yaml_frontmatter(idx, fm):
                    continue
                if is_sec and self._is_rule_definition_line(line):
                    continue
                if is_shell and line.strip().startswith('#'):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    desc_text = (f'{desc}'
                                 f'\n\n⚠️  潜在影响: 通过伪造系统对话框诱导用户输入 macOS 登录密码，'
                                 f'攻击者可获取系统级访问权限。'
                                 f'\n\n📋 可疑代码 (第 {line_num} 行):'
                                 f'\n  {line.strip()[:200]}')
                    findings.append(CredentialFinding(
                        rule_id=rule_id, title=title, severity=severity,
                        description=desc_text,
                        file_path=str(file_path), line_number=line_num,
                        category='osascript_password_dialog', confidence=0.95,
                        remediation='立即移除 osascript 密码弹窗代码。这是 Nova Stealer 等恶意软件使用的钓鱼技术。'))
        return findings

    def _check_sensitive_paths(self, content, file_path, is_sec, is_shell=False,
                                md_blocks=None, fm=None, full_lines=None):
        findings = []
        is_doc = file_path.suffix.lower() in ('.md', '.txt')
        md_blocks = md_blocks or []
        fm = fm or (-1, -1)
        
        # 敏感路径的影响说明映射
        path_impact_map = {
            '.env': '该文件通常包含 API 密钥、数据库密码等敏感凭证，读取后可能被发送到外部服务器。',
            'ssh': 'SSH 私钥是系统身份认证的核心凭证，泄露后可被用于未授权的远程登录。',
            'private_key': '私钥文件一旦泄露，攻击者可冒充用户身份进行加密通信或签名操作。',
            'keychain': 'macOS Keychain 存储了用户的网站密码、WiFi 密码、证书等敏感信息。',
            'password': '密码相关文件或变量可能包含明文或弱加密的用户凭证。',
            'token': 'Token 通常用于 API 认证和会话管理，泄露可导致账户接管。',
            'credential': '凭据文件可能包含用户名/密码对或其他认证信息。',
        }
        
        for pattern, severity, rule_id, title in SENSITIVE_FILE_PATHS:
            for line_num, line in enumerate(content.split('\n'), 1):
                idx = line_num - 1
                # ⭐ Markdown code block 过滤
                if is_doc and self._in_md_code_block(idx, md_blocks):
                    continue
                # ⭐ YAML frontmatter 过滤
                if is_doc and self._in_yaml_frontmatter(idx, fm):
                    continue
                if is_sec and self._is_rule_definition_line(line):
                    continue
                if is_shell and line.strip().startswith('#'):
                    continue
                # Shell 脚本中的 echo/print/token 变量赋值通常是配置说明或检查逻辑
                if is_shell:
                    stripped = line.strip()
                    if stripped.startswith('echo ') or stripped.startswith("echo '") or \
                       stripped.startswith("echo \"") or ".get('" in stripped or \
                       re.match(r'\w+\s*=\s*\w+\.get\(', stripped) or \
                       "'item':" in stripped or "'status':" in stripped or "'action':" in stripped:
                        continue
                if re.search(pattern, line, re.IGNORECASE):
                    if is_doc and severity == 'MEDIUM':
                        continue
                    
                    # 构建影响说明
                    impact = '读取此类文件可能导致敏感信息泄露。'
                    for kw, desc in path_impact_map.items():
                        if kw.lower() in line.lower():
                            impact = desc
                            break
                    
                    desc_text = (f'🔐 检测到对敏感文件路径的引用。'
                                 f'\n\n⚠️  潜在影响: {impact}'
                                 f'\n\n📋 可疑代码 (第 {line_num} 行):'
                                 f'\n  {line.strip()[:200]}')
                    
                    findings.append(CredentialFinding(
                        rule_id=rule_id, title=title, severity=severity,
                        description=desc_text,
                        file_path=str(file_path), line_number=line_num,
                        category='sensitive_file_access',
                        confidence=0.8 if is_doc else 0.9,
                        remediation='审查对该敏感文件的访问意图。确认是否存在将内容外传的行为（如 HTTP POST、文件上传等）。'))
        return findings

    def _check_browser_theft(self, content, file_path, is_sec, is_shell=False,
                              md_blocks=None, fm=None, full_lines=None):
        findings = []
        md_blocks = md_blocks or []
        fm = fm or (-1, -1)
        is_md = file_path.suffix.lower() in ('.md', '.txt', '.rst')
        
        browser_impact_map = {
            'localStorage': 'LocalStorage 存储了用户的会话 Token、偏好设置和敏感数据，可被用于会话劫持。',
            'sessionStorage': 'SessionStorage 包含当前会话的临时数据，泄露可导致中间人攻击。',
            'document.cookie': 'Cookie 通常包含会话标识符和认证信息，窃取后可冒充用户身份。',
            'document.body.innerText': '读取整个页面内容可能捕获用户的个人信息、财务数据等敏感内容。',
            'Login Data': 'Chrome/Edge 浏览器的保存密码数据库，包含用户的所有网站登录凭证。',
            'logins.json': 'Firefox 浏览器的保存密码文件，泄露后可导致所有关联账户被入侵。',
        }
        
        for pattern, severity, rule_id, title in BROWSER_THEFT_PATTERNS:
            for line_num, line in enumerate(content.split('\n'), 1):
                idx = line_num - 1
                if is_md and self._in_md_code_block(idx, md_blocks):
                    continue
                if is_md and self._in_yaml_frontmatter(idx, fm):
                    continue
                if is_sec and self._is_rule_definition_line(line):
                    continue
                if is_shell and line.strip().startswith('#'):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    # 构建影响说明
                    impact = '浏览器数据存储了用户的敏感信息，未经授权访问可能导致隐私泄露和账户接管。'
                    for kw, desc in browser_impact_map.items():
                        if kw.lower() in line.lower():
                            impact = desc
                            break
                    
                    desc_text = (f'🌐 检测到可能的浏览器数据窃取行为。'
                                 f'\n\n⚠️  潜在影响: {impact}'
                                 f'\n\n📋 可疑代码 (第 {line_num} 行):'
                                 f'\n  {line.strip()[:200]}')
                    
                    findings.append(CredentialFinding(
                        rule_id=rule_id, title=title, severity=severity,
                        description=desc_text,
                        file_path=str(file_path), line_number=line_num,
                        category='browser_data_theft', confidence=0.85,
                        remediation='审查浏览器数据访问的真实目的。除非是明确的浏览器扩展开发，否则不应直接访问浏览器存储。'))
        return findings

    def _check_keychain(self, content, file_path, is_sec, is_shell=False,
                         md_blocks=None, fm=None, full_lines=None):
        findings = []
        md_blocks = md_blocks or []
        fm = fm or (-1, -1)
        is_md = file_path.suffix.lower() in ('.md', '.txt', '.rst')
        for pattern, severity, rule_id, title in KEYCHAIN_PATTERNS:
            for line_num, line in enumerate(content.split('\n'), 1):
                idx = line_num - 1
                if is_md and self._in_md_code_block(idx, md_blocks):
                    continue
                if is_md and self._in_yaml_frontmatter(idx, fm):
                    continue
                if is_sec and self._is_rule_definition_line(line):
                    continue
                if is_shell and line.strip().startswith('#'):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    desc_text = (f'🔑 检测到 macOS Keychain 访问操作。'
                                 f'\n\n⚠️  潜在影响: Keychain 是 macOS 的核心凭证存储系统，'
                                 f'包含 WiFi 密码、网站凭证、证书私钥等敏感信息。'
                                 f'未经授权的访问可能导致系统级凭证泄露。'
                                 f'\n\n📋 可疑代码 (第 {line_num} 行):'
                                 f'\n  {line.strip()[:200]}')
                    findings.append(CredentialFinding(
                        rule_id=rule_id, title=title, severity=severity,
                        description=desc_text,
                        file_path=str(file_path), line_number=line_num,
                        category='keychain_access', confidence=0.9,
                        remediation='审查 Keychain 访问的必要性。合法的 Keychain 操作应有明确的用户授权和合理的业务需求。'))
        return findings

    def _check_exfil_combinations(self, content, file_path, is_sec, is_shell=False,
                                   md_blocks=None, fm=None, full_lines=None):
        findings = []
        md_blocks = md_blocks or []
        fm = fm or (-1, -1)
        is_md = file_path.suffix.lower() in ('.md', '.txt', '.rst')
        for pattern, severity, rule_id, title, desc in EXFIL_COMBINATION_PATTERNS:
            for line_num, line in enumerate(content.split('\n'), 1):
                idx = line_num - 1
                # ⭐ Markdown code block 过滤
                if is_md and self._in_md_code_block(idx, md_blocks):
                    continue
                # ⭐ YAML frontmatter 过滤
                if is_md and self._in_yaml_frontmatter(idx, fm):
                    continue
                if is_sec and self._is_rule_definition_line(line):
                    continue
                if is_shell and line.strip().startswith('#'):
                    continue
                # Shell 脚本中嵌入的 Python 配置检查代码（如 auth_config.get('token')）
                # 不是凭证窃取，而是安全合规检查
                if is_shell:
                    stripped = line.strip()
                    if ".get('" in stripped and any(kw in stripped for kw in ['token', 'secret', 'key', 'auth']):
                        # 类似 auth_config.get('token', '') — 读取配置值做验证
                        continue
                    if "'item':" in stripped or "'status':" in stripped or "'action':" in stripped:
                        # 报告生成代码中的描述文本
                        continue
                    # 审计脚本中的 find ... | wc -l 是计数而非窃取
                    if 'find ' in stripped and '| wc -' in stripped:
                        continue
                    # 审计脚本中的目录存在性检查 [ -d ~/.ssh ]
                    if re.match(r'\[\s*-d\s+', stripped) or re.match(r'\[\s*-f\s+', stripped):
                        continue
                    # 安全审计报告生成代码（Python dict 嵌入在 heredoc 中）
                    if "'risk':" in stripped or "'fix_cmd':" in stripped or "'required':" in stripped:
                        continue
                    # Shell 脚本中的 echo/print/token 变量赋值通常是配置说明或检查逻辑
                    if stripped.startswith('echo ') or stripped.startswith("echo '") or \
                       stripped.startswith("echo \"") or ".get('" in stripped or \
                       re.match(r'\w+\s*=\s*\w+\.get\(', stripped) or \
                       "'item':" in stripped or "'status':" in stripped or "'action':" in stripped:
                        continue
                if re.search(pattern, line, re.IGNORECASE):
                    # 额外过滤：跳过枚举/常量定义行（如 DetectionCategory.CREDENTIALS）
                    stripped = line.strip()
                    if re.match(r'(?:category|type|kind|level)\s*[=:]\s*\w+\.', stripped, re.IGNORECASE):
                        continue
                    if re.match(r'(?:class|def|const|let|var)\s+\w*cred', stripped, re.IGNORECASE):
                        continue
                    
                    # 构建影响说明
                    exfil_impact_map = {
                        'CRED_EXFIL_001': '直接读取包含敏感凭证的文件（.env、SSH 私钥、配置文件等），获取的内容可能被发送到外部服务器。',
                        'CRED_EXFIL_002': 'webhook.site 是公开的数据接收端点，常用于快速测试数据外泄。生产代码中使用此端点高度可疑。',
                        'CRED_EXFIL_003': 'Discord Webhook 通常被攻击者用于将窃取的数据发送到自有 Discord 频道，绕过传统安全检测。',
                        'CRED_EXFIL_004': '通过 Telegram Bot API 发送消息可将窃取的数据推送到攻击者控制的 Telegram 群组或频道。',
                        'CRED_EXFIL_005': '将文件打包压缩后上传是典型的大规模数据外泄手法，可能窃取整个目录的敏感文件。',
                    }
                    impact = exfil_impact_map.get(rule_id, '检测到可能的数据外传行为，需要进一步审查确认意图。')
                    
                    desc_text = (f'📤 检测到凭证外传风险模式。'
                                 f'\n\n⚠️  潜在影响: {impact}'
                                 f'\n\n📋 可疑代码 (第 {line_num} 行):'
                                 f'\n  {stripped[:200]}')
                    
                    findings.append(CredentialFinding(
                        rule_id=rule_id, title=title, severity=severity,
                        description=desc_text,
                        file_path=str(file_path), line_number=line_num,
                        category='credential_exfiltration', confidence=0.85,
                        remediation='审查数据外传的目标和内容。除非有明确的业务需求且经过安全审计，否则不应将敏感数据传输到外部端点。'))
        return findings

    def get_summary(self) -> Dict:
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        by_category = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1
        return {
            'total_findings': len(self.findings),
            'by_severity': by_severity,
            'by_category': by_category,
        }


__all__ = ['CredentialTheftDetector', 'CredentialFinding']
