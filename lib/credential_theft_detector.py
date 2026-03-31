#!/usr/bin/env python3
"""
凭证窃取检测引擎 v1.0 — Credential Theft Detection Engine
v3.6 新增：参考 SmartChainArk / 慢雾安全 / 腾讯科恩实验室报告

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
from typing import Dict, List, Optional
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
# Nova Stealer 经典手法：伪造 System Preferences 密码对话框
OSASCRIPT_PASSWORD_DIALOG_PATTERNS = [
    # 直接 osascript 密码弹窗
    (r'osascript\s+-e\s+.*display\s+dialog.*password', 
     'CRITICAL', 'CRED_OSASCRIPT_001',
     'macOS osascript 密码弹窗',
     '检测到使用 osascript 创建密码输入对话框。这是 Nova Stealer 等恶意软件的经典手法，'
     '可伪造与 macOS 系统偏好设置完全相同的密码输入框，诱导用户输入系统密码。'),
    
    # 伪装成系统提示
    (r'osascript\s+-e\s+.*System\s+Preferences.*password',
     'CRITICAL', 'CRED_OSASCRIPT_002',
     '伪装系统偏好设置的密码弹窗',
     '检测到 osascript 弹窗伪装成 "System Preferences" 请求密码。'
     '这是已知的社会工程学攻击手法，用户输入的密码会被发送到攻击者服务器。'),
    
    # hidden answer 属性（隐藏密码输入）
    (r'osascript\s+-e\s+.*with\s+hidden\s+answer',
     'CRITICAL', 'CRED_OSASCRIPT_003',
     '隐藏式密码输入对话框',
     '检测到 osascript 使用 hidden answer 属性创建密码输入框。'
     '该属性使输入内容显示为圆点（•••），是典型的密码收集行为。'),
    
    # AppleScript do shell script with administrator privileges
    (r'do\s+shell\s+script.*administrator\s+privileges',
     'HIGH', 'CRED_OSASCRIPT_004',
     'AppleScript 管理员权限提升',
     '检测到 AppleScript 尝试以管理员权限执行 shell 命令，可能触发系统密码弹窗。'),
]

# ─── SSH/凭证文件路径检测 ────────────────────────────────────────
SENSITIVE_FILE_PATHS = [
    # SSH 密钥
    (r'~\/\.ssh\/id_rsa', 'CRITICAL', 'CRED_SSH_001', 'SSH RSA 私钥路径引用'),
    (r'~\/\.ssh\/id_ed25519', 'CRITICAL', 'CRED_SSH_002', 'SSH Ed25519 私钥路径引用'),
    (r'~\/\.ssh\/id_ecdsa', 'CRITICAL', 'CRED_SSH_003', 'SSH ECDSA 私钥路径引用'),
    (r'~\/\.ssh\/config', 'HIGH', 'CRED_SSH_004', 'SSH 配置文件路径引用'),
    (r'~\/\.ssh\/known_hosts', 'MEDIUM', 'CRED_SSH_005', 'SSH known_hosts 路径引用'),
    (r'\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa)', 'CRITICAL', 'CRED_SSH_006', 'SSH 私钥相对路径引用'),
    
    # Cloud 凭证
    (r'~\/\.aws\/credentials', 'CRITICAL', 'CRED_AWS_001', 'AWS 凭证文件路径引用'),
    (r'~\/\.aws\/config', 'HIGH', 'CRED_AWS_002', 'AWS 配置文件路径引用'),
    (r'~\/\.config\/gcloud', 'CRITICAL', 'CRED_GCP_001', 'GCP 凭证目录引用'),
    (r'~\/\.azure', 'CRITICAL', 'CRED_AZURE_001', 'Azure 凭证目录引用'),
    
    # 通用凭证
    (r'~\/\.(?:bashrc|zshrc|profile|bash_profile)', 'HIGH', 'CRED_SHELL_001', 'Shell 配置文件路径引用'),
    (r'~\/\.netrc', 'CRITICAL', 'CRED_NETRC_001', '.netrc 文件路径引用（含明文密码）'),
    (r'~\/\.git-credentials', 'CRITICAL', 'CRED_GIT_001', 'Git 凭证文件路径引用'),
    (r'~\/\.npmrc', 'HIGH', 'CRED_NPM_001', 'npm 配置文件路径引用（可能含 token）'),
    (r'~\/\.pypirc', 'HIGH', 'CRED_PYP_001', 'PyPI 配置文件路径引用'),
    
    # 加密钱包
    (r'~\/Library\/Application\s+Support\/Google\/Chrome.*Local\s+State', 'CRITICAL', 'CRED_CHROME_001', 'Chrome 浏览器数据路径引用'),
    (r'~\/Library\/Keychains', 'CRITICAL', 'CRED_KEYCHAIN_001', 'macOS Keychain 路径引用'),
    (r'(?:MetaMask|TronLink|Phantom).*wallet', 'CRITICAL', 'CRED_WALLET_001', '加密钱包相关路径引用'),
]

# ─── 浏览器数据窃取检测 ──────────────────────────────────────────
BROWSER_THEFT_PATTERNS = [
    # JavaScript 浏览器 API 数据窃取
    (r'localStorage\.getItem', 'HIGH', 'CRED_BROWSER_001', 'localStorage 数据读取'),
    (r'sessionStorage\.getItem', 'HIGH', 'CRED_BROWSER_002', 'sessionStorage 数据读取'),
    (r'document\.cookie', 'CRITICAL', 'CRED_BROWSER_003', 'Cookie 读取操作'),
    (r'document\.body\.innerText', 'MEDIUM', 'CRED_BROWSER_004', '页面全文内容读取'),
    
    # Chrome 数据库直接读取
    (r'Login\s+Data', 'CRITICAL', 'CRED_BROWSER_005', 'Chrome 登录数据库引用'),
    (r'Web\s+Data.*autofill', 'HIGH', 'CRED_BROWSER_006', 'Chrome 自动填充数据库引用'),
    (r'History.*chrome', 'MEDIUM', 'CRED_BROWSER_007', 'Chrome 历史记录引用'),
    
    # Firefox
    (r'logins\.json', 'CRITICAL', 'CRED_BROWSER_008', 'Firefox 登录数据引用'),
    (r'key4\.db', 'CRITICAL', 'CRED_BROWSER_009', 'Firefox 主密钥数据库引用'),
]

# ─── 凭证外传组合模式 ────────────────────────────────────────────
EXFIL_COMBINATION_PATTERNS = [
    # 读取敏感文件 + POST 外传
    (r'(?:readFile|open|cat)\s*\(?.*(?:\.env|\.ssh|credentials|secret|token|password)',
     'CRITICAL', 'CRED_EXFIL_001',
     '读取敏感凭证文件',
     '检测到代码尝试读取包含敏感信息的文件（.env、SSH 密钥、凭证文件等）。'),
    
    # webhook 外传
    (r'webhook\.site', 'CRITICAL', 'CRED_EXFIL_002',
     'webhook.site 外传端点',
     '检测到使用 webhook.site 作为数据外传端点。这是恶意软件常用的临时接收服务。'),
    
    # Discord webhook 滥用
    (r'discord(?:app)?\.com\/api\/webhooks', 'HIGH', 'CRED_EXFIL_003',
     'Discord Webhook 数据外传',
     '检测到使用 Discord Webhook 作为数据传输通道。可能被用于外传窃取的数据。'),
    
    # Telegram bot 数据外传
    (r'api\.telegram\.org\/bot.*\/sendMessage', 'HIGH', 'CRED_EXFIL_004',
     'Telegram Bot 数据外传',
     '检测到使用 Telegram Bot API 发送消息。可能被用于外传窃取的数据。'),
    
    # ZIP 打包 + 上传
    (r'(?:zip|tar|compress).*(?:upload|post|send|curl|fetch|requests)', 'CRITICAL', 'CRED_EXFIL_005',
     '打包压缩并上传',
     '检测到将文件打包压缩后上传的行为，可能是数据批量外传。'),
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
    """

    def __init__(self):
        self.findings: List[CredentialFinding] = []

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
        """分析单个文件"""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return findings
        
        lines = content.split('\n')
        
        # 1. osascript 密码弹窗检测
        findings.extend(self._check_osascript(content, file_path))
        
        # 2. 敏感文件路径检测
        findings.extend(self._check_sensitive_paths(content, file_path))
        
        # 3. 浏览器数据窃取检测
        findings.extend(self._check_browser_theft(content, file_path))
        
        # 4. Keychain 操作检测
        findings.extend(self._check_keychain(content, file_path))
        
        # 5. 凭证外传组合模式
        findings.extend(self._check_exfil_combinations(content, file_path))
        
        self.findings.extend(findings)
        return findings

    def _check_osascript(self, content: str, file_path: Path) -> List[CredentialFinding]:
        """检测 macOS osascript 伪造密码弹窗"""
        findings = []
        lines = content.split('\n')
        
        for pattern, severity, rule_id, title, desc in OSASCRIPT_PASSWORD_DIALOG_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(CredentialFinding(
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        description=(
                            f'{desc}\n\n'
                            f'📋 可疑代码 (第 {line_num} 行):\n'
                            f'```\n{line.strip()[:300]}\n```'
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        category='osascript_password_dialog',
                        confidence=0.95,
                        remediation='立即移除 osascript 密码弹窗代码。合法技能不应请求系统密码。',
                    ))
        
        return findings

    def _check_sensitive_paths(self, content: str, file_path: Path) -> List[CredentialFinding]:
        """检测敏感文件路径引用"""
        findings = []
        lines = content.split('\n')
        
        for pattern, severity, rule_id, title in SENSITIVE_FILE_PATHS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # 检查是否只是文档中的说明（如 README.md 中的安装指南）
                    is_doc_only = file_path.suffix.lower() in ('.md', '.txt')
                    
                    # 即使在文档中，SSH 私钥和钱包路径也值得标记
                    if is_doc_only and severity == 'MEDIUM':
                        continue  # 跳过文档中的低危路径引用
                    
                    findings.append(CredentialFinding(
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        description=(
                            f'检测到对敏感文件路径的引用。\n\n'
                            f'📋 可疑代码 (第 {line_num} 行):\n'
                            f'```\n{line.strip()[:300]}\n```'
                            + ('\n\n⚠️ 注意：此发现在文档文件中，请确认是否为安装说明而非实际代码。' if is_doc_only else '')
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        category='sensitive_file_access',
                        confidence=0.8 if is_doc_only else 0.9,
                        remediation='审查对该敏感文件的访问意图，确认是否为恶意凭证收集。',
                    ))
        
        return findings

    def _check_browser_theft(self, content: str, file_path: Path) -> List[CredentialFinding]:
        """检测浏览器数据窃取行为"""
        findings = []
        lines = content.split('\n')
        
        for pattern, severity, rule_id, title in BROWSER_THEFT_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(CredentialFinding(
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        description=(
                            f'检测到可能的浏览器数据窃取行为。\n\n'
                            f'📋 可疑代码 (第 {line_num} 行):\n'
                            f'```\n{line.strip()[:300]}\n```'
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        category='browser_data_theft',
                        confidence=0.85,
                        remediation='审查浏览器数据访问的真实目的，确认是否为恶意数据收集。',
                    ))
        
        return findings

    def _check_keychain(self, content: str, file_path: Path) -> List[CredentialFinding]:
        """检测 Keychain 操作"""
        findings = []
        lines = content.split('\n')
        
        for pattern, severity, rule_id, title in KEYCHAIN_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(CredentialFinding(
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        description=(
                            f'检测到 macOS Keychain 访问操作。\n\n'
                            f'📋 可疑代码 (第 {line_num} 行):\n'
                            f'```\n{line.strip()[:300]}\n```'
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        category='keychain_access',
                        confidence=0.9,
                        remediation='审查 Keychain 访问的必要性，非系统工具不应访问用户钥匙串。',
                    ))
        
        return findings

    def _check_exfil_combinations(self, content: str, file_path: Path) -> List[CredentialFinding]:
        """检测凭证外传组合模式"""
        findings = []
        lines = content.split('\n')
        
        for pattern, severity, rule_id, title, desc in EXFIL_COMBINATION_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(CredentialFinding(
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        description=(
                            f'{desc}\n\n'
                            f'📋 可疑代码 (第 {line_num} 行):\n'
                            f'```\n{line.strip()[:300]}\n```'
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        category='credential_exfiltration',
                        confidence=0.85,
                        remediation='审查数据外传的目标和内容，确认是否为恶意数据收集。',
                    ))
        
        return findings

    def get_summary(self) -> Dict:
        """获取凭证窃取检测统计摘要"""
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


# 导出
__all__ = ['CredentialTheftDetector', 'CredentialFinding']