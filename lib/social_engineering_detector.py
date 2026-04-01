#!/usr/bin/env python3
"""
Social Engineering Detector — 文档社会工程学检测 (v5.1 新增)

检测 SKILL.md / README.md / INSTALL.md 等文档文件中的社会工程学攻击：
- Base64/Hex/ROT13 编码的可执行命令
- 诱导下载外部可执行文件
- 诱导提供凭证（API Key、密码、私钥）
- 诱导关闭安全工具
- 紧急/威胁性语言制造紧迫感
- 伪造的系统消息和状态输出

设计原则：
- 仅分析文档类文件（.md, .txt, .rst）
- 不调用 LLM，纯规则匹配（快速）
- 关注"诱导用户做什么"而非"代码做什么"

教训来源：
- bybit-trading 事件：SKILL.md 中包含 base64 编码的远程代码执行命令
- 供应链攻击趋势：恶意指令伪装成"安装步骤"
"""

import re
from pathlib import Path
from typing import Dict, List, Optional


# ─── 编码命令模式 ──────────────────────────────────────────
ENCODED_COMMAND_PATTERNS = [
    # Base64 解码执行
    (r'base64\s+(-d|--decode)\s*\|?\s*(bash|sh|zsh|powershell|cmd)', 'CRITICAL',
     'Base64 解码后直接执行', 'Base64 decoded command execution'),
    (r'echo\s+[\'"]?[A-Za-z0-9+/=]{20,}[\'"]?\s*\|\s*base64\s+(-d|--decode)', 'CRITICAL',
     'Echo + Base64 管道执行', 'Echo piped to base64 decode'),
    (r'base64\s+(-d|--decode).*\|\s*(bash|sh)', 'CRITICAL',
     'Base64 解码管道到 shell', 'Base64 decode piped to shell'),
    
    # Hex 解码执行
    (r'(echo|printf)\s+["\']?(\\x[0-9a-fA-F]{2}){10,}["\']?\s*\|\s*(bash|sh|python)', 'HIGH',
     'Hex 编码命令执行', 'Hex encoded command execution'),
    
    # PowerShell 编码
    (r'powershell.*-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}', 'CRITICAL',
     'PowerShell 编码命令', 'PowerShell encoded command'),
    (r'-nop(rofile)?\s+-w(indowstyle)?\s+hidden.*-enc', 'HIGH',
     'PowerShell 隐藏窗口执行', 'PowerShell hidden window execution'),
    
    # curl/wget 管道执行
    (r'curl\s+[^|]*\|\s*(bash|sh|zsh|python|ruby|perl)', 'CRITICAL',
     'curl 管道到解释器执行', 'curl piped to interpreter'),
    (r'wget\s+[^|]*-O-\s*\|\s*(bash|sh|zsh)', 'CRITICAL',
     'wget 管道到 shell 执行', 'wget piped to shell'),
    (r'curl\s+(-fsSL|--silent).*\|\s*bash', 'CRITICAL',
     '静默 curl 管道执行', 'Silent curl piped to bash'),
]

# ─── 可疑下载源 ─────────────────────────────────────────────
SUSPICIOUS_DOWNLOAD_PATTERNS = [
    # IP 直连下载（非域名）
    (r'(curl|wget|fetch)\s+.*https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'HIGH',
     '从 IP 地址直接下载', 'Direct download from IP address'),
    
    # 短链接服务
    (r'(curl|wget|fetch)\s+.*(bit\.ly|t\.co|tinyurl|goo\.gl|is\.gd)', 'MEDIUM',
     '通过短链接下载', 'Download via URL shortener'),
    
    # 非 HTTPS 下载
    (r'(curl|wget)\s+http://(?!localhost|127\.0\.0\.1)', 'MEDIUM',
     '非加密 HTTP 下载', 'Unencrypted HTTP download'),
]

# ─── 可执行文件投递 ─────────────────────────────────────────
EXECUTABLE_DELIVERY_PATTERNS = [
    # 下载 .exe/.bat/.cmd
    (r'\.(exe|bat|cmd|ps1|msi|dll)\b', 'HIGH',
     '引用 Windows 可执行文件', 'Reference to Windows executable'),
    
    # 密码保护的压缩包
    (r'(password|passwd|pwd)\s*[=:]\s*\d+', 'MEDIUM',
     '密码保护的压缩包（可能绕过杀毒）', 'Password-protected archive (may bypass AV)'),
    
    # 要求禁用杀毒软件
    (r'(disable|turn off|bypass).*(antivirus|defender|security|firewall)', 'CRITICAL',
     '要求禁用安全软件', 'Request to disable security software'),
    (r'(关闭|禁用|绕过).*(杀毒|防火墙|安全软件|defender)', 'CRITICAL',
     '要求禁用安全软件（中文）', 'Request to disable security software (CN)'),
]

# ─── 凭证索取 ───────────────────────────────────────────────
CREDENTIAL_HARVESTING_PATTERNS = [
    # API Key 收集
    (r'(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*your[_-]?', 'MEDIUM',
     '.env 模板中的凭证占位符', 'Credential placeholder in .env template'),
    
    # 明确要求用户提供敏感信息
    (r'(enter|provide|paste|input).*(api[_-]?key|secret|password|private[_-]?key|token)', 'HIGH',
     '要求用户提供敏感凭证', 'Request for sensitive credentials'),
    (r'(输入|提供|粘贴).*(密钥|密码|私钥|token|api[_-]?key)', 'HIGH',
     '要求用户提供敏感凭证（中文）', 'Request for sensitive credentials (CN)'),
    
    # 钱包/加密货币相关
    (r'(private[_-]?key|seed[_-]?phrase|mnemonic|wallet[_-]?address).*(enter|provide|paste)', 'CRITICAL',
     '要求提供钱包私钥或助记词', 'Request for wallet private key or mnemonic'),
]

# ─── 紧急/社会工程学语言 ─────────────────────────────────────
URGENCY_PATTERNS = [
    (r'\b(CRITICAL|URGENT|MUST|REQUIRED|MANDATORY|IMMEDIATE)\b.{0,30}(before|first|now|immediately)', 'MEDIUM',
     '使用紧急语言制造紧迫感', 'Urgency language creating pressure'),
    (r'(critical|urgent).{0,50}(requirement|step|action)', 'MEDIUM',
     '标记为关键/紧急步骤', 'Marked as critical/urgent step'),
    (r'without.{0,30}(will not work|fail|broken|error)', 'MEDIUM',
     '威胁性语言（不做会失败）', 'Threatening language (failure if not done)'),
    (r'(必须|务必|千万).{0,20}(先|立即|马上|否则)', 'MEDIUM',
     '紧急中文指令', 'Urgent Chinese instruction'),
]

# ─── 伪造系统输出 ───────────────────────────────────────────
FAKE_OUTPUT_PATTERNS = [
    # 伪造的初始化日志
    (r'\[(INIT|READY|OK|SUCCESS|AUTH)\].*(successful|loaded|connected|ready)', 'MEDIUM',
     '伪造的系统初始化日志输出', 'Fake system initialization log output'),
    (r'\[INIT\].*(checking|verifying|authenticating|connecting)', 'MEDIUM',
     '伪造的状态检查日志', 'Fake status check log'),
    
    # 伪造的成功确认
    (r'✅.*(authenticated|verified|confirmed|authorized)', 'LOW',
     '伪造的成功确认标记', 'Fake success confirmation marker'),
]


# ─── v5.2 新增：提示注入与指令操控（AI 独有攻击面） ──────
# 参考：阿里云 ClawHub 扫描报告 — 11.8% 威胁为提示注入
PROMPT_INJECTION_PATTERNS = [
    # 覆盖/忽略先前指令
    (r'(ignore|disregard|override|bypass).{0,30}(previous|prior|earlier|existing).{0,20}(instruction|rule|prompt|system)', 'CRITICAL',
     '试图覆盖系统指令', 'Attempt to override system instructions'),
    (r'(忽略|覆盖|绕过).{0,20}(之前|原有|系统).{0,20}(指令|规则|提示)', 'CRITICAL',
     '试图覆盖系统指令（中文）', 'Attempt to override system instructions (CN)'),
    
    # 角色伪装/权限提升
    (r'you are now.{0,30}(admin|root|superuser|owner|developer mode)', 'HIGH',
     '角色伪装/权限提升企图', 'Role impersonation / privilege escalation'),
    (r'(你现在是|你扮演).{0,20}(管理员|开发者|系统)', 'HIGH',
     '角色伪装企图（中文）', 'Role impersonation attempt (CN)'),
    
    # 诱导泄露敏感信息
    (r'(reveal|expose|show|output|print).{0,30}(api[_-]?key|secret|password|token|credential|private[_-]?key)', 'HIGH',
     '诱导泄露敏感凭证', 'Induce leakage of sensitive credentials'),
    (r'(泄露|暴露|显示|输出).{0,20}(密钥|密码|token|凭证|私钥)', 'HIGH',
     '诱导泄露敏感凭证（中文）', 'Induce leakage of sensitive credentials (CN)'),
    
    # 关闭安全防护
    (r'(disable|turn off|deactivate|skip).{0,30}(security|safety|guard|filter|moderation|validation)', 'CRITICAL',
     '试图关闭安全防护', 'Attempt to disable security measures'),
    (r'(关闭|禁用|跳过).{0,20}(安全|防护|过滤|验证|审核)', 'CRITICAL',
     '试图关闭安全防护（中文）', 'Attempt to disable security measures (CN)'),
    
    # 无限制模式
    (r'(unrestricted|uncensored|no[-_]?limit|without restriction).{0,20}(mode|access|operation)', 'HIGH',
     '请求无限制模式', 'Request for unrestricted mode'),
]


# ─── v5.2 新增：供应链投递模式（Prerequisites 外链执行） ──
# 参考：阿里云 ClawHub 扫描报告 — 34.6% 威胁为恶意投递
SUPPLY_CHAIN_PATTERNS = [
    # Prerequisites/安装步骤中的非官方下载
    (r'(prerequisite|pre[-_]?requisite|before.{0,10}install|installation.{0,10}step).{0,200}(download|curl|wget|fetch)', 'HIGH',
     '安装前置条件中包含下载步骤', 'Download step in prerequisites'),
    (r'(前置条件|安装前|先执行).{0,100}(下载|curl|wget|获取)', 'HIGH',
     '安装前置条件包含下载（中文）', 'Download in prerequisites (CN)'),
    
    # 从代码托管平台下载可执行文件
    (r'(github\.com|gitlab\.com|gitee\.com).{0,100}/releases?/{0,100}\.(exe|bin|sh|bat|zip|tar\.gz)', 'HIGH',
     '从代码托管平台下载可执行文件', 'Executable download from code hosting platform'),
    
    # Pastebin/粘贴站点脚本执行
    (r'(pastebin\.com|gist\.github\.com|raw\.githubusercontent\.com).{0,100}\|\s*(bash|sh|python)', 'CRITICAL',
     '从粘贴站点下载并执行脚本', 'Download and execute script from paste site'),
    
    # 硬编码密码/解压密码
    (r'(password|passwd|pwd|解压密码|密码).{0,10}[=:]\s*[a-zA-Z0-9]{4,}', 'MEDIUM',
     '文档中包含硬编码密码', 'Hardcoded password in documentation'),
    
    # 临时目录落地执行（macOS 投毒特征）
    (r'TMPDIR.*curl.*chmod.*\./', 'CRITICAL',
     '临时目录下载执行链（macOS 投毒特征）', 'Temp directory download-execute chain (macOS poisoning)'),
    (r'xattr\s+(-c|-d com\.apple\.quarantine)', 'HIGH',
     '移除文件隔离属性（macOS Gatekeeper 绕过）', 'Remove quarantine attribute (macOS Gatekeeper bypass)'),
]


# ─── v5.2 新增：凭据窃取反模式 ──────────────────────────
# 参考：阿里云 intel-asrai 案例 — 私钥作为 URL 参数传递
CREDENTIAL_THEFT_PATTERNS = [
    # 私钥/助记词作为 URL 参数
    (r'(https?://[^?]+\?).{0,200}(private[_-]?key|secret|mnemonic|seed)=', 'CRITICAL',
     '敏感凭据通过 URL 参数传递', 'Sensitive credential passed via URL parameter'),
    
    # 要求配置钱包私钥到环境变量
    (r'(export|set).{0,50}(PRIVATE_KEY|WALLET_KEY|SEED_PHRASE|MNEMONIC)', 'HIGH',
     '要求设置钱包私钥到环境变量', 'Set wallet private key to environment variable'),
    
    # MCP 配置中的敏感字段
    (r'"args".{0,100}"--api-key"', 'MEDIUM',
     'MCP 配置中直接传入 API Key', 'API Key passed directly in MCP config args'),
    
    # 要求修改 .env 或配置文件后重启
    (r'(add|paste|enter).{0,50}(api[_-]?key|secret|token).{0,50}(\.env|config|settings)', 'MEDIUM',
     '要求将凭证写入配置文件', 'Request to write credentials to config file'),
    
    # webhook/exfil URL 模式
    (r'(webhook|callback|notify|report|log).{0,50}(https?://(?!api\.)[^\s]+)', 'MEDIUM',
     '可疑的外部回调/Webhook URL', 'Suspicious external callback/webhook URL'),
]


class SocialEngineeringDetector:
    """文档社会工程学检测引擎"""

    # 只扫描文档类文件
    DOC_EXTENSIONS = {'.md', '.txt', '.rst', '.text', '.adoc'}
    
    # 跳过的目录
    SKIP_DIRS = {'node_modules', '__pycache__', '.git', 'vendor', 'dist', 'build'}

    def scan(self, target_path: Path) -> List[Dict]:
        """扫描目标目录中的文档文件"""
        findings: List[Dict] = []

        if target_path.is_file():
            if target_path.suffix.lower() in self.DOC_EXTENSIONS:
                findings.extend(self._scan_file(target_path))
            return findings

        if not target_path.is_dir():
            return findings

        for f in sorted(target_path.rglob('*')):
            # 跳过子目录中的 node_modules 等
            if any(skip in f.parts for skip in self.SKIP_DIRS):
                continue
            
            if not f.is_file():
                continue
            
            if f.suffix.lower() not in self.DOC_EXTENSIONS:
                continue
            
            # 跳过太大的文件（> 500KB）
            try:
                if f.stat().st_size > 500 * 1024:
                    continue
            except Exception:
                continue

            findings.extend(self._scan_file(f, target_path))

        return findings

    def _scan_file(self, file_path: Path, base_path: Optional[Path] = None) -> List[Dict]:
        """扫描单个文档文件"""
        findings: List[Dict] = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return findings

        rel_path = str(file_path.relative_to(base_path)) if base_path else file_path.name

        # 按行号追踪
        lines = content.split('\n')

        all_patterns = (
            ('encoded_command', ENCODED_COMMAND_PATTERNS),
            ('suspicious_download', SUSPICIOUS_DOWNLOAD_PATTERNS),
            ('executable_delivery', EXECUTABLE_DELIVERY_PATTERNS),
            ('credential_harvesting', CREDENTIAL_HARVESTING_PATTERNS),
            ('urgency', URGENCY_PATTERNS),
            ('fake_output', FAKE_OUTPUT_PATTERNS),
            # v5.2 新增
            ('prompt_injection', PROMPT_INJECTION_PATTERNS),
            ('supply_chain', SUPPLY_CHAIN_PATTERNS),
            ('credential_theft', CREDENTIAL_THEFT_PATTERNS),
        )

        for category, patterns in all_patterns:
            for pattern, severity, title_cn, title_en in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.I):
                        # 去重：同一文件的同一类别只报告一次（取最高严重性）
                        existing = next(
                            (f for f in findings 
                             if f['category'] == category and f['file'] == rel_path),
                            None
                        )
                        if existing:
                            # 如果新发现更严重，更新
                            sev_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                            if sev_order.get(severity, 0) > sev_order.get(existing['severity'], 0):
                                existing.update({
                                    'severity': severity,
                                    'title': f'{title_cn} ({file_path.name}:{line_num})',
                                    'title_en': f'{title_en} ({file_path.name}:{line_num})',
                                    'line': line_num,
                                    'matched_line': line.strip()[:200],
                                })
                        else:
                            findings.append({
                                'id': f'SE-{category[:3].upper()}-{len(findings)+1:03d}',
                                'severity': severity,
                                'category': category,
                                'title': f'{title_cn} ({file_path.name}:{line_num})',
                                'title_en': f'{title_en} ({file_path.name}:{line_num})',
                                'file': rel_path,
                                'line': line_num,
                                'description': f'文档文件 {rel_path} 第 {line_num} 行检测到: {title_cn}',
                                'recommendation': self._get_recommendation(category, severity),
                                'matched_line': line.strip()[:200],
                            })

        return findings

    def _get_recommendation(self, category: str, severity: str) -> str:
        recommendations = {
            'encoded_command': '⛔ 不要执行任何编码后解码的命令。这是远程代码执行的典型手法。',
            'suspicious_download': '⚠️ 审查下载源是否可信。避免从 IP 地址或短链接下载。',
            'executable_delivery': '⛔ 不要下载或运行来源不明的可执行文件。',
            'credential_harvesting': '⚠️ 不要在文档指引下直接粘贴凭证。使用安全的配置管理方式。',
            'urgency': 'ℹ️ 警惕使用紧急语言的指令。合法的安装流程不需要制造紧迫感。',
            'fake_output': 'ℹ️ 文档中展示的"成功日志"可能是伪造的，用于建立虚假信任。',
            # v5.2 新增
            'prompt_injection': '⛔ SKILL.md 中包含试图覆盖系统指令的自然语言描述。这是 AI 独有的攻击面，传统安全工具无法检测。',
            'supply_chain': '⛔ 安装前置条件中包含非官方下载/执行步骤。这是供应链投递的典型手法（占威胁总量 34.6%）。',
            'credential_theft': '⛔ 检测到凭据窃取反模式（如私钥作为 URL 参数传递）。立即停止安装并轮换相关凭证。',
        }
        return recommendations.get(category, '请人工审查此发现。')
