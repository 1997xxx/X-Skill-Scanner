#!/usr/bin/env python3
"""
网络行为画像引擎 v1.0 — Network Behavior Profiling Engine
v3.3 新增：参考 Astrix Security / AegisScan 的网络行为分析能力

通过静态分析构建技能的网络行为画像：
- 外连域名/IP 提取与分类
- API 调用模式分析
- 数据传输方向判断 (上传 vs 下载)
- 隐蔽信道检测 (DNS tunneling, ICMP covert)
- C2 通信特征识别
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class NetworkEndpoint:
    """网络端点信息"""
    url: str
    domain: str
    ip_address: Optional[str]
    protocol: str
    port: int
    is_ip_literal: bool
    context: str  # 周围的代码上下文
    line_number: int
    file_path: str


@dataclass
class NetworkProfile:
    """网络行为画像"""
    endpoints: List[NetworkEndpoint] = field(default_factory=list)
    api_calls: Dict[str, int] = field(default_factory=dict)
    upload_patterns: List[str] = field(default_factory=list)
    download_patterns: List[str] = field(default_factory=list)
    suspicious_behaviors: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    verdict: str = "UNKNOWN"


@dataclass
class NetworkFinding:
    """网络行为发现项"""
    rule_id: str
    title: str
    severity: str
    description: str
    file_path: str
    line_number: int
    category: str
    confidence: float = 0.8
    remediation: str = "需要人工审查"


# ─── 已知安全域名白名单 ────────────────────────────────────────
SAFE_DOMAINS = {
    'api.openai.com', 'api.anthropic.com', 'github.com', 'raw.githubusercontent.com',
    'pypi.org', 'files.pythonhosted.org', 'registry.npmjs.org',
    'docs.python.org', 'developer.mozilla.org',
}

# ─── 可疑 TLD ──────────────────────────────────────────────────
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.buzz', '.icu'}

# ─── 网络请求模式 ──────────────────────────────────────────────
NETWORK_PATTERNS = [
    # Python requests
    (r'requests\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'python_requests'),
    (r'requests\.(get|post|put|delete|patch)\s*\(\s*(?:f)?["\']([^"\']*)\{', 'python_requests_fstring'),
    
    # Python urllib
    (r'urllib\.request\.urlopen\s*\(\s*["\']([^"\']+)["\']', 'python_urllib'),
    (r'urllib\.request\.Request\s*\(\s*["\']([^"\']+)["\']', 'python_urllib_request'),
    
    # Python httpx
    (r'httpx\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', 'python_httpx'),
    (r'client\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', 'python_http_client'),
    
    # Shell curl/wget
    (r'curl\s+(?:-\w+\s+)*["\']?([^"\'\s|]+)', 'shell_curl'),
    (r'wget\s+(?:-\w+\s+)*["\']?([^"\'\s|]+)', 'shell_wget'),
    
    # JavaScript fetch
    (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'js_fetch'),
    (r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', 'js_axios'),
    
    # Python socket
    (r'socket\.socket\(\).*connect\s*\(\s*\(\s*["\']([^"\']+)["\']', 'python_socket'),
    (r'socket\.connect\s*\(\s*\(\s*["\']([^"\']+)["\']', 'python_socket_connect'),
    
    # Raw IP addresses in URLs
    (r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'ip_url'),
]

# ─── v5.5.1: 可信域名白名单（企业内部 API）─────────────────
# 这些域名的网络请求不应被标记为数据外传或可疑行为
TRUSTED_DOMAINS = {
    # 阿里巴巴/蚂蚁集团内部
    'alibaba-inc.com', 'alibaba.com', 'antgroup.com', 'antfin.com',
    'ant-global.com', 'antglobal-inc.com', 'mybank.cn',
    # 钉钉
    'oapi.dingtalk.com', 'api.dingtalk.com', 'dingtalk.com',
    'dingtalkapps.com', 'larksuite.com', 'feishu.cn',
    # FBI/ODPS 数据分析平台
    'fbi.alibaba-inc.com', 'odps.alibaba-inc.com',
    # 常见云服务提供商
    'aliyuncs.com', 'alicloudapi.com', 'aliyun.com',
    'amazonaws.com', 'azure.com', 'googleapis.com',
    # OpenClaw/OpenAI 生态
    'openai.com', 'openclaw.ai', 'anthropic.com',
}


def _is_trusted_domain(url_or_domain: str) -> bool:
    """检查 URL 或域名是否在可信白名单中"""
    url_lower = url_or_domain.lower()
    for domain in TRUSTED_DOMAINS:
        if domain in url_lower:
            return True
    return False


# ─── v5.5.1: 可信域名白名单（企业内部 API）─────────────────
# 这些域名的网络请求不应被标记为数据外传或可疑行为
TRUSTED_DOMAINS = {
    # 阿里巴巴/蚂蚁集团内部
    'alibaba-inc.com', 'alibaba.com', 'antgroup.com', 'antfin.com',
    'ant-global.com', 'antglobal-inc.com', 'mybank.cn',
    # 钉钉
    'oapi.dingtalk.com', 'api.dingtalk.com', 'dingtalk.com',
    'dingtalkapps.com', 'larksuite.com', 'feishu.cn',
    # FBI/ODPS 数据分析平台
    'fbi.alibaba-inc.com', 'odps.alibaba-inc.com',
    # 常见云服务提供商
    'aliyuncs.com', 'alicloudapi.com', 'aliyun.com',
    'amazonaws.com', 'azure.com', 'googleapis.com',
    # OpenClaw/OpenAI 生态
    'openai.com', 'openclaw.ai', 'anthropic.com',
}


def _is_trusted_domain(url_or_domain: str) -> bool:
    """检查 URL 或域名是否在可信白名单中"""
    url_lower = url_or_domain.lower()
    for domain in TRUSTED_DOMAINS:
        if domain in url_lower:
            return True
    return False


# ─── v5.5.1: 可信域名白名单（企业内部 API）─────────────────
# 这些域名的网络请求不应被标记为数据外传或可疑行为
TRUSTED_DOMAINS = {
    # 阿里巴巴/蚂蚁集团内部
    'alibaba-inc.com', 'alibaba.com', 'antgroup.com', 'antfin.com',
    'ant-global.com', 'antglobal-inc.com', 'mybank.cn',
    # 钉钉
    'oapi.dingtalk.com', 'api.dingtalk.com', 'dingtalk.com',
    'dingtalkapps.com', 'larksuite.com', 'feishu.cn',
    # FBI/ODPS 数据分析平台
    'fbi.alibaba-inc.com', 'odps.alibaba-inc.com',
    # 常见云服务提供商
    'aliyuncs.com', 'alicloudapi.com', 'aliyun.com',
    'amazonaws.com', 'azure.com', 'googleapis.com',
    # OpenClaw/OpenAI 生态
    'openai.com', 'openclaw.ai', 'anthropic.com',
}


def _is_trusted_domain(url_or_domain: str) -> bool:
    """检查 URL 或域名是否在可信白名单中"""
    url_lower = url_or_domain.lower()
    for domain in TRUSTED_DOMAINS:
        if domain in url_lower:
            return True
    return False


# ─── 数据外传模式 ──────────────────────────────────────────────
EXFILTRATION_PATTERNS = [
    (r'requests\.post.*(?:data|json)\s*=', 'HTTP POST with data payload'),
    (r'curl\s+.*-X\s+POST', 'curl POST request'),
    (r'curl\s+.*-d\s+', 'curl with data'),
    (r'curl\s+.*--data', 'curl with data parameter'),
    (r'urllib.*\.encode\(', 'URL encoded data transmission'),
    (r'base64.*requests', 'Base64 encoded data sent via HTTP'),
    (r'encrypt.*send|encrypt.*post|encrypt.*upload', 'Encrypted data transmission'),
]

# ─── 隐蔽信道模式 ──────────────────────────────────────────────
COVERT_CHANNEL_PATTERNS = [
    (r'subprocess.*nslookup|subprocess.*dig', 'DNS query via subprocess'),
    (r'socket.*sendto.*53', 'Direct DNS port communication'),
    (r'icmp|ping.*-c|ping.*-n', 'ICMP-based communication'),
    (r'timeout\s+\d+\s+ping', 'Timed ping (possible covert channel)'),
]


class NetworkProfiler:
    """
    网络行为画像引擎
    
    分析维度:
    1. 端点提取 - 从代码中提取所有网络端点
    2. 域名信誉 - 检查域名的可信度
    3. 传输方向 - 区分上传和下载操作
    4. 隐蔽信道 - 检测 DNS tunneling、ICMP covert 等
    5. C2 特征 - 识别命令控制通信模式
    """

    def __init__(self):
        self.findings: List[NetworkFinding] = []
        self.profiles: Dict[str, NetworkProfile] = {}

    def analyze_directory(self, dir_path: Path, recursive: bool = True,
                           path_filter=None) -> List[NetworkFinding]:
        """分析目录中所有文件的网络行为"""
        from path_filter import PathFilter as PF
        pf = path_filter or PF()
        all_findings = []
        
        extensions = {'.py', '.js', '.ts', '.sh', '.bash', '.zsh'}
        
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

    def _analyze_file(self, file_path: Path) -> List[NetworkFinding]:
        """分析单个文件的网络行为"""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return findings
        
        lines = content.split('\n')
        
        # ─── 1. 提取所有网络端点 ───────────────────────────────
        endpoints = self._extract_endpoints(content, file_path)
        
        # ─── 2. 分析每个端点 ──────────────────────────────────
        for endpoint in endpoints:
            endpoint_findings = self._analyze_endpoint(endpoint)
            findings.extend(endpoint_findings)
        
        # ─── 3. 检测数据外传模式 ──────────────────────────────
        exfil_findings = self._detect_exfiltration(content, file_path)
        findings.extend(exfil_findings)
        
        # ─── 4. 检测隐蔽信道 ──────────────────────────────────
        covert_findings = self._detect_covert_channels(content, file_path)
        findings.extend(covert_findings)
        
        # ─── 5. 检测 C2 通信特征 ──────────────────────────────
        c2_findings = self._detect_c2_patterns(content, file_path)
        findings.extend(c2_findings)
        
        self.findings.extend(findings)
        return findings

    def _extract_endpoints(self, content: str, file_path: Path) -> List[NetworkEndpoint]:
        """从代码中提取所有网络端点"""
        endpoints = []
        lines = content.split('\n')
        
        for pattern, pattern_type in NETWORK_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                url_or_host = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                
                # 获取上下文
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end]
                
                endpoint = self._parse_endpoint(url_or_host, str(file_path), line_num, context)
                if endpoint:
                    endpoints.append(endpoint)
        
        return endpoints

    def _parse_endpoint(self, url_str: str, file_path: str, 
                         line_num: int, context: str) -> Optional[NetworkEndpoint]:
        """解析 URL 字符串为端点对象"""
        try:
            # 清理 URL
            url_str = url_str.strip().rstrip('"\'')
            
            # 如果是裸 IP，添加协议前缀
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_str):
                url_str = f'http://{url_str}'
            
            parsed = urlparse(url_str)
            
            if not parsed.netloc and not parsed.path:
                return None
            
            domain = parsed.hostname or ''
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
            
            port = parsed.port or (443 if parsed.scheme == 'https' else 80 if parsed.scheme == 'http' else 0)
            
            return NetworkEndpoint(
                url=url_str,
                domain=domain,
                ip_address=domain if is_ip else None,
                protocol=parsed.scheme or 'unknown',
                port=port,
                is_ip_literal=is_ip,
                context=context,
                line_number=line_num,
                file_path=file_path,
            )
        except Exception:
            return None

    def _analyze_endpoint(self, endpoint: NetworkEndpoint) -> List[NetworkFinding]:
        """分析单个端点的风险"""
        findings = []
        
        # ─── IP 直连 ───────────────────────────────────────────
        if endpoint.is_ip_literal:
            findings.append(NetworkFinding(
                rule_id='NET_PROFILE_001',
                title=f'IP 直连: {endpoint.ip_address}',
                severity='MEDIUM',
                description=(
                    f'检测到直接使用 IP 地址进行网络连接: {endpoint.ip_address}\n'
                    f'协议: {endpoint.protocol}, 端口: {endpoint.port}\n\n'
                    f'IP 直连通常用于:\n'
                    f'- 规避 DNS 监控和域名黑名单\n'
                    f'- 快速切换 C2 服务器\n'
                    f'- 隐藏真实的域名基础设施'
                ),
                file_path=endpoint.file_path,
                line_number=endpoint.line_number,
                category='ip_direct_connection',
                confidence=0.8,
                remediation='使用域名而非裸 IP，除非有明确理由',
            ))
        
        # ─── 可疑 TLD ──────────────────────────────────────────
        for tld in SUSPICIOUS_TLDS:
            if endpoint.domain.endswith(tld):
                findings.append(NetworkFinding(
                    rule_id='NET_PROFILE_002',
                    title=f'可疑顶级域名: {endpoint.domain}',
                    severity='MEDIUM',
                    description=f'连接到使用可疑 TLD ({tld}) 的域名: {endpoint.domain}',
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    category='suspicious_tld',
                    confidence=0.7,
                    remediation='验证该域名的合法性',
                ))
                break
        
        # ─── 非标准端口 ────────────────────────────────────────
        if endpoint.port not in (80, 443, 0) and endpoint.protocol in ('http', 'https'):
            findings.append(NetworkFinding(
                rule_id='NET_PROFILE_003',
                title=f'非标准端口: {endpoint.port}',
                severity='LOW',
                description=f'HTTP/S 连接使用了非标准端口: {endpoint.port}',
                file_path=endpoint.file_path,
                line_number=endpoint.line_number,
                category='non_standard_port',
                confidence=0.6,
                remediation='确认非标准端口的使用是否合理',
            ))
        
        return findings

    def _detect_exfiltration(self, content: str, file_path: Path) -> List[NetworkFinding]:
        """检测数据外传模式
        
        v5.5.1 修复：跳过可信域名的请求，避免企业内部 API 误报。
        """
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # ✅ 跳过可信域名的行
            if _is_trusted_domain(line):
                continue
            for pattern, desc in EXFILTRATION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(NetworkFinding(
                        rule_id='NET_EXFIL_001',
                        title=f'疑似数据外传: {desc}',
                        severity='HIGH',
                        description=(
                            f'检测到可能的数据外传模式。\n\n'
                            f'模式: {desc}\n'
                            f'行 {line_num}: `{line.strip()[:200]}`'
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        category='data_exfiltration',
                        confidence=0.75,
                        remediation='审查数据传输的目标和内容',
                    ))
                    break
        
        return findings

    def _detect_covert_channels(self, content: str, file_path: Path) -> List[NetworkFinding]:
        """检测隐蔽信道"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in COVERT_CHANNEL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(NetworkFinding(
                        rule_id='NET_COVERT_001',
                        title=f'疑似隐蔽信道: {desc}',
                        severity='HIGH',
                        description=(
                            f'检测到可能的隐蔽通信信道。\n\n'
                            f'模式: {desc}\n'
                            f'行 {line_num}: `{line.strip()[:200]}`'
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        category='covert_channel',
                        confidence=0.7,
                        remediation='审查该网络操作的真实目的',
                    ))
                    break
        
        return findings

    def _detect_c2_patterns(self, content: str, file_path: Path) -> List[NetworkFinding]:
        """检测 C2 通信特征"""
        findings = []
        
        c2_indicators = [
            (r'(?:beacon|heartbeat|check.in|phone.home)', 'C2 Beacon/Heartbeat'),
            (r'(?:command|cmd|task)\s*=\s*(?:requests|urllib)', 'Remote Command Retrieval'),
            (r'while\s+True.*(?:sleep|time)', 'Persistent Connection Loop'),
            (r'(?:callback|reverse.connect|back.connect)', 'Reverse Connection'),
        ]
        
        # Check single-line patterns first
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in c2_indicators:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(NetworkFinding(
                        rule_id='NET_C2_001',
                        title=f'C2 通信特征: {desc}',
                        severity='CRITICAL',
                        description=(
                            f'检测到命令控制 (C2) 通信特征。\n\n'
                            f'特征: {desc}\n'
                            f'行 {line_num}: `{line.strip()[:200]}`'
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        category='c2_communication',
                        confidence=0.8,
                        remediation='立即阻断并深入调查',
                    ))
                    break
        
        # v3.6: Multi-line C2 detection — while True + sleep pattern across lines
        if not findings:
            multiline_c2 = [
                (r'while\s+True:[\s\S]{0,200}(?:sleep|time\.sleep)', 'Persistent Connection Loop (multi-line)'),
                (r'(?:import\s+time[\s\S]{0,100}|time[\s\S]{0,100}import)[\s\S]{0,200}while\s+True', 'Timed Loop Pattern'),
            ]
            for pattern, desc in multiline_c2:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(NetworkFinding(
                        rule_id='NET_C2_002',
                        title=f'C2 通信特征: {desc}',
                        severity='CRITICAL',
                        description=(
                            f'检测到跨行 C2 通信特征（多行模式）。\n\n'
                            f'特征: {desc}'
                        ),
                        file_path=str(file_path),
                        line_number=1,
                        category='c2_communication',
                        confidence=0.7,
                        remediation='立即阻断并深入调查',
                    ))
                    break
        
        return findings

    def get_summary(self) -> Dict:
        """获取网络行为画像统计摘要"""
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
__all__ = ['NetworkProfiler', 'NetworkEndpoint', 'NetworkProfile', 'NetworkFinding']