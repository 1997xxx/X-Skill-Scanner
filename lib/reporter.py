#!/usr/bin/env python3
"""
报告生成引擎
生成扫描报告（文本/JSON/HTML）
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class ReportGenerator:
    """扫描报告生成器"""
    
    def __init__(self, output_format: str = 'text'):
        self.output_format = output_format
    
    def generate(self, scan_result: Dict, output_path: Optional[str] = None) -> str:
        """
        生成扫描报告
        
        Args:
            scan_result: 扫描结果字典
            output_path: 输出文件路径（None 则返回字符串）
        
        Returns:
            报告内容
        """
        if self.output_format == 'json':
            report = self._generate_json(scan_result)
        elif self.output_format == 'html':
            report = self._generate_html(scan_result)
        else:
            report = self._generate_text(scan_result)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
        
        return report
    
    def _generate_text(self, result: Dict) -> str:
        """生成文本格式报告"""
        lines = [
            "═══════════════════════════════════════════════════════════",
            "           SKILL SECURITY SCAN REPORT",
            "═══════════════════════════════════════════════════════════",
            f"Skill: {result.get('target', 'Unknown')}",
            f"Scan Date: {result.get('scan_time', datetime.now().isoformat())}",
            f"Files Reviewed: {result.get('total_files', 0)}",
            "───────────────────────────────────────────────────────────",
            f"RISK LEVEL: {result.get('risk_level', 'UNKNOWN')}",
            f"RISK SCORE: {result.get('risk_score', 0)}/100",
            f"VERDICT: {result.get('verdict', 'UNKNOWN')}",
            "───────────────────────────────────────────────────────────",
            "FINDINGS BY SEVERITY:"
        ]
        
        for severity, count in result.get('findings_by_severity', {}).items():
            lines.append(f"  • {severity}: {count}")
        
        lines.append("───────────────────────────────────────────────────────────")
        lines.append("FINDINGS BY CATEGORY:")
        
        for category, count in result.get('findings_by_category', {}).items():
            lines.append(f"  • {category}: {count}")
        
        if result.get('findings'):
            lines.append("───────────────────────────────────────────────────────────")
            lines.append("DETAILED FINDINGS:")
            
            for i, finding in enumerate(result['findings'][:10], 1):
                if hasattr(finding, 'severity'):
                    lines.append(f"\n{i}. [{finding.severity}] {finding.title}")
                    lines.append(f"   File: {finding.file_path}:{finding.line_number}")
                    lines.append(f"   Description: {finding.description}")
                    lines.append(f"   Remediation: {finding.remediation}")
                else:
                    lines.append(f"\n{i}. [{finding.get('severity', 'UNKNOWN')}] {finding.get('title', 'Unknown')}")
                    lines.append(f"   File: {finding.get('file_path', 'Unknown')}:{finding.get('line_number', 0)}")
                    lines.append(f"   Description: {finding.get('description', 'N/A')}")
                    lines.append(f"   Remediation: {finding.get('remediation', 'N/A')}")
        
        lines.append("\n───────────────────────────────────────────────────────────")
        lines.append(f"SUMMARY: {result.get('summary', 'No summary available')}")
        lines.append("═══════════════════════════════════════════════════════════")
        
        return '\n'.join(lines)
    
    def _generate_json(self, result: Dict) -> str:
        """生成 JSON 格式报告"""
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    def _generate_html(self, result: Dict) -> str:
        """生成 HTML 格式报告"""
        risk_level = result.get('risk_level', 'UNKNOWN')
        risk_class = risk_level.lower()
        
        findings_rows = ''
        for finding in result.get('findings', [])[:10]:
            findings_rows += f'''
            <tr>
                <td><span class="severity-{finding.get('severity', 'LOW').lower()}">{finding.get('severity', 'UNKNOWN')}</span></td>
                <td>{finding.get('title', 'Unknown')}</td>
                <td>{finding.get('file_path', 'N/A')}:{finding.get('line_number', 0)}</td>
                <td>{finding.get('remediation', 'N/A')}</td>
            </tr>
            '''
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Skill Security Report - {result.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .risk-badge {{ display: inline-block; padding: 8px 16px; border-radius: 4px; font-weight: bold; font-size: 18px; }}
        .risk-low {{ background: #28a745; color: white; }}
        .risk-medium {{ background: #ffc107; color: black; }}
        .risk-high {{ background: #fd7e14; color: white; }}
        .risk-extreme {{ background: #dc3545; color: white; }}
        .verdict {{ font-size: 24px; font-weight: bold; margin: 20px 0; padding: 15px; border-radius: 4px; }}
        .verdict-safe {{ background: #d4edda; color: #155724; }}
        .verdict-caution {{ background: #fff3cd; color: #856404; }}
        .verdict-danger {{ background: #f8d7da; color: #721c24; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 4px; text-align: center; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
        .stat-label {{ font-size: 12px; color: #666; margin-top: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Skill Security Scan Report</h1>
        
        <p><strong>Target:</strong> {result.get('target', 'Unknown')}</p>
        <p><strong>Scan Time:</strong> {result.get('scan_time', datetime.now().isoformat())}</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{result.get('total_files', 0)}</div>
                <div class="stat-label">Files Reviewed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{result.get('total_findings', 0)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{result.get('risk_score', 0)}</div>
                <div class="stat-label">Risk Score</div>
            </div>
        </div>
        
        <div class="risk-badge risk-{risk_class}">{risk_level}</div>
        
        <div class="verdict verdict-{self._get_verdict_class(result.get('verdict', ''))}">
            {result.get('verdict', 'UNKNOWN')}
        </div>
        
        <h2>Findings by Severity</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            {self._generate_severity_rows(result.get('findings_by_severity', {}))}
        </table>
        
        <h2>Detailed Findings</h2>
        <table>
            <tr><th>Severity</th><th>Issue</th><th>Location</th><th>Remediation</th></tr>
            {findings_rows}
        </table>
        
        <h2>Summary</h2>
        <p>{result.get('summary', 'No summary available')}</p>
    </div>
</body>
</html>'''
        
        return html
    
    def _get_verdict_class(self, verdict: str) -> str:
        """获取裁决对应的 CSS 类"""
        verdict_lower = verdict.lower()
        if 'safe' in verdict_lower:
            return 'safe'
        elif 'caution' in verdict_lower:
            return 'caution'
        else:
            return 'danger'
    
    def _generate_severity_rows(self, severity_dict: Dict) -> str:
        """生成严重性统计行"""
        rows = ''
        for severity, count in severity_dict.items():
            rows += f'<tr><td>{severity}</td><td>{count}</td></tr>'
        return rows
