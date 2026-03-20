#!/usr/bin/env python3
"""
Ant International Skill Scanner - 主扫描器
整合静态分析、威胁情报、语义审计三层防御
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# 添加 lib 目录到路径
lib_path = Path(__file__).parent
sys.path.insert(0, str(lib_path))

from static_analyzer import StaticAnalyzer
from threat_intel import ThreatIntelligence
from reporter import ReportGenerator


class SkillScanner:
    """技能安全扫描器"""
    
    def __init__(self, enable_semantic: bool = False, enable_threat_intel: bool = True):
        self.static_analyzer = StaticAnalyzer()
        self.threat_intel = ThreatIntelligence() if enable_threat_intel else None
        self.reporter = ReportGenerator()
        self.enable_semantic = enable_semantic
        
        # 语义审计延迟导入（需要 OpenClaw llm-task）
        if enable_semantic:
            try:
                from semantic_auditor import SemanticAuditor
                self.semantic_auditor = SemanticAuditor()
            except ImportError:
                print("⚠️  语义审计模块不可用，将跳过语义分析")
                self.enable_semantic = False
    
    def scan(self, target_path: str) -> Dict:
        """扫描单个目标"""
        target = Path(target_path)
        
        if not target.exists():
            return {
                'error': f'Target not found: {target_path}',
                'risk_level': 'ERROR',
                'verdict': 'SCAN_FAILED'
            }
        
        print(f"🔍 开始扫描：{target}")
        print(f"扫描时间：{datetime.now().isoformat()}")
        print()
        
        # 1. 威胁情报检查（技能名称）
        threat_intel_findings = []
        if self.threat_intel:
            print("📊 步骤 1/3: 威胁情报匹配...")
            is_malicious, matched = self.threat_intel.check_skill_name(target.name)
            if is_malicious:
                threat_intel_findings.append({
                    'rule_id': 'THREAT_001',
                    'severity': 'CRITICAL',
                    'category': 'threat_intel',
                    'title': '恶意技能名称匹配',
                    'description': f'技能名称匹配黑名单：{matched}',
                    'file_path': str(target),
                    'remediation': '禁止安装此技能'
                })
                print(f"   ⛔ 发现恶意技能名称：{matched}")
            else:
                print("   ✅ 威胁情报检查通过")
        
        # 2. 静态分析
        print("\n📊 步骤 2/3: 静态分析...")
        static_findings = []
        
        if target.is_file():
            static_findings = self.static_analyzer.analyze_file(target)
        else:
            static_findings = self.static_analyzer.analyze_directory(target, recursive=True)
        
        print(f"   发现 {len(static_findings)} 个静态分析问题")
        for finding in static_findings[:5]:  # 显示前 5 个
            print(f"   - [{finding.severity}] {finding.title} @ {finding.file_path}:{finding.line_number}")
        if len(static_findings) > 5:
            print(f"   ... 还有 {len(static_findings) - 5} 个")
        
        # 3. 语义审计（可选）
        semantic_findings = []
        if self.enable_semantic and not static_findings:  # 仅当静态分析无问题时进行
            print("\n📊 步骤 3/3: 语义审计...")
            if target.is_file():
                content = target.read_text(encoding='utf-8')
                semantic_findings = self.semantic_auditor.audit_file(target, content)
            else:
                semantic_findings = self.semantic_auditor.audit_directory(target)
            print(f"   发现 {len(semantic_findings)} 个语义分析问题")
        
        # 合并所有发现
        all_findings = threat_intel_findings + static_findings + semantic_findings
        
        # 计算风险等级
        risk_score = self._calculate_risk_score(all_findings)
        risk_level = self._get_risk_level(risk_score)
        verdict = self._get_verdict(risk_level)
        
        # 按严重程度和类别分组
        findings_by_severity = {}
        findings_by_category = {}
        
        for finding in all_findings:
            # 支持 Finding 对象和字典
            if hasattr(finding, 'severity'):
                severity = finding.severity
                category = finding.category
            else:
                severity = finding.get('severity', 'UNKNOWN')
                category = finding.get('category', 'unknown')
            
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
            findings_by_category[category] = findings_by_category.get(category, 0) + 1
        
        # 构建扫描结果
        result = {
            'target': str(target),
            'scan_time': datetime.now().isoformat(),
            'total_files': 1 if target.is_file() else len(list(target.rglob('*'))),
            'total_findings': len(all_findings),
            'findings_by_severity': findings_by_severity,
            'findings_by_category': findings_by_category,
            'findings': all_findings,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'verdict': verdict,
            'summary': self._generate_summary(all_findings, risk_level)
        }
        
        print(f"\n{'='*60}")
        print(f"扫描完成")
        print(f"风险等级：{risk_level}")
        print(f"风险分数：{risk_score}/100")
        print(f"结论：{verdict}")
        print(f"{'='*60}")
        
        return result
    
    def _calculate_risk_score(self, findings: List) -> int:
        """计算风险分数 (0-100)"""
        severity_weights = {
            'CRITICAL': 40,
            'HIGH': 25,
            'MEDIUM': 10,
            'LOW': 5,
            'INFO': 1
        }
        
        score = 0
        for finding in findings:
            # 支持 Finding 对象和字典
            if hasattr(finding, 'severity'):
                severity = finding.severity
            else:
                severity = finding.get('severity', 'LOW')
            score += severity_weights.get(severity, 5)
        
        return min(score, 100)  # 上限 100
    
    def _get_risk_level(self, score: int) -> str:
        """根据分数获取风险等级"""
        if score >= 80:
            return 'EXTREME'
        elif score >= 50:
            return 'HIGH'
        elif score >= 20:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_verdict(self, risk_level: str) -> str:
        """获取安装建议"""
        verdicts = {
            'EXTREME': '❌ DO NOT INSTALL',
            'HIGH': '❌ DO NOT INSTALL',
            'MEDIUM': '⚠️  INSTALL WITH CAUTION',
            'LOW': '✅ SAFE TO INSTALL'
        }
        return verdicts.get(risk_level, '⚠️  REVIEW REQUIRED')
    
    def _generate_summary(self, findings: List, risk_level: str) -> str:
        """生成总结"""
        if not findings:
            return "未发现安全问题，可以安全安装"
        
        critical_count = 0
        high_count = 0
        for f in findings:
            severity = f.severity if hasattr(f, 'severity') else f.get('severity', 'LOW')
            if severity == 'CRITICAL':
                critical_count += 1
            elif severity == 'HIGH':
                high_count += 1
        
        if critical_count > 0:
            return f"发现 {critical_count} 个严重问题，禁止安装"
        elif high_count > 0:
            return f"发现 {high_count} 个高风险问题，需要人工审查"
        else:
            return f"发现 {len(findings)} 个安全问题，建议审查后安装"


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description='Ant International Skill Scanner - AI 技能安全扫描器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python3 scan -t ./my-skill/
  python3 scan -t ./my-skill/ --semantic
  python3 scan -t ./my-skill/ --json -o report.json
  python3 scan -t ~/.openclaw/workspace/skills/ -r
        '''
    )
    
    parser.add_argument('-t', '--target', required=True, help='扫描目标路径')
    parser.add_argument('-s', '--semantic', action='store_true', help='启用语义审计')
    parser.add_argument('-r', '--recursive', action='store_true', help='递归扫描目录')
    parser.add_argument('-j', '--json', action='store_true', help='输出 JSON 格式')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--no-threat-intel', action='store_true', help='跳过威胁情报检查')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    # 创建扫描器
    scanner = SkillScanner(
        enable_semantic=args.semantic,
        enable_threat_intel=not args.no_threat_intel
    )
    
    # 执行扫描
    result = scanner.scan(args.target)
    
    # 输出结果
    if args.json:
        output = json.dumps(result, indent=2, ensure_ascii=False)
    else:
        scanner.reporter.output_format = 'text'
        output = scanner.reporter.generate(result)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"\n报告已保存到：{args.output}")
    else:
        print(output)
    
    # 根据风险等级设置退出码
    if result.get('risk_level') in ['EXTREME', 'HIGH']:
        sys.exit(1)
    elif result.get('risk_level') == 'MEDIUM':
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
