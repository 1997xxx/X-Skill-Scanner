#!/usr/bin/env python3
"""
X Skill Scanner v3.7.0 - 主扫描器
十二层防御管线：威胁情报 → 去混淆 → 静态分析 → AST → 依赖检查 → 提示词注入 → 基线比对 → 语义审计 → 熵值分析 → 安装钩子 → 网络行为画像 → 凭证窃取检测

版本演进:
- v3.0: 去混淆 + AST + 基线追踪 + 依赖检查 + SARIF
- v3.1: 提示词注入探针 + 语义审计重构
- v3.2: 威胁情报全面升级 (ClawHavoc/Snyk/SkillJect, 316 恶意技能)
- v3.3: 熵值分析 + 安装钩子检测 + 网络行为画像
- v3.4: MurphySec 报告整合 + 攻击手法分析
- v3.5: 报告格式全面升级 (HTML/MD/Text 统一结构)
- v3.6: 凭证窃取检测 + CJK 自适应熵值 + 零信任白名单 + 误报调优
- v3.7: 误报消除引擎 — 规则定义上下文过滤 + 非可执行上下文识别 + typosquat 空名修复
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional


def _p(*args, **kwargs):
    """进度输出 — 统一走 stderr，不干扰 JSON/SARIF stdout"""
    kwargs.setdefault('file', sys.stderr)
    print(*args, **kwargs)


# 添加 lib 目录到路径
lib_path = Path(__file__).parent
if str(lib_path) not in sys.path:
    sys.path.insert(0, str(lib_path))

project_root = lib_path.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from static_analyzer import StaticAnalyzer
from threat_intel import ThreatIntelligence
from reporter import ReportGenerator
from risk_scorer import RiskScorer
from whitelist import WhitelistManager
from i18n import I18n, set_lang as set_i18n_lang

# v3.0 新引擎
from deobfuscator import Deobfuscator
from ast_analyzer import ASTAnalyzer
from baseline import BaselineTracker
from dependency_checker import DependencyChecker
from path_filter import PathFilter
from prompt_injection_probes import PromptInjectionTester

# v3.3 新增引擎 — 参考 ClawGuard Auditor / SecureClaw / Astrix Security
from entropy_analyzer import EntropyAnalyzer
from install_hook_detector import InstallHookDetector
from network_profiler import NetworkProfiler

# v3.6 新增引擎 — 参考 SmartChainArk / 慢雾安全 / 腾讯科恩实验室报告
from credential_theft_detector import CredentialTheftDetector


class SkillScanner:
    """技能安全扫描器 v3.0 — 七层防御管线"""

    # ─── 统一风险等级阈值 (与 risk_scorer.py 一致) ──────────────
    RISK_THRESHOLDS = {
        'EXTREME': 80,
        'HIGH': 50,
        'MEDIUM': 20,
    }

    def __init__(
        self,
        enable_semantic: bool = True,
        enable_threat_intel: bool = True,
        enable_deobfuscation: bool = True,
        enable_ast_analysis: bool = True,
        enable_baseline: bool = True,
        enable_dep_check: bool = True,
        output_format: str = 'text',
        lang: str = 'zh',
        whitelist_path: Optional[str] = None,
        enable_whitelist: bool = True,
    ):
        self.output_format = output_format
        self.enable_whitelist = enable_whitelist

        default_rules = Path(__file__).parent.parent / 'rules' / 'static_rules.yaml'
        markdown_rules = Path(__file__).parent.parent / 'rules' / 'markdown_rules.yaml'
        rules_file = None

        if default_rules.exists():
            try:
                with open(default_rules, 'r', encoding='utf-8') as f:
                    test_data = __import__('yaml').safe_load(f)
                if test_data:
                    rules_file = str(default_rules)
                    _p(f"✅ 加载主规则文件: {default_rules.name}")
            except Exception as e:
                _p(f"⚠️  主规则文件解析失败: {e}")

        if markdown_rules.exists():
            try:
                with open(markdown_rules, 'r', encoding='utf-8') as f:
                    md_data = __import__('yaml').safe_load(f)
                if md_data and 'markdown_security' in md_data:
                    _p(f"✅ 加载 Markdown 规则: {len(md_data['markdown_security']['rules'])} 条")
            except Exception as e:
                _p(f"⚠️  Markdown 规则文件解析失败: {e}")

        self.static_analyzer = StaticAnalyzer(rules_file=rules_file)
        self.threat_intel = ThreatIntelligence() if enable_threat_intel else None
        self.reporter = ReportGenerator(output_format=output_format)
        self.risk_scorer = RiskScorer()
        self.whitelist = WhitelistManager()
        self.i18n = I18n(lang)

        if enable_whitelist:
            if whitelist_path and os.path.exists(whitelist_path):
                self.whitelist.load_from_file(whitelist_path)
            else:
                default_whitelist = os.path.join(
                    os.path.dirname(__file__), '..', 'config', 'whitelist.json'
                )
                if os.path.exists(default_whitelist):
                    self.whitelist.load_from_file(default_whitelist)

        self.enable_semantic = enable_semantic
        if enable_semantic:
            try:
                from semantic_auditor import SemanticAuditor
                self.semantic_auditor = SemanticAuditor()
            except ImportError:
                _p("⚠️  语义审计模块不可用，将跳过语义分析")
                self.enable_semantic = False

        # v3.0 新引擎初始化
        self.enable_deobfuscation = enable_deobfuscation
        self.deobfuscator = Deobfuscator() if enable_deobfuscation else None

        self.enable_ast_analysis = enable_ast_analysis
        self.ast_analyzer = ASTAnalyzer() if enable_ast_analysis else None

        self.enable_baseline = enable_baseline
        self.baseline_tracker = BaselineTracker() if enable_baseline else None

        self.enable_dep_check = enable_dep_check
        self.dep_checker = DependencyChecker() if enable_dep_check else None

        # 路径过滤器（所有引擎共享）
        self.path_filter = PathFilter()

        # v3.1 新增：提示词注入测试
        self.enable_prompt_injection = True
        self.prompt_injection_tester = PromptInjectionTester()

        # v3.3 新增引擎初始化 — 参考 ClawGuard Auditor / SecureClaw / Astrix Security
        self.enable_entropy_analysis = True
        self.entropy_analyzer = EntropyAnalyzer()

        self.enable_hook_detection = True
        self.hook_detector = InstallHookDetector()

        self.enable_network_profiling = True
        self.network_profiler = NetworkProfiler()

        # v3.6 新增引擎 — 凭证窃取检测（osascript 弹窗、SSH 密钥读取、浏览器数据窃取）
        self.enable_credential_theft_detection = True
        self.credential_theft_detector = CredentialTheftDetector()

    # ─── 辅助方法 ───────────────────────────────────────────────
    def _extract_skill_metadata(self, target: Path) -> Dict:
        """从 SKILL.md 或目录结构提取技能元数据"""
        metadata = {'author': '', 'description': '', 'name': target.name}
        
        try:
            if target.is_file():
                content = target.read_text(encoding='utf-8', errors='ignore')
            else:
                skill_md = target / 'SKILL.md'
                if skill_md.exists():
                    content = skill_md.read_text(encoding='utf-8', errors='ignore')
                else:
                    return metadata
            
            # 提取作者信息（多种格式）
            author_patterns = [
                r'Author:\s*(.+)',
                r'作者[:：]\s*(.+)',
                r'Created by[:：]?\s*(.+)',
                r'By[:：]\s*(.+)',
                r'@(\w+)',
                r'github\.com/([^/]+)/',
            ]
            
            for pattern in author_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    metadata['author'] = match.group(1).strip().rstrip('.')
                    break
            
            # 从路径推断作者 (e.g., skills/zaycv/linkedin-job-application)
            if not metadata['author']:
                path_parts = target.parts
                for i, part in enumerate(path_parts):
                    if part == 'skills' and i + 1 < len(path_parts):
                        potential_author = path_parts[i + 1]
                        if potential_author not in ['main', 'master', 'blob', 'tree']:
                            metadata['author'] = potential_author
                            break
            
            # 提取描述
            desc_match = re.search(r'^>\s*(.+)$', content, re.MULTILINE)
            if desc_match:
                metadata['description'] = desc_match.group(1).strip()
            
        except Exception as e:
            _p(f"   ⚠️  元数据提取失败: {e}")
        
        return metadata
    
    def _detect_campaign_patterns(self, target: Path, files_to_scan: List[Path]) -> List[Dict]:
        """检测已知攻击活动模式 (ClawHavoc/Snyk/ToxicSkills)"""
        findings = []
        
        # ClawHavoc 活动特征：随机后缀命名模式
        random_suffix_pattern = re.compile(r'^[a-z0-9]+-[a-f0-9]{5}$')
        if random_suffix_pattern.match(target.name.lower()):
            findings.append({
                'rule_id': 'CAMPAIGN_CLAWHAVOC_001',
                'severity': 'HIGH',
                'category': 'threat_intel',
                'title': '疑似 ClawHavoc 活动命名模式',
                'description': f'技能名称 "{target.name}" 匹配 ClawHavoc 活动的随机后缀命名模式\n特征：基础名 + 5位随机十六进制后缀\n建议：高度怀疑为自动化生成的恶意技能',
                'file_path': str(target),
                'remediation': '拒绝安装，报告给安全团队',
                'source': 'threat_intel',
            })
        
        # ToxicSkills 活动特征：批量发布模式检测
        if target.is_dir():
            sibling_dirs = list(target.parent.glob('*')) if target.parent else []
            similar_names = [d for d in sibling_dirs if d.is_dir() and d.name.startswith(target.name.split('-')[0])]
            if len(similar_names) > 3:
                findings.append({
                    'rule_id': 'CAMPAIGN_TOXIC_001',
                    'severity': 'HIGH',
                    'category': 'threat_intel',
                    'title': '疑似批量发布活动 (ToxicSkills 模式)',
                    'description': f'检测到 {len(similar_names)} 个同名前缀技能\n这可能是 ToxicSkills 类型的批量恶意发布活动\n建议：审查所有相关技能',
                    'file_path': str(target),
                    'remediation': '批量审查同名技能家族',
                    'source': 'threat_intel',
                })
        
        # SkillJect 活动特征：隐蔽执行链
        execution_chain_indicators = [
            (r'curl.*\|\s*(ba)?sh', '远程脚本直接执行'),
            (r'wget.*-O-.*\|\s*(ba)?sh', 'wget 管道执行'),
            (r'python3?\s+-c\s+["\'].*import\s+os', '内联 Python 代码执行'),
            (r'eval\s*\(', '动态代码执行 (eval)'),
            (r'exec\s*\(', '动态代码执行 (exec)'),
        ]
        
        for file_path in files_to_scan:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                for pattern, desc in execution_chain_indicators:
                    if re.search(pattern, content):
                        findings.append({
                            'rule_id': 'CAMPAIGN_SKILLJECT_001',
                            'severity': 'CRITICAL',
                            'category': 'threat_intel',
                            'title': f'SkillJect 执行链检测: {desc}',
                            'description': f'检测到 SkillJect 风格的隐蔽执行链\n模式：{desc}\n文件：{file_path.name}\n建议：立即终止安装流程',
                            'file_path': str(file_path),
                            'remediation': '禁止安装，这是典型的 SkillJect 攻击模式',
                            'source': 'threat_intel',
                        })
                        break  # One finding per file is enough
            except Exception:
                pass
        
        return findings

    # ─── 扫描管线 ───────────────────────────────────────────────
    def scan(self, target_path: str) -> Dict:
        """扫描单个目标 — 七层防御管线"""
        target = Path(target_path)

        if not target.exists():
            return {
                'error': f'Target not found: {target_path}',
                'risk_level': 'ERROR',
                'verdict': 'SCAN_FAILED',
            }

        _p(f"🔍 开始扫描：{target}")
        _p(f"扫描时间：{datetime.now().isoformat()}")
        _p()

        # ─── 统计文件数（在扫描开始时记录，避免后续清理影响）──
        try:
            if target.is_file():
                total_files = 1
            elif target.is_dir():
                all_entries = list(target.rglob('*'))
                total_files = len([f for f in all_entries if f.is_file()])
            else:
                total_files = 0
        except Exception as e:
            _p(f"   ⚠️  统计文件数失败: {e}")
            total_files = 0

        # 0. 白名单检查
        if self.enable_whitelist:
            _p("📊 步骤 0/7: 白名单检查...")
            whitelist_result = self.whitelist.is_whitelisted(target)
            if whitelist_result.get('is_whitelisted', False):
                reason = whitelist_result.get('reason', 'Matched whitelist')
                _p(f"   ✅ 白名单豁免：{reason}")
                return {
                    'target': str(target),
                    'status': 'WHITELISTED',
                    'verdict': 'SAFE',
                    'message': f"{self.i18n.t('whitelist_passed', skill=target.name)} - {reason}",
                    'findings': [],
                    'risk_score': 0,
                    'risk_level': 'LOW',
                    'whitelist_reason': reason,
                }
            _p("   ℹ️  未匹配白名单，继续扫描")

        all_findings: List[Dict] = []

        # 1. 威胁情报 (v3.2 - 全面集成 ClawHavoc/Snyk/SkillJect 情报)
        if self.threat_intel:
            _p("📊 步骤 1/7: 威胁情报匹配...")
            
            # 提取技能元数据（作者、描述等）
            skill_metadata = self._extract_skill_metadata(target)
            
            # 1a. 技能名称匹配
            ti_result = self.threat_intel.check_skill_name(target.name)
            is_malicious = ti_result[0]
            matched = ti_result[1] if len(ti_result) > 1 else None
            risk_cat = ti_result[2] if len(ti_result) > 2 else ''
            
            if is_malicious:
                cat_label = {
                    'KNOWN_MALICIOUS': '已知恶意',
                    'TYPOSQUAT': 'Typosquat 伪装',
                }.get(risk_cat, risk_cat)
                
                all_findings.append({
                    'rule_id': 'THREAT_001',
                    'severity': 'CRITICAL',
                    'category': 'threat_intel',
                    'title': f'恶意技能名称匹配 ({cat_label})',
                    'description': f'技能名称匹配威胁情报库：{matched}\n来源：Koi.ai ClawHavoc / Snyk ToxicSkills / SkillJect\n风险类别：{risk_cat}',
                    'file_path': str(target),
                    'remediation': '禁止安装此技能 — 已确认属于已知恶意技能家族',
                    'source': 'threat_intel',
                })
                _p(f"   ⛔ 发现恶意技能名称：{matched} ({cat_label})")
            
            # 1b. 作者信誉检查 (优化：从 SKILL.md 提取作者信息)
            author_match = False
            author = skill_metadata.get('author', '')
            if author:
                is_author_bad, matched_author = self.threat_intel.check_author(author)
                if is_author_bad:
                    author_match = True
                    all_findings.append({
                        'rule_id': 'THREAT_002',
                        'severity': 'HIGH',
                        'category': 'threat_intel',
                        'title': f'恶意作者检测: {matched_author}',
                        'description': f'技能作者 "{author}" 出现在已知恶意作者列表中\n关联活动：ClawHavoc / ToxicSkills 攻击活动\n建议：审查该作者发布的所有技能',
                        'file_path': str(target),
                        'remediation': '审查作者所有发布的技能，可能存在关联风险',
                        'source': 'threat_intel',
                    })
                    _p(f"   ⚠️  发现恶意作者：{matched_author}")
            
            # 1c. IOC 域名/IP 扫描 (优化：只扫描可执行文件和配置文件)
            ioc_findings = []
            scan_extensions = {'.py', '.sh', '.js', '.ts', '.bash', '.zsh', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf'}
            files_to_scan = [target] if target.is_file() else [
                f for f in target.rglob('*') 
                if f.is_file() and (f.suffix.lower() in scan_extensions or f.name in ['Makefile', 'Dockerfile', '.env'])
            ]
            
            for file_path in files_to_scan:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    for ioc in self.threat_intel.intel_data.get('ioc_domains', []):
                        if ioc in content:
                            ioc_type = "C2 服务器" if ioc[0].isdigit() else "载荷托管域"
                            ioc_findings.append({
                                'rule_id': 'THREAT_003',
                                'severity': 'CRITICAL',
                                'category': 'threat_intel',
                                'title': f'已知 IOC 匹配: {ioc}',
                                'description': f'文件包含已知恶意指标 (IOC)\nIOC: {ioc}\n类型：{ioc_type}\n文件：{file_path.name}',
                                'file_path': str(file_path),
                                'remediation': '立即阻断与该 IOC 的所有通信，审查相关代码逻辑',
                                'source': 'threat_intel',
                            })
                            _p(f"   🚨 发现 IOC 匹配：{ioc} in {file_path.name}")
                except Exception:
                    pass
            
            all_findings.extend(ioc_findings)
            
            # 1d. 攻击模式匹配 (优化：基于 SkillJect/ClawHavoc 的攻击模式)
            attack_pattern_findings = []
            for file_path in files_to_scan:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    pattern_matches = self.threat_intel.check_code_patterns(content)
                    for pm in pattern_matches:
                        attack_pattern_findings.append({
                            'rule_id': f'THREAT_PATTERN_{pm["pattern_id"].upper()}',
                            'severity': pm['severity'],
                            'category': 'threat_intel',
                            'title': f'攻击模式匹配: {pm["description"]}',
                            'description': f'检测到已知攻击模式\n模式：{pm["pattern_id"]}\n指示器：{pm["indicator"]}\n严重程度：{pm["severity"]}',
                            'file_path': str(file_path),
                            'remediation': '审查相关代码段，确认是否存在恶意行为',
                            'source': 'threat_intel',
                        })
                except Exception:
                    pass
            
            all_findings.extend(attack_pattern_findings)
            
            # 1e. 活动集群检测 (新增 - 检测 ClawHavoc/Snyk 报告的活动模式)
            campaign_findings = self._detect_campaign_patterns(target, files_to_scan)
            all_findings.extend(campaign_findings)
            
            # 汇总威胁情报结果
            total_ti = sum([is_malicious, author_match, len(ioc_findings), len(attack_pattern_findings), len(campaign_findings)])
            if total_ti == 0:
                _p("   ✅ 威胁情报检查通过")
            else:
                _p(f"   ⚠️  威胁情报发现 {total_ti} 个问题 (IOC:{len(ioc_findings)} 模式:{len(attack_pattern_findings)} 活动:{len(campaign_findings)})")
            
            # 性能优化：如果发现 CRITICAL 威胁情报，提前终止扫描
            if is_malicious or ioc_findings:
                _p("   ⚡ 发现 CRITICAL 威胁情报，跳过后续轻量级检查")

        # 2. 去混淆检测 (v3.0 新增)
        if self.deobfuscator and not target.is_file():
            _p("\n📊 步骤 2/7: 去混淆检测...")
            deob_findings = self.deobfuscator.analyze_directory(target, path_filter=self.path_filter)
            for f in deob_findings:
                all_findings.append({
                    'rule_id': f'DEOBF_{f.technique.upper()}',
                    'severity': f.severity,
                    'category': 'deobfuscation',
                    'title': f'混淆检测: {f.technique}',
                    'description': f.description,  # deobfuscator 已构建完整描述
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'remediation': '审查混淆代码的真实意图',
                    'source': 'deobfuscation',
                })
            _p(f"   发现 {len(deob_findings)} 个混淆问题")

        # 3. 静态分析
        _p("\n📊 步骤 3/7: 静态分析...")
        if target.is_file():
            static_findings = self.static_analyzer.analyze_file(target)
        else:
            static_findings = self.static_analyzer.analyze_directory(target, recursive=True, path_filter=self.path_filter)

        for f in static_findings:
            # 构建增强描述：包含匹配的代码片段
            desc = f.description
            evidence = getattr(f, 'evidence', '') or getattr(f, 'matched_text', '')
            if evidence and evidence not in desc:
                desc += f"\n\n📋 匹配代码:\n```\n{evidence[:300]}\n```"
            
            all_findings.append({
                'rule_id': getattr(f, 'rule_id', '') or f.category,
                'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                'category': getattr(f, 'category', 'static'),
                'title': f.title,
                'description': desc,
                'file_path': f.file_path,
                'line_number': getattr(f, 'line_number', 0),
                'remediation': f.remediation,
                'source': 'static_analysis',
                'code_evidence': evidence[:500] if evidence else '',
            })
        _p(f"   发现 {len(static_findings)} 个静态分析问题")

        # 4. AST 分析 (v3.0 新增)
        if self.ast_analyzer and not target.is_file():
            _p("\n📊 步骤 4/7: AST 深度分析...")
            ast_findings = self.ast_analyzer.analyze_directory(target, path_filter=self.path_filter)
            for f in ast_findings:
                all_findings.append({
                    'rule_id': f.rule_id,
                    'severity': f.severity,
                    'category': f.category,
                    'title': f.title,
                    'description': f.description,
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'remediation': f.remediation,
                    'source': 'ast_analysis',
                    'code_snippet': f.code_snippet[:200],
                })
            _p(f"   发现 {len(ast_findings)} 个 AST 级别问题")

        # 5. 依赖安全检查 (v3.0 新增)
        if self.dep_checker and not target.is_file():
            _p("\n📊 步骤 5/7: 依赖安全检查...")
            dep_findings = self.dep_checker.check_directory(target)
            for f in dep_findings:
                all_findings.append({
                    'rule_id': f.rule_id,
                    'severity': f.severity,
                    'category': 'dependency',
                    'title': f.title,
                    'description': f.description,
                    'file_path': f.file_path,
                    'remediation': f.remediation,
                    'source': 'dependency_check',
                    'metadata': {
                        'package': f.package_name,
                        'installed_version': f.installed_version,
                        'safe_version': f.safe_version,
                        'cve_ids': f.cve_ids,
                    },
                })
            _p(f"   发现 {len(dep_findings)} 个依赖安全问题")

        # 6. 提示词注入测试 (v3.1 新增)
        if self.prompt_injection_tester and not target.is_file():
            _p("\n📊 步骤 6/8: 提示词注入探针扫描...")
            pi_results = self.prompt_injection_tester.test_skill(target, path_filter=self.path_filter)
            for r in pi_results:
                all_findings.append({
                    'rule_id': r.probe_id,
                    'severity': r.severity,
                    'category': f'prompt_injection_{r.category}',
                    'title': f'提示词注入风险: {r.category}',
                    'description': r.description,
                    'file_path': str(target),
                    'remediation': '审查用户输入处理逻辑，添加输入过滤和沙箱隔离',
                    'source': 'prompt_injection_test',
                    'matched_text': r.matched_text[:200],
                })
            if pi_results:
                _p(f"   ⚠️  发现 {len(pi_results)} 个提示词注入风险点")
            else:
                _p("   ✅ 未发现提示词注入模式")

        # 7. 基线比对 (v3.0 新增)
        if self.baseline_tracker and not target.is_file():
            _p("\n📊 步骤 7/8: 基线比对 (Rug-Pull 检测)...")
            has_changes, changes = self.baseline_tracker.check_changes(target.name, target)
            if has_changes:
                critical_changes = [c for c in changes if c.severity == 'CRITICAL']
                high_changes = [c for c in changes if c.severity == 'HIGH']

                if critical_changes:
                    # 构建详细的变更描述
                    change_details = '\n'.join([
                        f"  • [{c.severity}] {c.change_type}: {c.file_path}"
                        for c in critical_changes[:10]
                    ])
                    all_findings.append({
                        'rule_id': 'BASELINE_CRITICAL',
                        'severity': 'CRITICAL',
                        'category': 'baseline_change',
                        'title': f'关键文件变更 ({len(critical_changes)} 个)',
                        'description': f'检测到核心文件被修改/删除/新增，可能存在 Rug-Pull 攻击\n\n📋 变更详情:\n{change_details}',
                        'file_path': str(target),
                        'remediation': '立即审查所有变更，确认是否为合法更新',
                        'source': 'baseline_check',
                        'metadata': {
                            'changes': [
                                {'type': c.change_type, 'path': c.file_path, 'severity': c.severity}
                                for c in changes
                            ]
                        },
                    })
                elif high_changes:
                    change_details = '\n'.join([
                        f"  • [{c.severity}] {c.change_type}: {c.file_path}"
                        for c in high_changes[:10]
                    ])
                    all_findings.append({
                        'rule_id': 'BASELINE_HIGH',
                        'severity': 'HIGH',
                        'category': 'baseline_change',
                        'title': f'代码文件变更 ({len(high_changes)} 个)',
                        'description': f'检测到代码文件变更，建议审查\n\n📋 变更详情:\n{change_details}',
                        'file_path': str(target),
                        'remediation': '审查变更内容，确认安全性后更新基线',
                        'source': 'baseline_check',
                        'metadata': {
                            'changes': [
                                {'type': c.change_type, 'path': c.file_path, 'severity': c.severity}
                                for c in changes
                            ]
                        },
                    })
                _p(f"   ⚠️  检测到 {len(changes)} 个文件变更")
            else:
                _p("   ✅ 基线一致，无变更")

        # 8. 语义审计（可选）
        semantic_findings = []
        if self.enable_semantic:
            _p("\n📊 步骤 8/8: 语义审计...")
            if target.is_file():
                content = target.read_text(encoding='utf-8')
                semantic_findings = self.semantic_auditor.audit_file(target, content)
            else:
                semantic_findings = self.semantic_auditor.audit_directory(target, path_filter=self.path_filter)
            
            # 只过滤明显的推理过程文本（整段都是指令的情况）
            reasoning_indicators = [
                'analyze the input code', 'refine findings for json',
                'draft the json output', 'ensure all findings follow',
                'the overall risk_level must be',
                'determine overall risk level based on',
            ]
            
            for f in semantic_findings:
                desc = (f.description or '').lower()
                title = (f.title or '').lower()
                
                # 只有当描述完全由推理指令组成时才跳过
                # 关键判断：如果描述包含具体的代码证据/上下文，说明是有效发现
                has_evidence = any(marker in desc for marker in ['```', '检测到', '模式', 'context'])
                is_reasoning_leak = (
                    len(desc) > 100 and
                    not has_evidence and
                    any(kw in desc for kw in reasoning_indicators)
                )
                
                # 标题本身是推理步骤名称也跳过
                is_step_title = title.startswith(('step ', 'phase ', 'stage '))
                
                if is_reasoning_leak or is_step_title:
                    _p(f"   ⏭️  跳过推理泄漏: {f.title[:50]}")
                    continue
                
                all_findings.append({
                    'rule_id': f'SEMANTIC_{f.category.upper()}',
                    'severity': f.severity,
                    'category': f'semantic_{f.category}',
                    'title': f.title,
                    'description': (f.description or '')[:500],
                    'file_path': f.file_path,
                    'line_number': getattr(f, 'line', 0),
                    'remediation': f.remediation,
                    'source': 'semantic_audit',
                })
            _p(f"   发现 {len(semantic_findings)} 个语义分析问题")

        # ─── v3.3 新增引擎 ──────────────────────────────────────

        # 9. 熵值分析 (v3.3 新增 — 参考 ClawGuard Auditor)
        if self.entropy_analyzer and not target.is_file():
            _p("\n📊 步骤 9/11: 熵值分析...")
            entropy_findings = self.entropy_analyzer.analyze_directory(target, path_filter=self.path_filter)
            for f in entropy_findings:
                all_findings.append({
                    'rule_id': f.rule_id,
                    'severity': f.severity,
                    'category': 'entropy_analysis',
                    'title': f.title,
                    'description': f.description[:800],
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'remediation': f.remediation,
                    'source': 'entropy_analysis',
                    'metadata': {
                        'entropy_score': f.entropy_score,
                        'threshold': f.threshold,
                    },
                })
            if entropy_findings:
                _p(f"   ⚠️  发现 {len(entropy_findings)} 个熵值异常问题")
            else:
                _p("   ✅ 熵值分析正常，未发现异常编码区域")

        # 10. 安装钩子检测 (v3.3 新增 — 参考 SecureClaw)
        if self.hook_detector and not target.is_file():
            _p("\n📊 步骤 10/11: 安装钩子检测...")
            hook_findings = self.hook_detector.analyze_directory(target, path_filter=self.path_filter)
            for f in hook_findings:
                all_findings.append({
                    'rule_id': f.rule_id,
                    'severity': f.severity,
                    'category': 'install_hook',
                    'title': f.title,
                    'description': f.description[:800],
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'remediation': f.remediation,
                    'source': 'install_hook_detection',
                    'metadata': {
                        'hook_type': f.hook_type,
                    },
                })
            if hook_findings:
                _p(f"   ⚠️  发现 {len(hook_findings)} 个安装钩子问题")
            else:
                _p("   ✅ 未发现可疑安装钩子")

        # 11. 网络行为画像 (v3.3 新增 — 参考 Astrix Security)
        if self.network_profiler and not target.is_file():
            _p("\n📊 步骤 11/12: 网络行为画像...")
            network_findings = self.network_profiler.analyze_directory(target, path_filter=self.path_filter)
            for f in network_findings:
                all_findings.append({
                    'rule_id': f.rule_id,
                    'severity': f.severity,
                    'category': 'network_behavior',
                    'title': f.title,
                    'description': f.description[:800],
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'remediation': f.remediation,
                    'source': 'network_profiling',
                })
            if network_findings:
                _p(f"   ⚠️  发现 {len(network_findings)} 个网络行为风险")
            else:
                _p("   ✅ 网络行为正常，无可疑连接")

        # ─── 步骤 12: 凭证窃取检测 (v3.6 新增) ─────────────────
        if self.credential_theft_detector and not target.is_file():
            _p("\n🔐 步骤 12/12: 凭证窃取检测...")
            cred_findings = self.credential_theft_detector.analyze_directory(target, path_filter=self.path_filter)
            for f in cred_findings:
                all_findings.append({
                    'rule_id': f.rule_id,
                    'severity': f.severity,
                    'category': 'credential_theft',
                    'title': f.title,
                    'description': f.description[:800],
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'remediation': f.remediation,
                    'source': 'credential_theft_detection',
                })
            if cred_findings:
                _p(f"   ⚠️  发现 {len(cred_findings)} 个凭证窃取风险")
            else:
                _p("   ✅ 凭证窃取检测正常")

        # ─── 计算风险分数 ──────────────────────────────────────
        risk_score = self._calculate_risk_score(all_findings)
        risk_level = self._get_risk_level(risk_score)
        verdict = self._get_verdict(risk_level)

        # ─── 统计 ──────────────────────────────────────────────
        findings_by_severity: Dict[str, int] = {}
        findings_by_category: Dict[str, int] = {}
        findings_by_source: Dict[str, int] = {}

        for finding in all_findings:
            severity = finding.get('severity', 'UNKNOWN')
            category = finding.get('category', 'unknown')
            source = finding.get('source', 'unknown')
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
            findings_by_category[category] = findings_by_category.get(category, 0) + 1
            findings_by_source[source] = findings_by_source.get(source, 0) + 1

        result = {
            'target': str(target),
            'scan_time': datetime.now().isoformat(),
            'scanner_version': '3.7.0',
            'total_files': total_files,
            'total_findings': len(all_findings),
            'findings_by_severity': findings_by_severity,
            'findings_by_category': findings_by_category,
            'findings_by_source': findings_by_source,
            'findings': all_findings,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'verdict': verdict,
            'summary': self._generate_summary(all_findings, risk_level),
        }

        _p(f"\n{'=' * 60}")
        _p("扫描完成")
        _p(f"风险等级：{risk_level}")
        _p(f"风险分数：{risk_score}/100")
        _p(f"结论：{verdict}")
        _p(f"{'=' * 60}")

        # 更新基线（如果通过）
        if self.baseline_tracker and risk_level in ('LOW', 'MEDIUM'):
            self.baseline_tracker.create_baseline(
                target.name, str(target), risk_level, risk_score
            )

        return result

    # ─── 内部工具方法 ──────────────────────────────────────────
    def _calculate_risk_score(self, findings: List) -> int:
        """计算风险分数 (0-100) — 统一算法"""
        severity_weights = {
            'CRITICAL': 30,
            'HIGH': 20,
            'MEDIUM': 10,
            'LOW': 5,
            'INFO': 1,
        }
        score = 0
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            score += severity_weights.get(severity, 5)
        return min(score, 100)

    def _get_risk_level(self, score: int) -> str:
        """根据分数获取风险等级 — 与 risk_scorer.py 一致"""
        if score >= self.RISK_THRESHOLDS['EXTREME']:
            return 'EXTREME'
        elif score >= self.RISK_THRESHOLDS['HIGH']:
            return 'HIGH'
        elif score >= self.RISK_THRESHOLDS['MEDIUM']:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _get_verdict(self, risk_level: str) -> str:
        verdicts = {
            'EXTREME': '❌ DO NOT INSTALL',
            'HIGH': '❌ DO NOT INSTALL',
            'MEDIUM': '⚠️  INSTALL WITH CAUTION',
            'LOW': '✅ SAFE TO INSTALL',
        }
        return verdicts.get(risk_level, '⚠️  REVIEW REQUIRED')

    @staticmethod
    def _count_files(target: Path) -> int:
        """统计文件数，容错处理"""
        try:
            if target.is_file():
                return 1
            return len([f for f in target.rglob('*') if f.is_file()])
        except Exception:
            return 0

    def _generate_summary(self, findings: List, risk_level: str) -> str:
        if not findings:
            return "未发现安全问题，可以安全安装"
        total = len(findings)
        critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high_count = sum(1 for f in findings if f.get('severity') == 'HIGH')
        parts = [f"共发现 **{total}** 个安全问题。其中："]
        if critical_count > 0:
            parts.append(f"**{critical_count} 个严重 (CRITICAL)**")
        if high_count > 0:
            parts.append(f"**{high_count} 个高危 (HIGH)**")
        medium_count = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        if medium_count > 0:
            parts.append(f"**{medium_count} 个中危 (MEDIUM)**")
        low_count = sum(1 for f in findings if f.get('severity') == 'LOW')
        if low_count > 0:
            parts.append(f"**{low_count} 个低危 (LOW)**")
        summary = '、'.join(parts) + '。'
        if risk_level in ('EXTREME', 'HIGH'):
            summary += '**禁止安装此技能。**'
        elif risk_level == 'MEDIUM':
            summary += '建议人工审查后决定是否安装。'
        return summary


# ─── SARIF 输出 ────────────────────────────────────────────────
def _generate_sarif(result: Dict) -> str:
    """生成 SARIF 2.1.0 格式报告"""
    rules = {}
    results_list = []

    for finding in result.get('findings', []):
        rule_id = finding.get('rule_id', 'UNKNOWN')
        severity = finding.get('severity', 'MEDIUM')

        if rule_id not in rules:
            rules[rule_id] = {
                'id': rule_id,
                'name': finding.get('title', rule_id),
                'shortDescription': {'text': finding.get('description', '')},
                'defaultConfiguration': {'level': _sarif_level(severity)},
            }

        sarif_result = {
            'ruleId': rule_id,
            'level': _sarif_level(severity),
            'message': {'text': finding.get('description', '')},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': finding.get('file_path', '')},
                },
            }],
        }

        line_num = finding.get('line_number')
        if line_num:
            sarif_result['locations'][0]['physicalLocation']['region'] = {
                'startLine': line_num,
            }

        results_list.append(sarif_result)

    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'X Skill Scanner',
                    'version': result.get('scanner_version', '3.0.0'),
                    'informationUri': 'https://github.com/1997xxx/X-Skill-Scanner',
                    'rules': list(rules.values()),
                },
            },
            'results': results_list,
            'invocations': [{
                'executionSuccessful': True,
                'endTimeUtc': result.get('scan_time', ''),
            }],
        }],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _sarif_level(severity: str) -> str:
    """转换为 SARIF 级别"""
    mapping = {
        'CRITICAL': 'error',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'note',
        'INFO': 'note',
    }
    return mapping.get(severity, 'warning')


# ─── CLI 入口 ──────────────────────────────────────────────────
def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description='X Skill Scanner v3.0 - AI 技能安全扫描器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python3 scan -t ./my-skill/                 # 默认启用语义审计
  python3 scan -t ./my-skill/ --no-semantic   # 快速模式（跳过语义审计）
  python3 scan -t ./my-skill/ --json -o report.json
  python3 scan -t ~/.openclaw/workspace/skills/ -r
  python3 scan -t ./my-skill/ --sarif -o results.sarif
        ''',
    )

    parser.add_argument('-t', '--target', help='扫描目标路径')
    parser.add_argument('--url', help='扫描远程技能 URL (GitHub raw link)')
    parser.add_argument('--no-semantic', action='store_true', help='跳过语义审计')
    parser.add_argument('-r', '--recursive', action='store_true', help='递归扫描目录')
    parser.add_argument('-j', '--json', action='store_true', help='输出 JSON 格式')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--no-threat-intel', action='store_true', help='跳过威胁情报检查')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')

    # 输出格式
    parser.add_argument(
        '--format',
        choices=['text', 'json', 'html', 'md', 'sarif'],
        default='html',
        help='输出格式: text|json|html(默认)|md|sarif',
    )

    # 语言
    parser.add_argument(
        '--lang',
        choices=['zh', 'en'],
        default='zh',
        help='报告语言: zh(默认中文)|en(English)',
    )

    # 白名单
    parser.add_argument('--whitelist', help='白名单文件路径 (JSON格式)')
    parser.add_argument('--no-whitelist', action='store_true', help='跳过白名单检查')

    # v3.0 新选项
    parser.add_argument('--no-deobfuscation', action='store_true', help='跳过去混淆检测')
    parser.add_argument('--no-ast', action='store_true', help='跳过 AST 分析')
    parser.add_argument('--no-baseline', action='store_true', help='跳过基线比对')
    parser.add_argument('--no-deps', action='store_true', help='跳过依赖检查')
    parser.add_argument('--baseline-only', action='store_true', help='仅执行基线比对')
    parser.add_argument('--update-baseline', action='store_true', help='更新基线后退出')

    args = parser.parse_args()

    # 处理 URL 扫描
    target_path = args.target
    temp_dir = None

    if args.url and not args.target:
        import tempfile
        import shutil

        _p(f"📥 下载远程技能: {args.url}")
        url_path = args.url.split('/')[-2] if '/skills/' in args.url else 'remote-skill'
        skill_dir = Path(__file__).parent.parent
        temp_dir = skill_dir / 'tmp' / url_path
        temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            import urllib.request
            skill_md_url = args.url if args.url.endswith('.md') else f"{args.url}/SKILL.md"
            if 'github.com' in skill_md_url and '/blob/' in skill_md_url:
                skill_md_url = skill_md_url.replace('/blob/', '/raw/')

            req = urllib.request.Request(skill_md_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8')

            (temp_dir / 'SKILL.md').write_text(content, encoding='utf-8')
            _p(f"✅ 已下载到: {temp_dir}")
            target_path = str(temp_dir)
        except Exception as e:
            _p(f"❌ 下载失败: {e}")
            sys.exit(1)

    if not target_path:
        parser.error("请指定 -t/--target 或 --url")

    # 创建扫描器
    scanner = SkillScanner(
        enable_semantic=not args.no_semantic,
        enable_threat_intel=not args.no_threat_intel,
        enable_deobfuscation=not args.no_deobfuscation,
        enable_ast_analysis=not args.no_ast,
        enable_baseline=not args.no_baseline,
        enable_dep_check=not args.no_deps,
        output_format=args.format,
        lang=args.lang,
        whitelist_path=args.whitelist,
        enable_whitelist=not args.no_whitelist,
    )

    # 基线专用模式
    if args.baseline_only and scanner.baseline_tracker:
        target = Path(target_path)
        has_changes, changes = scanner.baseline_tracker.check_changes(target.name, target)
        if has_changes:
            _p(f"⚠️  检测到 {len(changes)} 个文件变更:")
            for c in changes:
                _p(f"  [{c.severity}] {c.change_type}: {c.file_path}")
            sys.exit(1)
        else:
            _p("✅ 基线一致，无变更")
            sys.exit(0)

    if args.update_baseline and scanner.baseline_tracker:
        result = scanner.scan(target_path)
        scanner.baseline_tracker.create_baseline(
            Path(target_path).name, target_path,
            result.get('risk_level', 'UNKNOWN'),
            result.get('risk_score', 0),
        )
        sys.exit(0)

    # 执行扫描
    result = scanner.scan(target_path)

    # 输出结果
    if args.json or args.format == 'sarif':
        if args.format == 'sarif':
            output = _generate_sarif(result)
        else:
            output = json.dumps(result, indent=2, ensure_ascii=False)
        # JSON/SARIF 同时写 stdout（可管道化）和文件
        sys.stdout.write(output)
        sys.stdout.write('\n')
    else:
        output = scanner.reporter.generate(result)

    # 确定输出路径
    if args.output:
        output_path = args.output
    else:
        skill_dir = Path(__file__).parent.parent
        reports_dir = skill_dir / 'reports'
        reports_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        target_name = Path(target_path).name or 'unknown'
        ext = 'sarif' if args.format == 'sarif' else args.format
        output_path = str(reports_dir / f"{target_name}-report-{timestamp}.{ext}")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(output)
    _p(f"\n报告已保存到：{output_path}")

    # 清理临时文件
    if temp_dir and temp_dir.exists():
        import shutil
        shutil.rmtree(temp_dir)
        _p(f"🧹 已清理临时文件: {temp_dir}")

    # 根据风险等级设置退出码
    if result.get('risk_level') in ['EXTREME', 'HIGH']:
        sys.exit(1)
    elif result.get('risk_level') == 'MEDIUM':
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()