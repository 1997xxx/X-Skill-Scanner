#!/usr/bin/env python3
"""
X Skill Scanner v6.0.0 - 主扫描器
架构：技能画像 → 自适应扫描 → 误报预过滤 → SubAgent 二次审查 → 最终裁决

版本演进:
- v3.x: 逐步叠加 12 层检测引擎（详见 CHANGELOG.md）
- v4.0: LLM 二次审查引擎 — 规则引擎高召回 + LLM 高精度 = 低误报不漏报
- v4.1: 技能画像 + 误报预过滤 + 自适应扫描策略 + 跨层关联
- v5.0: 画像驱动自适应扫描 + LLM 批量审查 + 跨层关联分析 + 风险评分升级
- v6.0: SubAgent 多 Agent 审查 + 统一数据模型 + 启发式降级
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Import shared constants
from constants import (
    MAX_RISK_SCORE, MIN_RISK_SCORE,
    TRUST_THRESHOLD_QUICK, TRUST_THRESHOLD_STANDARD,
    MAX_FILES_QUICK_MODE, MAX_FILES_STANDARD_MODE,
    DEFAULT_TIMEOUT_SECONDS, LLM_REVIEW_TIMEOUT_SECONDS,
    SCANNER_VERSION,
)


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
from i18n import I18n

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

# v4.0/v5.0 新增引擎 — LLM 二次审查
from subagent_reviewer import SubAgentReviewer

# v5.0 新增引擎 — 技能画像 + 误报预过滤
from skill_profiler import SkillProfiler
from fp_filter import FPFilter

# v5.1 新增引擎 — 前置合法性检查（Gatekeeper）
from pre_flight_check import PreFlightCheck

# v5.1 新增引擎 — 文档社会工程学检测
from social_engineering_detector import SocialEngineeringDetector


class SkillScanner:
    """技能安全扫描器 v5.0 — 轻量初筛 + LLM 二次审查"""

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

        # v4.0/v5.0 新增引擎 — LLM 二次审查
        self.enable_llm_review = True   # v5.0: 默认开启
        self.llm_reviewer = None

        # v5.0 新增引擎 — 技能画像 + 误报预过滤
        self.skill_profiler = SkillProfiler()
        self.fp_filter = FPFilter()
        self._skill_profile = None      # 扫描时填充

        # v5.1 新增引擎 — 前置合法性检查（Gatekeeper）
        self.pre_flight_check = PreFlightCheck()

        # v5.1 新增引擎 — 文档社会工程学检测
        self.social_engineering_detector = SocialEngineeringDetector()

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

    def _should_run_engine(self, engine_name: str) -> bool:
        """根据画像策略决定是否运行某引擎"""
        if not self._skill_profile:
            return True
        strategy = self._skill_profile.scan_strategy
        if strategy == "quick":
            return engine_name in {"threat_intel", "static_analysis", "credential_theft"}
        return True

    def _has_critical_or_high_findings(self, findings: list) -> bool:
        """检查是否存在 CRITICAL 或 HIGH 级别的发现"""
        for f in findings:
            sev = f.get('severity', '') if isinstance(f, dict) else getattr(f, 'severity', '')
            if sev in ('CRITICAL', 'HIGH'):
                return True
        return False

    def _get_llm_review_threshold(self, findings: list = None) -> str:
        """根据画像策略 + 实际发现严重度决定 LLM 审查阈值
        
        安全原则：即使 quick 策略，发现 CRITICAL/HIGH 问题时也必须触发 LLM 审查。
        防止高信任度伪装包（如恶意安全工具）绕过深度检测。
        """
        if not self._skill_profile:
            return "MEDIUM"
        
        strategy = self._skill_profile.scan_strategy
        base_threshold = {
            "quick": "NEVER",
            "standard": "MEDIUM",
        }.get(strategy, "ALL")
        
        # 安全覆盖：存在 CRITICAL/HIGH 发现时，强制升级为 MEDIUM 阈值
        if base_threshold == "NEVER" and findings and self._has_critical_or_high_findings(findings):
            return "MEDIUM"
        
        return base_threshold

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
            (r'curl.*\|\s*(ba)?sh', '远程脚本直接执行',
             '通过 curl 下载远程脚本并直接通过管道执行，无需写入磁盘即可运行任意代码。攻击者可随时修改远程内容实现零日攻击。'),
            (r'wget.*-O-.*\|\s*(ba)?sh', 'wget 管道执行',
             '通过 wget 下载远程脚本并通过标准输出管道执行，是常见的无文件攻击手法。'),
            (r'python3?\s+-c\s+["\'].*import\s+os', '内联 Python 代码执行',
             '使用 python -c 内联执行包含 os 模块导入的代码，可绕过常规的文件扫描检测。'),
            (r'eval\s*\(', '动态代码执行 (eval)',
             '使用 eval() 在运行时动态执行字符串形式的代码，是 SkillJect 攻击的核心技术。恶意代码可在安装时或运行时被触发。'),
            (r'exec\s*\(', '动态代码执行 (exec)',
             '使用 exec() 在运行时动态执行代码，与 eval 类似但更危险，可执行任意 Python 语句块。'),
        ]
        
        for file_path in files_to_scan:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                for pattern, desc, impact_desc in execution_chain_indicators:
                    match = re.search(pattern, content)
                    if match:
                        # 提取匹配的代码行作为证据
                        matched_lines = []
                        for line in content.split('\n'):
                            stripped = line.strip()
                            if stripped and not stripped.startswith('#'):
                                try:
                                    if re.search(pattern, line):
                                        matched_lines.append(stripped)
                                        if len(matched_lines) >= 2:
                                            break
                                except re.error:
                                    pass
                        
                        desc_parts = [f'🔴 检测到 SkillJect 风格的隐蔽执行链']
                        desc_parts.append(f'\n📌 执行模式: {desc}')
                        desc_parts.append(f'📁 文件: {file_path.name}')
                        desc_parts.append(f'\n⚠️  潜在影响: {impact_desc}')
                        
                        if matched_lines:
                            desc_parts.append('\n📋 匹配代码片段:')
                            for ml in matched_lines:
                                desc_parts.append(f'  {ml[:150]}')
                        
                        findings.append({
                            'rule_id': 'CAMPAIGN_SKILLJECT_001',
                            'severity': 'CRITICAL',
                            'category': 'threat_intel',
                            'title': f'SkillJect 执行链检测: {desc}',
                            'description': '\n'.join(desc_parts),
                            'file_path': str(file_path),
                            'remediation': '禁止安装。SkillJect 是一种通过动态代码执行在安装或运行时注入恶意代码的攻击手法。审查所有 eval/exec/管道执行的使用场景。',
                            'source': 'threat_intel',
                        })
                        break  # One finding per file is enough
            except Exception:
                pass
        
        return findings

    # ─── 扫描管线 ───────────────────────────────────────────────
    def _is_self_scan(self, target: Path) -> bool:
        """检测是否在扫描自身项目"""
        try:
            # Check if target contains scanner.py (unique identifier)
            scanner_file = target / 'lib' / 'scanner.py'
            if scanner_file.exists():
                return True
            # Also check if any subdirectory contains it
            for f in target.rglob('scanner.py'):
                parent = f.parent.name
                if parent == 'lib':
                    return True
        except Exception:
            pass
        return False

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

        # ─── v5.2.1: Self-scan detection ────────────────────────
        is_self = self._is_self_scan(target)
        if is_self:
            _p("   🔒 检测到自引用扫描（扫描器自身）— 启用特殊模式")
            _p("      • 跳过威胁情报 IOC 匹配（文档中的示例数据）")
            _p("      • 跳过社会工程学检测（安全规则描述）")
            _p("      • 跳过提示词注入探针（测试数据/探针定义）")
            _p("      • 跳过基线跟踪（正常开发变更）")
            _p("      • 跳过跨层关联分析（基于误报的连锁反应）")
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

        # ─── v5.1: 前置合法性检查（Gatekeeper）─────────────────────
        _p("🛡️  步骤 -1/7: 前置合法性检查...")
        pfc_result = self.pre_flight_check.validate(target)
        if not pfc_result['passed']:
            _p(f"   ❌ 前置合法性检查未通过: {pfc_result['message']}")
            for f in pfc_result['findings']:
                sev_icon = {'CRITICAL': '⛔', 'HIGH': '🔴', 'MEDIUM': '🟡'}.get(f['severity'], 'ℹ️')
                _p(f"      {sev_icon} [{f['severity']}] {f['title']} ({f['file']})")
            
            # 将 PFC 发现转换为扫描器格式并加入结果
            pfc_findings = []
            for f in pfc_result['findings']:
                pfc_findings.append({
                    'id': f['id'],
                    'severity': f['severity'],
                    'category': f.get('category', 'pre_flight'),
                    'title': f['title'],
                    'file': f['file'],
                    'line': f.get('line', 0),
                    'description': f['description'],
                    'recommendation': f['recommendation'],
                })
            
            return {
                'target': str(target),
                'status': 'PRE_FLIGHT_FAILED',
                'verdict': 'BLOCK',
                'message': pfc_result['message'],
                'findings': pfc_findings,
                'risk_score': MAX_RISK_SCORE,
                'risk_level': 'EXTREME',
                'total_files': total_files,
                'pre_flight_findings': pfc_result['findings'],
            }
        _p(f"   ✅ {pfc_result['message']}")

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
        static_findings = []  # default, may be set by engine

        # ─── v5.0: 技能画像（先获取基本情况）─────────────────────
        _p("🔎 步骤 0.5: 技能画像...")
        try:
            self._skill_profile = self.skill_profiler.profile(target)
            # 将威胁情报链接到画像引擎（用于作者信誉检查）
            if self.threat_intel:
                self.skill_profiler.set_threat_intel(self.threat_intel)
                self._skill_profile = self.skill_profiler.profile(target)  # 重新画像
            
            profile = self._skill_profile
            _p(f"   技能: {profile.name} | 作者: {profile.author or '未知'} | "
               f"类型: {profile.skill_type} | 文件: {profile.file_count}")
            _p(f"   信任分数: {profile.trust_score}/MAX_RISK_SCORE | "
               f"推荐策略: {profile.scan_strategy} | "
               f"红旗: {len(profile.risk_fingerprint.get('red_flags', []))}")
            
            # 如果信任分数极高且无红旗，可以跳过部分检查
            if profile.scan_strategy == 'quick' and profile.trust_score >= 80:
                _p("   ✅ 高信任度技能，启用快速扫描模式")
        except Exception as e:
            _p(f"   ⚠️  技能画像失败: {e}，使用标准扫描")
            self._skill_profile = None

        # 1. 威胁情报 (v3.2 - 全面集成 ClawHavoc/Snyk/SkillJect 情报)
        if self.threat_intel and self._should_run_engine("threat_intel") and not is_self:
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
            doc_extensions = {'.md', '.txt', '.rst', '.text'}  # v5.1: 文档也需扫描 IOC（bybit-trading 教训）
            # v5.0: 跳过扫描器自身的参考数据文件（避免自引用误报）
            ref_data_names = {'threat_intel.json', '.semantic_cache.json', 'baseline.json',
                              'whitelist.json', 'malicious_skills.json', 'known_bad.json'}
            files_to_scan = [target] if target.is_file() else [
                f for f in target.rglob('*') 
                if f.is_file() and f.name not in ref_data_names
                   and (f.suffix.lower() in scan_extensions or f.suffix.lower() in doc_extensions or f.name in ['Makefile', 'Dockerfile', '.env'])
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
                    pattern_matches = self.threat_intel.check_code_patterns(content, file_path)
                    for pm in pattern_matches:
                        pattern_id = pm['pattern_id']
                        indicator = pm['indicator']
                        severity = pm['severity']
                        pat_desc = pm.get('description', '')
                        
                        # 构建结构化描述
                        desc_parts = [f'🔍 检测到已知攻击模式：{pat_desc}']
                        desc_parts.append(f'\n📌 模式 ID: {pattern_id}')
                        desc_parts.append(f'🎯 匹配指示器: `{indicator}`')
                        desc_parts.append(f'📁 文件: {file_path.name}')
                        
                        # 根据模式类型补充影响说明
                        impact_map = {
                            'credential_harvesting': '该模式会收集用户的敏感凭证（API 密钥、密码、Token 等），可能导致账户被未授权访问。',
                            'config_exfiltration': '该模式读取 Agent 配置文件并通过 HTTP 请求发送到外部服务器，属于典型的数据外泄行为。',
                            'remote_script_download': '该模式从远程服务器下载并执行脚本，攻击者可通过修改远程内容实现任意代码执行。',
                            'reverse_shell': '该模式建立反向 Shell 连接，使攻击者能够远程控制受害系统。',
                            'base64_exec': '该模式使用 Base64 编码隐藏恶意载荷以绕过静态检测，解码后执行危险操作。',
                            'macos_staged_payload': '该模式在 macOS 上分阶段下载、剥离安全属性并执行载荷，是典型的持久化攻击手法。',
                            'typosquatting': '该技能名称模仿知名项目，利用用户拼写错误进行钓鱼或分发恶意代码。',
                            'hidden_backdoor': '该技能表面功能正常，但隐藏了后门行为（如 cron 定时任务、反向 Shell 等）。',
                            'prompt_injection': '该模式尝试通过注入指令覆盖 Agent 的原始提示词，可能导致信息泄露或未授权操作。',
                            'social_engineering': '该技能滥用知名品牌名称获取用户信任，诱导用户执行危险操作。',
                            'webhook_exfiltration': '该模式通过 Webhook（Discord/Telegram/webhook.site）将窃取的数据发送到攻击者控制的端点。',
                            'browser_data_theft': '该模式窃取浏览器存储的敏感数据（Cookie、LocalStorage、保存的密码等）。',
                            'nova_stealer_c2': '该模式与 Nova Stealer 恶意软件的 C2 通信特征匹配，用于窃取系统凭证。',
                            'osascript_password_phishing': '该模式通过 macOS osascript 伪造系统密码对话框进行钓鱼攻击（Nova Stealler 技术）。',
                        }
                        if pattern_id in impact_map:
                            desc_parts.append(f'\n⚠️  潜在影响: {impact_map[pattern_id]}')
                        
                        # 提取匹配的代码行作为证据
                        matched_lines = []
                        for line in content.split('\n'):
                            if indicator.lower() in line.lower():
                                stripped = line.strip()
                                if stripped and not stripped.startswith('#'):
                                    matched_lines.append(stripped)
                                    if len(matched_lines) >= 3:
                                        break
                        
                        if matched_lines:
                            desc_parts.append('\n📋 匹配代码片段:')
                            for ml in matched_lines:
                                desc_parts.append(f'  {ml[:120]}')
                        
                        full_description = '\n'.join(desc_parts)
                        
                        # 生成针对性修复建议
                        remediation_map = {
                            'credential_harvesting': '立即拒绝安装。检查代码中所有引用 .env、password、token 的位置，确认是否有外部传输行为。',
                            'config_exfiltration': '立即拒绝安装。搜索所有 .post(、fetch(、webhook 调用，确认数据外传目标地址。',
                            'remote_script_download': '禁止安装包含远程脚本执行的技能。所有依赖应通过包管理器安装，而非动态下载执行。',
                            'reverse_shell': '立即拒绝安装并报告安全团队。这是高危持久化攻击手法。',
                            'base64_exec': '拒绝安装。要求作者提供解码后的源码供审查，或直接拒绝模糊不清的技能。',
                            'prompt_injection': '拒绝安装。检查所有 system prompt 相关操作，确保无指令注入风险。',
                            'social_engineering': '拒绝安装。验证技能名称和作者身份的真实性。',
                            'webhook_exfiltration': '立即拒绝安装。搜索所有 webhook.site、discord.com/api/webhooks 等外部端点引用。',
                        }
                        remediation = remediation_map.get(pattern_id, '审查相关代码段，确认是否存在恶意行为。重点关注指示器 `' + indicator + '` 的使用上下文。')
                        
                        attack_pattern_findings.append({
                            'rule_id': f'THREAT_PATTERN_{pattern_id.upper()}',
                            'severity': severity,
                            'category': 'threat_intel',
                            'title': f'攻击模式匹配: {pat_desc}',
                            'description': full_description,
                            'file_path': str(file_path),
                            'remediation': remediation,
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

        # 1.5 文档社会工程学检测 (v5.1 新增 — bybit-trading 事件教训)
        if not is_self:
            _p("\n📋 步骤 1.5/7: 文档社会工程学检测...")
            se_findings = self.social_engineering_detector.scan(target)
        else:
            _p("\n📋 步骤 1.5/7: 文档社会工程学检测...（自引用模式：跳过）")
            se_findings = []
        for f in se_findings:
            all_findings.append({
                'rule_id': f['id'],
                'severity': f['severity'],
                'category': f.get('category', 'social_engineering'),
                'title': f['title'],
                'description': f.get('description', ''),
                'file_path': f['file'],
                'line_number': f.get('line', 0),
                'remediation': f.get('recommendation', '人工审查'),
                'source': 'social_engineering',
                'matched_line': f.get('matched_line', ''),
            })
        if se_findings:
            _p(f"   ⚠️  发现 {len(se_findings)} 个社会工程学问题")
            for f in se_findings[:5]:  # 只显示前 5 条
                sev_icon = {'CRITICAL': '⛔', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': 'ℹ️'}.get(f['severity'], 'ℹ️')
                _p(f"      {sev_icon} [{f['severity']}] {f['title']}")
            if len(se_findings) > 5:
                _p(f"      ... 还有 {len(se_findings) - 5} 条")
        else:
            _p("   ✅ 未发现社会工程学攻击模式")

        # 2. 去混淆检测 (v3.0 新增)
        if self.deobfuscator and not target.is_file() and self._should_run_engine("deobfuscation"):
            _p("\n📊 步骤 2/7: 去混淆检测...")
            deob_findings = self.deobfuscator.analyze_directory(target, path_filter=self.path_filter)
            for f in deob_findings:
                desc = f.description
                evidence_text = ''
                
                # v5.1: 将解码后的内容注入报告和 evidence
                if hasattr(f, 'decoded') and f.decoded and f.decoded.strip():
                    decoded_preview = f.decoded[:300]
                    desc += f"\n\n🔓 解码内容:\n```\n{decoded_preview}\n```"
                    evidence_text = decoded_preview
                
                all_findings.append({
                    'rule_id': f'DEOBF_{f.technique.upper()}',
                    'severity': f.severity,
                    'category': 'deobfuscation',
                    'title': f'混淆检测: {f.technique}',
                    'description': desc,
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'remediation': '审查混淆代码的真实意图',
                    'source': 'deobfuscation',
                    'evidence': evidence_text,
                    'decoded_content': getattr(f, 'decoded', ''),
                })
            _p(f"   发现 {len(deob_findings)} 个混淆问题")

        # 3. 静态分析
        if self._should_run_engine("static_analysis"):
            _p("\n📊 步骤 3/7: 静态分析...")
            if target.is_file():
                static_findings = self.static_analyzer.analyze_file(target)
            else:
                static_findings = self.static_analyzer.analyze_directory(target, recursive=True, path_filter=self.path_filter)

            for f in static_findings:
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
        else:
            static_findings = []
            _p("\n⏭️  跳过静态分析（快速模式）")

        # 4. AST 分析 (v3.0 新增)
        if self.ast_analyzer and not target.is_file() and self._should_run_engine("ast_analysis"):
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
        if self.dep_checker and not target.is_file() and self._should_run_engine("dependency_check"):
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
        # 6. 提示词注入探针 (v3.0 新增)
        if self.prompt_injection_tester and not target.is_file() and self._should_run_engine("prompt_injection") and not is_self:
            _p("\n📊 步骤 6/8: 提示词注入探针扫描...")
            pi_results = self.prompt_injection_tester.test_skill(target, path_filter=self.path_filter)
        elif is_self:
            _p("\n📊 步骤 6/8: 提示词注入探针扫描...（自引用模式：跳过）")
            pi_results = []
        else:
            pi_results = []
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
        if self.baseline_tracker and not target.is_file() and self._should_run_engine("baseline_change") and not is_self:
            _p("\n📊 步骤 7/8: 基线比对 (Rug-Pull 检测)...")
            has_changes, changes = self.baseline_tracker.check_changes(target.name, target)
        elif is_self:
            _p("\n📊 步骤 7/8: 基线比对 (Rug-Pull 检测)...（自引用模式：跳过）")
            has_changes, changes = False, []
        else:
            has_changes, changes = False, []
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
        if self.enable_semantic and self._should_run_engine("semantic_audit"):
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
        if self.entropy_analyzer and not target.is_file() and self._should_run_engine("entropy_analysis"):
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
        if self.hook_detector and not target.is_file() and self._should_run_engine("install_hook"):
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
        if self.network_profiler and not target.is_file() and self._should_run_engine("network_behavior"):
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
        if self.credential_theft_detector and not target.is_file() and self._should_run_engine("credential_theft"):
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

        # ─── v5.0: 跨层关联分析 ──────────────────────────────
        correlation_result = None
        if all_findings and not is_self:
            try:
                from correlation_engine import CorrelationEngine
                corr_engine = CorrelationEngine()
                correlation_result = corr_engine.analyze(all_findings)

                for cf in correlation_result.correlation_findings:
                    all_findings.append({
                        "rule_id": cf.rule_id,
                        "severity": cf.severity,
                        "category": f"correlation_{cf.chain_name}",
                        "title": cf.title,
                        "description": cf.description,
                        "file_path": str(target),
                        "remediation": "审查完整的攻击链模式",
                        "source": "correlation_engine",
                        "metadata": {
                            "chain_name": cf.chain_name,
                            "related_count": len(cf.related_findings),
                        },
                    })

                if correlation_result.attack_chains:
                    chain_names = [c.name for c in correlation_result.attack_chains]
                    _p(f"\n🔗 v5.0 关联分析: 检测到 {len(correlation_result.attack_chains)} 条攻击链: {', '.join(chain_names)}")
                else:
                    _p(f"\n🔗 v5.0 关联分析: 未检测到完整攻击链 (关联加成: +{correlation_result.correlation_score})")
            except ImportError:
                _p("\n⚠️  关联分析模块不可用，跳过")
            except Exception as e:
                _p(f"\n⚠️  关联分析失败: {e}")

        # ─── v5.0: 误报预过滤 + LLM 二次审查 ─────────────────
        llm_review_summary = None
        fp_filter_summary = None
        
        if all_findings:
            # 步骤 1: 误报预过滤（快速，不调用 LLM）
            if self.fp_filter:
                _p("\n🔍 v5.0 误报预过滤...")
                kept_findings, filter_results = self.fp_filter.filter_findings(all_findings)
                fp_filter_summary = self.fp_filter.get_filter_summary(filter_results)
                
                fp_count = fp_filter_summary['by_verdict'].get('FP', 0)
                uncertain_count = fp_filter_summary['by_verdict'].get('UNCERTAIN', 0)
                tp_count = fp_filter_summary['by_verdict'].get('TP', 0)
                
                _p(f"   预过滤: {len(all_findings)} 条发现 → "
                   f"{fp_count} 误报(已过滤) | {tp_count} 真实威胁 | {uncertain_count} 待LLM审查")
                
                all_findings = kept_findings
            else:
                _p("\n⚠️  误报预过滤器已禁用，跳过")
            
            # 步骤 2: LLM/SubAgent 审查（v6.0 — 基于 sessions_spawn，兼容全平台）
            llm_threshold = self._get_llm_review_threshold(all_findings)
            if self.enable_llm_review and self.llm_reviewer and all_findings and llm_threshold != "NEVER":
                _p("\n🤖 v6.0 SubAgent 智能审查...")
                try:
                    # Update reviewer with target info
                    self.llm_reviewer.target = target
                    self.llm_reviewer.skill_info = {
                        'name': getattr(self, '_skill_name', target.name),
                        'type': getattr(self, '_skill_type', 'unknown'),
                        'file_count': total_files,
                        'trust_score': getattr(self, '_trust_score', 50),
                    }
                    
                    # Review findings
                    reviews = self.llm_reviewer.review(all_findings, use_subagent=True)
                    
                    # Filter out FP findings
                    fp_count = sum(1 for r in reviews if r.verdict == 'FP')
                    tp_count = sum(1 for r in reviews if r.verdict == 'TP')
                    hr_count = sum(1 for r in reviews if r.verdict == 'HUMAN_REVIEW')
                    
                    _p(f"   审查结果: {len(all_findings)} 条 → "
                       f"{fp_count} 误报 | {tp_count} 真实威胁 | {hr_count} 需人工审查")
                    
                    # Keep only TP and HUMAN_REVIEW findings
                    fp_ids = {id(r.original_finding) for r in reviews if r.verdict == 'FP'}
                    all_findings = [f for f in all_findings if id(f) not in fp_ids]
                    
                    llm_review_summary = {
                        'total': len(reviews),
                        'fp': fp_count,
                        'tp': tp_count,
                        'human_review': hr_count,
                        'mode': self.llm_reviewer.mode,
                    }
                except Exception as e:
                    _p(f"   ⚠️  SubAgent 审查失败: {e}，使用预过滤结果")

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
            'scanner_version': '5.1.0',
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
            'llm_review': llm_review_summary,
            'fp_filter': fp_filter_summary,
            'skill_profile': asdict(self._skill_profile) if self._skill_profile else None,
            "correlation": {
                "chains_detected": len(correlation_result.attack_chains) if correlation_result else 0,
                "correlation_score": correlation_result.correlation_score if correlation_result else 0,
                "chain_names": [c.name for c in correlation_result.attack_chains] if correlation_result else [],
            } if correlation_result else None,
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
        'version': '5.0.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'X Skill Scanner',
                    'version': result.get('scanner_version', '5.0.0'),
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


# ─── Deep Analysis Review Task Builder ────────────────────────
def _build_deep_review_task(target_path: str, scan_result: Dict) -> Dict:
    """
    构造子 Agent 深度审查任务。
    
    当扫描结果为 HIGH/EXTREME 时，此函数生成一个结构化的 JSON 报告，
    包含所有关键发现和相关代码片段，供子 Agent 做最终误报/真实威胁判断。
    
    Returns:
        dict — 可直接作为 sessions_spawn task 参数的 JSON 对象
    """
    target = Path(target_path)
    risk_level = scan_result.get('risk_level', 'UNKNOWN')
    risk_score = scan_result.get('risk_score', 0)
    findings = scan_result.get('findings', [])
    
    # 提取高风险发现
    high_findings = [f for f in findings if f.get('severity', '').upper() in ('CRITICAL', 'HIGH')]
    
    # 读取关键文件内容（限制大小避免 token 爆炸）
    code_contexts = []
    max_file_size = 8192  # 每个文件最大 8KB
    
    # 优先读取有问题的文件
    seen_files = set()
    for finding in high_findings[:10]:  # 最多取前 10 个高危发现
        file_path = finding.get('file_path', '') or finding.get('file', '')
        if not file_path or file_path in seen_files:
            continue
        seen_files.add(file_path)
        
        fp = Path(file_path)
        if fp.exists() and fp.is_file():
            try:
                content = fp.read_text(encoding='utf-8', errors='replace')
                if len(content) > max_file_size:
                    # 截取发现问题附近的代码
                    line_num = finding.get('line', 0)
                    if line_num > 0:
                        lines = content.split('\n')
                        start = max(0, line_num - 20)
                        end = min(len(lines), line_num + 20)
                        content = '\n'.join(lines[start:end])
                        content = f'... (truncated, showing lines {start+1}-{end}) ...\n' + content
                    else:
                        content = content[:max_file_size] + '\n... (truncated)'
                
                rel_path = str(fp.relative_to(target)) if str(fp).startswith(str(target)) else file_path
                code_contexts.append({
                    'file': rel_path,
                    'content': content,
                    'finding_ref': finding.get('rule_id', finding.get('pattern_id', '')),
                    'line': finding.get('line', 0),
                })
            except Exception as e:
                code_contexts.append({
                    'file': file_path,
                    'content': f'[无法读取: {e}]',
                })
    
    # 如果没有找到具体文件，读取技能目录下的主要文件
    if not code_contexts and target.is_dir():
        for fname in ['SKILL.md', 'main.py', 'index.js', '__init__.py', 'app.py']:
            fp = target / fname
            if fp.exists():
                try:
                    content = fp.read_text(encoding='utf-8', errors='replace')
                    if len(content) > max_file_size:
                        content = content[:max_file_size] + '\n... (truncated)'
                    code_contexts.append({'file': fname, 'content': content})
                except Exception:
                    pass
    
    # 格式化发现摘要
    findings_summary = []
    for f in high_findings[:10]:
        findings_summary.append({
            'rule_id': f.get('rule_id', f.get('pattern_id', 'N/A')),
            'severity': f.get('severity', 'UNKNOWN'),
            'description': f.get('description', ''),
            'file': f.get('file_path', f.get('file', 'N/A')),
            'line': f.get('line', 0),
            'matched_code': f.get('matched_code', f.get('indicator', '')),
        })
    
    task_prompt = f"""🔒 技能安全深度审查任务

## 背景
扫描器对技能 `{target.name}` 进行了初步扫描，发现高风险问题。
需要你作为资深安全工程师进行人工审查，判断是否为误报。

## 初步扫描结果
- 风险等级：{risk_level}
- 风险分数：{risk_score}/100
- 高风险发现数量：{len(high_findings)}

## 关键发现
{json.dumps(findings_summary, indent=2, ensure_ascii=False)}

## 完整代码上下文
以下是被标记为有问题的文件的完整代码。请仔细阅读并判断每个发现的真实性。

"""
    
    for ctx in code_contexts:
        task_prompt += f"\n### 文件: {ctx['file']}\n"
        if ctx.get('finding_ref'):
            task_prompt += f"关联规则: {ctx['finding_ref']}"
        if ctx.get('line'):
            task_prompt += f" (第 {ctx['line']} 行附近)"
        task_prompt += f"\n```\n{ctx['content']}\n```\n"
    
    task_prompt += """
## 审查标准

### ✅ 判断为误报（FALSE_POSITIVE）的条件
1. 凭证从环境变量读取（`os.environ.get()`、`process.env`），不是硬编码
2. 发送到企业内网可信域名（如 `alibaba-inc.com`, `aliyun.com`, `antgroup-inc.cn`）
3. 是正常的 API 认证流程，没有额外的凭证窃取行为
4. 没有混淆、动态执行、反向 Shell 等恶意特征
5. 威胁情报匹配的是规则定义行或文档字符串，不是实际可执行代码
6. `.get('token')` / `.get('secret')` 是正常的数据访问模式，非凭证收集

### ⛔ 判断为真实威胁（TRUE_POSITIVE）的条件
1. 硬编码凭证在代码中（API key、password、secret 直接写在源码里）
2. 发送到未知外部服务器或 IP 地址（非企业可信域名）
3. 读取 SSH 密钥、浏览器 Cookie、系统凭证文件（Keychain、Credential Manager）
4. 使用 eval/exec/subprocess 执行动态生成的代码
5. 有社会工程学攻击（钓鱼提示、伪造系统对话框）
6. Base64/Hex 编码后执行的 payload
7. 反向 Shell 或持久化后门

## 输出格式

请输出以下 JSON 格式的最终判断：

```json
{
  "verdict": "FALSE_POSITIVE" | "TRUE_POSITIVE" | "UNCERTAIN",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "risk_level_override": "LOW" | "MEDIUM" | "HIGH" | "EXTREME" | null,
  "analysis": {
    "credential_source": "描述凭证来源（环境变量/硬编码/不存在的）",
    "network_targets": ["列出所有网络请求目标域名/IP"],
    "trusted_domains": ["识别出的可信企业域名"],
    "suspicious_patterns": ["真正可疑的模式，如果没有则空数组"],
    "fp_explanations": ["对每个误报发现的解释"]
  },
  "recommendation": "可安全安装" | "需要进一步调查" | "阻止安装",
  "reasoning": "详细的分析过程和理由"
}
```
"""
    
    return {
        "task": task_prompt,
        "metadata": {
            "skill_name": target.name,
            "scan_risk_level": risk_level,
            "scan_risk_score": risk_score,
            "high_finding_count": len(high_findings),
            "total_finding_count": len(findings),
            "code_context_files": len(code_contexts),
            "scanner_version": "5.3.0",
        }
    }


# ─── CLI 入口 ──────────────────────────────────────────────────
def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description='X Skill Scanner v5.0 - AI 技能安全扫描器',
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

    # 安装
    parser.add_argument('--install', action='store_true', help=argparse.SUPPRESS)  # 兼容旧参数
    parser.add_argument('--no-prompt', action='store_true',
                        help='跳过安装询问（CI/自动化模式）')
    parser.add_argument('--install-to', default=None,
                        help='安装目标目录（默认 ~/.openclaw/workspace/skills/）')

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
    parser.add_argument('--no-llm-review', action='store_true', help='跳过 LLM 审查（v5.0 默认启用）')
    parser.add_argument('--no-fp-filter', action='store_true', help='禁用误报预过滤器')
    parser.add_argument('--update-baseline', action='store_true', help='更新基线后退出')
    parser.add_argument('--profile-only', action='store_true', help='仅输出技能画像后退出')
    parser.add_argument('--deep-analysis', action='store_true', help='深度分析模式：输出结构化审查报告供子 Agent 消费')

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
    
    # v6.0: SubAgent 二次审查（默认启用，可用 --no-llm-review 禁用）
    if not args.no_llm_review:
        try:
            scanner.enable_llm_review = True
            scanner.llm_reviewer = SubAgentReviewer(
                target=Path(target_path) if Path(target_path).exists() else None,
                skill_info={}
            )
            _p("🤖 SubAgent 二次审查已启用（v6.0）")
        except Exception as e:
            _p(f"⚠️  SubAgent 审查初始化失败: {e}，将跳过审查")
            scanner.enable_llm_review = False
    else:
        _p("⚠️  LLM 二次审查已禁用")
    
    # v5.0: 误报预过滤器（默认启用）
    if args.no_fp_filter:
        scanner.fp_filter = None
        _p("⚠️  误报预过滤器已禁用")

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

    # v5.0: 画像专用模式
    if args.profile_only:
        from skill_profiler import SkillProfiler
        profiler = SkillProfiler()
        profile = profiler.profile(Path(target_path))
        output = json.dumps(asdict(profile), indent=2, ensure_ascii=False)
        sys.stdout.write(output)
        sys.stdout.write('\n')
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

    # ─── 交互式安装询问（默认启用） ──────────────────────
    if not args.no_prompt:
        risk_level = result.get('risk_level', 'UNKNOWN')
        risk_score = result.get('risk_score', 0)
        verdict = result.get('verdict', '')
        skill_name = Path(target_path).name

        _p(f"\n{'=' * 60}")
        _p(f"📦 技能: {skill_name}")
        _p(f"   风险等级: {risk_level} ({risk_score}/MAX_RISK_SCORE)")
        _p(f"   扫描结论: {verdict}")
        _p(f"{'=' * 60}")

        try:
            answer = input("\n是否安装此技能？[y/N]: ").strip().lower()
            if answer in ('y', 'yes'):
                from openclaw_config import get_openclaw_home
                default_skills_dir = get_openclaw_home() / 'workspace' / 'skills'
                install_dir_str = args.install_to or input(f"安装路径 [默认: {default_skills_dir}]: ").strip()
                install_dir = Path(install_dir_str) if install_dir_str else default_skills_dir
                install_dir.mkdir(parents=True, exist_ok=True)
                dest = install_dir / skill_name

                if dest.exists():
                    overwrite = input(f"⚠️  {dest} 已存在，是否覆盖？[y/N]: ").strip().lower()
                    if overwrite not in ('y', 'yes'):
                        _p("❌ 取消安装")
                        sys.exit(0)

                import shutil
                target_p = Path(target_path)
                if target_p.is_dir():
                    shutil.copytree(str(target_p), str(dest), dirs_exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(target_p), str(dest))

                _p(f"✅ 已安装到: {dest}")
                sys.exit(0)
            else:
                _p("❌ 取消安装")
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            _p("\n❌ 取消安装")
            sys.exit(0)

    # ─── Deep Analysis 模式：输出结构化审查任务 ──────────────
    if args.deep_analysis:
        risk_level = result.get('risk_level', 'UNKNOWN')
        risk_score = result.get('risk_score', 0)
        if risk_level in ('HIGH', 'EXTREME'):
            deep_report = _build_deep_review_task(target_path, result)
            report_dir = Path(__file__).parent.parent / 'reports'
            report_dir.mkdir(exist_ok=True)
            deep_path = report_dir / f"{Path(target_path).name}-deep-review.json"
            deep_path.write_text(json.dumps(deep_report, indent=2, ensure_ascii=False), encoding='utf-8')
            _p(f"\n🧠 深度审查任务已生成: {deep_path}")
            _p("   → 将此文件内容作为 sessions_spawn task 参数即可启动子 Agent 审查")

    # 根据风险等级设置退出码
    if result.get('risk_level') in ['EXTREME', 'HIGH']:
        sys.exit(1)
    elif result.get('risk_level') == 'MEDIUM':
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()