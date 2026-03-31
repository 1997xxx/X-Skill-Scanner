#!/usr/bin/env python3
"""
跨层关联分析引擎 v5.0
Correlation Engine for Multi-Layer Attack Chain Detection

功能：
- 检测跨引擎的关联发现（如静态分析+威胁情报+行为分析的组合）
- 识别完整攻击链（如：混淆 → 外联 C2 → 凭证窃取）
- 计算关联风险加成
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


@dataclass
class AttackChain:
    """攻击链定义"""
    name: str
    description: str
    required_patterns: List[str]  # 必须匹配的模式
    optional_patterns: List[str] = field(default_factory=list)  # 可选增强模式
    severity: str = "HIGH"


@dataclass
class CorrelationFinding:
    """关联分析产生的发现"""
    rule_id: str
    severity: str
    chain_name: str
    title: str
    description: str
    related_findings: List[Dict]


@dataclass
class CorrelationResult:
    """关联分析结果"""
    attack_chains: List[AttackChain]
    correlation_findings: List[CorrelationFinding]
    correlation_score: int  # 0-100
    correlation_summary: str


# 预定义攻击链模式
ATTACK_CHAINS = [
    AttackChain(
        name="C2_Infiltration",
        description="混淆代码 + 可疑网络连接 + 持久化机制",
        required_patterns=["obfuscation", "network_suspicious"],
        optional_patterns=["persistence", "encoding"],
        severity="CRITICAL",
    ),
    AttackChain(
        name="Credential_Harvest",
        description="凭证窃取 + 数据外传 + 可疑安装钩子",
        required_patterns=["credential_theft", "data_exfiltration"],
        optional_patterns=["install_hook", "keylogger"],
        severity="CRITICAL",
    ),
    AttackChain(
        name="Supply_Chain_Attack",
        description="恶意依赖 + 安装时执行 + 篡改检测",
        required_patterns=["malicious_dependency", "install_hook"],
        optional_patterns=["baseline_change", "typosquat"],
        severity="HIGH",
    ),
    AttackChain(
        name="Rug_Pull_Pattern",
        description="基线变更 + 可疑语义 + 时间炸弹",
        required_patterns=["baseline_change", "semantic_risk"],
        optional_patterns=["time_bomb", "obfuscation"],
        severity="HIGH",
    ),
    AttackChain(
        name="Prompt_Injection_Combined",
        description="提示词注入 + 输入处理 + 敏感操作",
        required_patterns=["prompt_injection", "dangerous_function"],
        optional_patterns=["user_input", "code_execution"],
        severity="HIGH",
    ),
    AttackChain(
        name="Reverse_Shell_Chain",
        description="反向shell + 网络外联 + 混淆",
        required_patterns=["reverse_shell", "network_connection"],
        optional_patterns=["obfuscation", "encoding"],
        severity="CRITICAL",
    ),
]


class CorrelationEngine:
    """
    跨层关联分析引擎
    检测不同扫描层之间的关联，识别完整攻击链
    """

    def __init__(self):
        self.attack_chains = ATTACK_CHAINS
        self.correlation_score = 0
        self.detected_chains: List[AttackChain] = []
        self.correlation_findings: List[CorrelationFinding] = []

    def analyze(self, findings: List[Dict]) -> CorrelationResult:
        """
        对所有发现进行关联分析

        Args:
            findings: 所有引擎的发现列表

        Returns:
            CorrelationResult 包含检测到的攻击链和关联发现
        """
        if not findings:
            return CorrelationResult(
                attack_chains=[],
                correlation_findings=[],
                correlation_score=0,
                correlation_summary="无发现，跳过关联分析"
            )

        # 按类别和来源分组
        findings_by_category = self._group_by_category(findings)
        findings_by_source = self._group_by_source(findings)

        # 检测攻击链
        self._detect_attack_chains(findings_by_category, findings_by_source)

        # 检测跨源关联（同一文件不同引擎的发现）
        self._detect_cross_source_correlations(findings)

        # 计算关联分数
        self._calculate_correlation_score()

        # 生成摘要
        summary = self._generate_summary()

        return CorrelationResult(
            attack_chains=self.detected_chains,
            correlation_findings=self.correlation_findings,
            correlation_score=self.correlation_score,
            correlation_summary=summary,
        )

    def _group_by_category(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """按类别分组发现"""
        groups = defaultdict(list)
        for f in findings:
            category = f.get('category', 'unknown')
            groups[category].append(f)
        return dict(groups)

    def _group_by_source(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """按来源引擎分组发现"""
        groups = defaultdict(list)
        for f in findings:
            source = f.get('source', 'unknown')
            groups[source].append(f)
        return dict(groups)

    def _detect_attack_chains(self, by_category: Dict[str, List[Dict]],
                              by_source: Dict[str, List[Dict]]):
        """检测预定义的攻击链模式"""
        # 构建特征集合
        features = set()

        # 从类别提取特征
        category_map = {
            'credential_theft': 'credential_theft',
            'prompt_injection': 'prompt_injection',
            'deobfuscation': 'obfuscation',
            'entropy_analysis': 'obfuscation',
            'install_hook': 'install_hook',
            'baseline_change': 'baseline_change',
            'network_behavior': 'network_suspicious',
            'threat_intel': 'threat_intel',
            'dependency': 'malicious_dependency',
        }

        for cat, findings_list in by_category.items():
            cat_lower = cat.lower()
            for key, feature in category_map.items():
                if key in cat_lower:
                    features.add(feature)

        # 从发现内容提取额外特征
        all_findings_list = []
        for fl in by_category.values():
            all_findings_list.extend(fl)
        for f in all_findings_list:
            desc = (f.get('description', '') + f.get('title', '')).lower()
            if any(kw in desc for kw in ['reverse shell', '/dev/tcp', 'bash -i']):
                features.add('reverse_shell')
            if any(kw in desc for kw in ['exfiltrat', 'upload', 'send to']):
                features.add('data_exfiltration')
            if any(kw in desc for kw in ['persist', 'cron', 'startup']):
                features.add('persistence')
            if any(kw in desc for kw in ['keylogg', 'keystroke']):
                features.add('keylogger')
            if any(kw in desc for kw in ['time bomb', 'timebomb', 'trigger date']):
                features.add('time_bomb')
            if any(kw in desc for kw in ['typosquat', 'typo-squat']):
                features.add('typosquat')

        # 检查每条攻击链
        for chain in self.attack_chains:
            matched_required = all(
                req in features for req in chain.required_patterns
            )
            if matched_required:
                self.detected_chains.append(chain)

                # 创建关联发现
                related = self._get_related_findings(chain, by_category)
                self.correlation_findings.append(CorrelationFinding(
                    rule_id=f"CORR_{chain.name.upper()}",
                    severity=chain.severity,
                    chain_name=chain.name,
                    title=f"攻击链检测: {chain.name}",
                    description=f"检测到 {chain.description}\n"
                               f"匹配模式: {', '.join(chain.required_patterns)}",
                    related_findings=related,
                ))

    def _get_related_findings(self, chain: AttackChain,
                              by_category: Dict[str, List[Dict]]) -> List[Dict]:
        """获取与攻击链相关的发现"""
        related = []
        seen_ids = set()

        # 关键词到类别的映射
        keyword_to_cats = {
            'obfuscation': ['deobfuscation', 'entropy_analysis', 'encoding'],
            'network_suspicious': ['network_behavior', 'network'],
            'credential_theft': ['credential_theft', 'CRED'],
            'prompt_injection': ['prompt_injection', 'PROMPT'],
            'install_hook': ['install_hook'],
            'baseline_change': ['baseline_change', 'BASELINE'],
        }

        for pattern in chain.required_patterns + chain.optional_patterns:
            cats = keyword_to_cats.get(pattern, [pattern])
            for cat, findings_list in by_category.items():
                for c in cats:
                    if c in cat.lower():
                        for f in findings_list:
                            fid = f.get('rule_id', '') + f.get('file_path', '')
                            if fid not in seen_ids:
                                related.append(f)
                                seen_ids.add(fid)

        return related[:10]  # 限制数量

    def _detect_cross_source_correlations(self, findings: List[Dict]):
        """检测同一文件在不同引擎中的关联发现"""
        # 按文件路径分组
        by_file = defaultdict(list)
        for f in findings:
            fp = f.get('file_path', 'unknown')
            by_file[fp].append(f)

        # 检查多引擎命中
        for fp, file_findings in by_file.items():
            if len(file_findings) < 2:
                continue

            sources = set(f.get('source', 'unknown') for f in file_findings)
            if len(sources) >= 3:  # 至少3个不同引擎命中
                severities = [f.get('severity', 'LOW') for f in file_findings]
                max_sev = self._max_severity(severities)

                # 检查是否已添加过该文件的关联发现
                already_added = any(
                    cf.rule_id.startswith("CORR_MULTI_") and
                    any(rf.get('file_path') == fp for rf in cf.related_findings)
                    for cf in self.correlation_findings
                )

                if not already_added:
                    self.correlation_findings.append(CorrelationFinding(
                        rule_id=f"CORR_MULTI_{len(self.correlation_findings)}",
                        severity=max_sev,
                        chain_name="Multi_Engine_Hit",
                        title=f"多引擎交叉确认: {fp.split('/')[-1]}",
                        description=f"该文件被 {len(sources)} 个引擎检测到问题:\n"
                                   f"引擎: {', '.join(sorted(sources))}\n"
                                   f"发现数: {len(file_findings)}",
                        related_findings=file_findings,
                    ))

    def _max_severity(self, severities: List[str]) -> str:
        """获取最大严重度"""
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        max_val = 0
        max_sev = "LOW"
        for s in severities:
            val = order.get(s.upper(), 0)
            if val > max_val:
                max_val = val
                max_sev = s.upper()
        return max_sev

    def _calculate_correlation_score(self):
        """计算关联风险分数 (0-100)"""
        score = 0

        # 攻击链贡献
        for chain in self.detected_chains:
            if chain.severity == "CRITICAL":
                score += 25
            elif chain.severity == "HIGH":
                score += 15
            else:
                score += 10

        # 关联发现贡献
        score += len(self.correlation_findings) * 5

        self.correlation_score = min(100, score)

    def _generate_summary(self) -> str:
        """生成关联分析摘要"""
        if not self.detected_chains:
            return f"未检测到完整攻击链，关联加成: +{self.correlation_score}"

        chain_names = [c.name for c in self.detected_chains]
        return f"检测到 {len(self.detected_chains)} 条攻击链: {', '.join(chain_names)}"


__all__ = ['CorrelationEngine', 'CorrelationResult', 'CorrelationFinding', 'AttackChain']
