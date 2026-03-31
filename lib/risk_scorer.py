#!/usr/bin/env python3
"""
智能风险评分系统
Risk Scoring System
基于多维度因素计算风险分数 (0-100)
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    """风险等级 — v3.0 统一阈值 (与 scanner.py 一致)"""
    EXTREME = "EXTREME"  # 80-100
    HIGH = "HIGH"        # 50-79
    MEDIUM = "MEDIUM"    # 20-49
    LOW = "LOW"          # 5-19
    SAFE = "SAFE"        # 0-4


# 严重性权重 (P0-P3)
SEVERITY_WEIGHTS = {
    "CRITICAL": 30,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 1,
}

# 分类权重 (v3.2 新增威胁情报警示)
CATEGORY_WEIGHTS = {
    "CRED": 25,        # 凭证泄露 - 最高风险
    "PROMPT": 20,      # 提示词注入
    "MAL": 25,         # 恶意代码
    "DANGER": 15,      # 危险函数
    "SHELL": 25,       # Shell 注入
    "NETWORK": 20,     # 网络风险
    "FILE": 15,        # 文件操作
    "CODE": 10,        # 代码问题
    "TYPO": 5,         # Typosquatting
    "TIME": 20,        # 时间炸弹
    "ENCODING": 15,    # 编码混淆
    "INDIRECT": 15,    # 间接执行
    # v3.2 新增：威胁情报相关分类
    "THREAT": 30,      # 威胁情报匹配 - 最高优先级
    "CAMPAIGN": 25,    # 已知攻击活动
    "DEOBF": 20,       # 去混淆发现
    "BASELINE": 20,    # 基线变更 (Rug-Pull)
    "AST": 15,         # AST 分析发现
    "DEPENDENCY": 10,  # 依赖安全问题
}

# 风险因素调整 (v3.2 增强版)
RISK_MODIFIERS = {
    "has_credentials": 20,
    "has_network_access": 15,
    "has_file_write": 15,
    "has_exec_capability": 20,
    "has_obfuscation": 10,
    "has_self_modify": 15,
    "is_install_hook": 20,
    "has_external_deps": 5,
    # v3.2 新增：威胁情报相关
    "threat_intel_match": 30,     # 威胁情报匹配
    "known_malicious_name": 40,   # 已知恶意技能名
    "typosquat_detected": 25,     # Typosquat 检测
    "malicious_author": 20,       # 恶意作者
    "ioc_match": 35,              # IOC 匹配
    "campaign_pattern": 25,       # 攻击活动模式
}


@dataclass
class RiskFactor:
    """风险因素"""
    name: str
    weight: int
    description: str


class RiskScorer:
    """
    智能风险评分器
    
    计算公式:
    Base Score = Σ(Severity Weight) + Σ(Category Weight)
    Final Score = Base Score × Context Modifiers
    
    Risk Level:
    - EXTREME (90-100): 严重安全风险，需要立即处理
    - HIGH (70-89): 高风险，建议立即修复
    - MEDIUM (40-69): 中等风险，需要关注
    - LOW (20-39): 低风险，建议改进
    - SAFE (0-19): 无明显风险
    """
    
    def __init__(self):
        self.factors: List[RiskFactor] = []
        self._load_default_factors()
    
    def _load_default_factors(self):
        """加载默认风险因素"""
        for name, weight in RISK_MODIFIERS.items():
            self.factors.append(RiskFactor(
                name=name,
                weight=weight,
                description=f"检查是否存在 {name}"
            ))
    
    def calculate_score(
        self,
        findings: List[Dict],
        context: Optional[Dict] = None
    ) -> Dict:
        """
        计算风险分数
        
        Args:
            findings: 发现项列表
            context: 上下文信息
        
        Returns:
            包含 score, level, verdict, factors 的字典
        """
        if not findings:
            return {
                "score": 0,
                "level": "SAFE",
                "verdict": "✅ PASSED - No security issues detected",
                "factors": [],
                "breakdown": {}
            }
        
        # 基础分数计算
        base_score = 0
        severity_counts = {}
        category_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            category = finding.get('category', 'CODE')
            
            # 累加严重性权重
            base_score += SEVERITY_WEIGHTS.get(severity.upper(), 5)
            
            # 累加分类权重
            cat_prefix = category.split('_')[0] if '_' in category else category
            base_score += CATEGORY_WEIGHTS.get(cat_prefix, 5)
            
            # 统计计数
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # 上下文调整
        context_modifier = 1.0
        if context:
            if context.get("is_install_hook"):
                context_modifier *= 1.5
            if context.get("has_network_access"):
                context_modifier *= 1.2
            if context.get("has_credentials"):
                context_modifier *= 1.3
        
        # 计算最终分数 (上限 100)
        final_score = min(100, int(base_score * context_modifier))
        
        # 确定风险等级 — v3.0 统一阈值 (与 scanner.py 一致)
        if final_score >= 80:
            level = "EXTREME"
            verdict = "🚫 BLOCKED - Critical security risks detected"
        elif final_score >= 50:
            level = "HIGH"
            verdict = "⚠️ WARNING - High risk issues require attention"
        elif final_score >= 20:
            level = "MEDIUM"
            verdict = "⚡ CAUTION - Medium risk issues detected"
        elif final_score >= 5:
            level = "LOW"
            verdict = "✅ PASSED - Minor issues, mostly safe"
        else:
            level = "SAFE"
            verdict = "✅ PASSED - No significant security issues"
        
        return {
            "score": final_score,
            "level": level,
            "verdict": verdict,
            "breakdown": {
                "severity_counts": severity_counts,
                "category_counts": category_counts,
                "base_score": base_score,
                "context_modifier": context_modifier,
            }
        }
    
    def get_risk_details(self, score: int) -> Dict:
        """获取风险详情 — v3.0 统一阈值"""
        level = RiskLevel.SAFE
        
        if score >= 80:
            level = RiskLevel.EXTREME
        elif score >= 50:
            level = RiskLevel.HIGH
        elif score >= 20:
            level = RiskLevel.MEDIUM
        elif score >= 5:
            level = RiskLevel.LOW
        
        return {
            "level": level.value,
            "score": score,
            "description": self._get_level_description(level),
            "color": self._get_level_color(level),
            "recommendation": self._get_recommendation(level),
        }
    
    def _get_level_description(self, level: RiskLevel) -> str:
        """获取等级描述"""
        descriptions = {
            RiskLevel.EXTREME: "严重安全风险 - 可能导致凭证泄露、系统被控",
            RiskLevel.HIGH: "高风险 - 存在可被利用的安全漏洞",
            RiskLevel.MEDIUM: "中等风险 - 建议修复以提高安全性",
            RiskLevel.LOW: "低风险 - 轻微安全问题，可选择性修复",
            RiskLevel.SAFE: "安全 - 未检测到明显安全风险",
        }
        return descriptions.get(level, "未知风险等级")
    
    def _get_level_color(self, level: RiskLevel) -> str:
        """获取等级颜色 (用于终端输出)"""
        colors = {
            RiskLevel.EXTREME: "\033[91m",  # Red
            RiskLevel.HIGH: "\033[93m",     # Yellow
            RiskLevel.MEDIUM: "\033[33m",   # Orange
            RiskLevel.LOW: "\033[94m",      # Blue
            RiskLevel.SAFE: "\033[92m",     # Green
        }
        return colors.get(level, "\033[0m")
    
    def _get_recommendation(self, level: RiskLevel) -> str:
        """获取建议"""
        recommendations = {
            RiskLevel.EXTREME: "立即停止使用此 Skill，检查所有配置文件",
            RiskLevel.HIGH: "建议立即修复高危问题后再使用",
            RiskLevel.MEDIUM: "请评估风险后决定是否使用",
            RiskLevel.LOW: "可正常使用，建议关注后续更新",
            RiskLevel.SAFE: "安全使用，无须担心",
        }
        return recommendations.get(level, "无建议")


# 导出
__all__ = ['RiskScorer', 'RiskLevel', 'SEVERITY_WEIGHTS', 'CATEGORY_WEIGHTS', 'RISK_MODIFIERS']