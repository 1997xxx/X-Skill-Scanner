#!/usr/bin/env python3
"""
国际化支持 - Internationalization Support
支持多语言报告输出
"""

from typing import Dict, Optional
from enum import Enum


class Language(Enum):
    """支持的语言"""
    EN = "en"      # English
    ZH_CN = "zh-cn"  # 简体中文
    ZH_TW = "zh-tw"  # 繁體中文


# 翻译字典
TRANSLATIONS: Dict[Language, Dict[str, str]] = {
    Language.EN: {
        # 标题
        "report_title": "Skill Security Scan Report",
        "scan_summary": "Scan Summary",
        "findings_detail": "Detailed Findings",
        "risk_assessment": "Risk Assessment",
        
        # 基本信息
        "target": "Target",
        "scan_time": "Scan Time",
        "files_reviewed": "Files Reviewed",
        "total_findings": "Total Findings",
        "risk_score": "Risk Score",
        
        # 风险等级
        "risk_level": "Risk Level",
        "verdict": "Verdict",
        "EXTREME": "EXTREME",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "SAFE": "SAFE",
        
        # 严重性
        "severity": "Severity",
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Info",
        
        # 分类
        "category": "Category",
        "CRED": "Credential Exposure",
        "PROMPT": "Prompt Injection",
        "MAL": "Malicious Code",
        "DANGER": "Dangerous Function",
        "SHELL": "Shell Injection",
        "NETWORK": "Network Risk",
        "FILE": "File Operation",
        "CODE": "Code Issue",
        "TYPO": "Typosquatting",
        "TIME": "Time Bomb",
        "ENCODING": "Obfuscation",
        "INDIRECT": "Indirect Execution",
        
        # 裁决
        "verdict_blocked": "🚫 BLOCKED - Critical security risks detected",
        "verdict_warning": "⚠️ WARNING - High risk issues require attention",
        "verdict_caution": "⚡ CAUTION - Medium risk issues detected",
        "verdict_passed": "✅ PASSED - Minor issues, mostly safe",
        "verdict_safe": "✅ PASSED - No significant security issues",
        
        # 详细信息
        "location": "Location",
        "description": "Description",
        "remediation": "Remediation",
        "rule_id": "Rule ID",
        
        # 统计
        "findings_by_severity": "Findings by Severity",
        "findings_by_category": "Findings by Category",
        
        # 建议
        "recommendation": "Recommendation",
        "rec_extreme": "Immediately stop using this skill and review all configurations",
        "rec_high": "Fix high-risk issues before use",
        "rec_medium": "Evaluate risk before use",
        "rec_low": "Safe to use, recommend monitoring updates",
        "rec_safe": "Safe to use",
        
        # 错误
        "error_scan_failed": "Scan failed",
        "error_no_permission": "Permission denied",
        "error_file_not_found": "File not found",
    },
    
    Language.ZH_CN: {
        # 标题
        "report_title": "Skill 安全扫描报告",
        "scan_summary": "扫描概要",
        "findings_detail": "详细发现",
        "risk_assessment": "风险评估",
        
        # 基本信息
        "target": "目标",
        "scan_time": "扫描时间",
        "files_reviewed": "扫描文件数",
        "total_findings": "发现项总数",
        "risk_score": "风险分数",
        
        # 风险等级
        "risk_level": "风险等级",
        "verdict": "判定",
        "EXTREME": "极高风险",
        "HIGH": "高风险",
        "MEDIUM": "中等风险",
        "LOW": "低风险",
        "SAFE": "安全",
        
        # 严重性
        "severity": "严重性",
        "CRITICAL": "严重",
        "HIGH": "高",
        "MEDIUM": "中",
        "LOW": "低",
        "INFO": "信息",
        
        # 分类
        "category": "分类",
        "CRED": "凭证泄露",
        "PROMPT": "提示词注入",
        "MAL": "恶意代码",
        "DANGER": "危险函数",
        "SHELL": "Shell 注入",
        "NETWORK": "网络风险",
        "FILE": "文件操作",
        "CODE": "代码问题",
        "TYPO": "仿冒域名",
        "TIME": "时间炸弹",
        "ENCODING": "代码混淆",
        "INDIRECT": "间接执行",
        
        # 裁决
        "verdict_blocked": "🚫 拦截 - 检测到严重安全风险",
        "verdict_warning": "⚠️ 警告 - 高风险问题需要关注",
        "verdict_caution": "⚡ 注意 - 检测到中等风险",
        "verdict_passed": "✅ 通过 - 存在轻微问题，整体安全",
        "verdict_safe": "✅ 通过 - 未发现明显安全问题",
        
        # 详细信息
        "location": "位置",
        "description": "描述",
        "remediation": "修复建议",
        "rule_id": "规则 ID",
        
        # 统计
        "findings_by_severity": "按严重性分类",
        "findings_by_category": "按分类统计",
        
        # 建议
        "recommendation": "建议",
        "rec_extreme": "立即停止使用此 Skill，检查所有配置文件",
        "rec_high": "建议立即修复高危问题后再使用",
        "rec_medium": "请评估风险后决定是否使用",
        "rec_low": "可正常使用，建议关注后续更新",
        "rec_safe": "安全使用，无须担心",
        
        # 错误
        "error_scan_failed": "扫描失败",
        "error_no_permission": "权限不足",
        "error_file_not_found": "文件未找到",
    },
    
    Language.ZH_TW: {
        # 標題
        "report_title": "Skill 安全掃描報告",
        "scan_summary": "掃描概要",
        "findings_detail": "詳細發現",
        "risk_assessment": "風險評估",
        
        # 基本資訊
        "target": "目標",
        "scan_time": "掃描時間",
        "files_reviewed": "掃描檔案數",
        "total_findings": "發現項總數",
        "risk_score": "風險分數",
        
        # 風險等級
        "risk_level": "風險等級",
        "verdict": "判定",
        "EXTREME": "極高風險",
        "HIGH": "高風險",
        "MEDIUM": "中等風險",
        "LOW": "低風險",
        "SAFE": "安全",
        
        # 嚴重性
        "severity": "嚴重性",
        "CRITICAL": "嚴重",
        "HIGH": "高",
        "MEDIUM": "中",
        "LOW": "低",
        "INFO": "資訊",
        
        # 分類
        "category": "分類",
        "CRED": "憑證洩露",
        "PROMPT": "提示詞注入",
        "MAL": "惡意程式碼",
        "DANGER": "危險函數",
        "SHELL": "Shell 注入",
        "NETWORK": "網路風險",
        "FILE": "檔案操作",
        "CODE": "程式碼問題",
        "TYPO": "仿冒網域",
        "TIME": "時間炸彈",
        "ENCODING": "程式碼混淆",
        "INDIRECT": "間接執行",
        
        # 裁決
        "verdict_blocked": "🚫 攔截 - 偵測到嚴重安全風險",
        "verdict_warning": "⚠️ 警告 - 高風險問題需要關注",
        "verdict_caution": "⚡ 注意 - 偵測到中等風險",
        "verdict_passed": "✅ 通過 - 存在輕微問題，整體安全",
        "verdict_safe": "✅ 通過 - 未發現明顯安全問題",
        
        # 詳細資訊
        "location": "位置",
        "description": "描述",
        "remediation": "修復建議",
        "rule_id": "規則 ID",
        
        # 統計
        "findings_by_severity": "按嚴重性分類",
        "findings_by_category": "按分類統計",
        
        # 建議
        "recommendation": "建議",
        "rec_extreme": "立即停止使用此 Skill，檢查所有設定檔",
        "rec_high": "建議立即修復高危問題後再使用",
        "rec_medium": "請評估風險後決定是否使用",
        "rec_low": "可正常使用，建議關注後續更新",
        "rec_safe": "安全使用，無須擔心",
        
        # 錯誤
        "error_scan_failed": "掃描失敗",
        "error_no_permission": "權限不足",
        "error_file_not_found": "檔案未找到",
    },
}


class I18n:
    """
    国际化管理器
    
    用法:
        i18n = I18n()
        i18n.set_language("zh-cn")  # 设置语言
        
        # 翻译
        print(i18n.t("report_title"))  # 输出: Skill 安全扫描报告
        print(i18n.t("risk_score"))    # 输出: 风险分数
    """
    
    def __init__(self, lang: Optional[str] = None):
        self.current_lang = Language.EN
        
        if lang:
            self.set_language(lang)
    
    def set_language(self, lang: str) -> bool:
        """
        设置语言
        
        Args:
            lang: 语言代码 ("en", "zh-cn", "zh-tw")
        
        Returns:
            是否设置成功
        """
        lang_lower = lang.lower().replace("_", "-")
        
        for language in Language:
            if language.value == lang_lower:
                self.current_lang = language
                return True
        
        return False
    
    def t(self, key: str, **kwargs) -> str:
        """
        翻译 key
        
        Args:
            key: 翻译 key
            **kwargs: 格式化参数
        
        Returns:
            翻译后的文本
        """
        translations = TRANSLATIONS.get(self.current_lang, TRANSLATIONS[Language.EN])
        text = translations.get(key, key)
        
        if kwargs:
            try:
                return text.format(**kwargs)
            except (KeyError, ValueError):
                return text
        
        return text
    
    def get_available_languages(self) -> Dict[str, str]:
        """获取支持的语言列表"""
        return {
            "en": "English",
            "zh-cn": "简体中文",
            "zh-tw": "繁體中文",
        }


# 便捷函数
_i18n_instance = I18n()


def set_lang(lang: str) -> bool:
    """设置全局语言"""
    return _i18n_instance.set_language(lang)


def t(key: str) -> str:
    """翻译 key (全局)"""
    return _i18n_instance.t(key)


def get_langs() -> Dict[str, str]:
    """获取支持的语言"""
    return _i18n_instance.get_available_languages()


# 导出
__all__ = ['I18n', 'Language', 'TRANSLATIONS', 'set_lang', 't', 'get_langs']