# -*- coding: utf-8 -*-
"""
X Skill Scanner i18n - 多语言支持

Supported languages: zh (Chinese), en (English)
"""

class I18n:
    def __init__(self, lang='zh'):
        self.lang = lang
        self.translations = {
            # ─── Scan Start ──────────────────────────────────────
            'scan_start': {
                'zh': '🔍 X Skill Scanner 正在检测 {skill} 的安全性，请稍候...',
                'en': '🔍 X Skill Scanner is auditing {skill} for security risks, please wait...',
            },
            
            # ─── Risk Levels ──────────────────────────────────────
            'risk_level': {
                'zh': '风险等级',
                'en': 'Risk Level',
            },
            'risk_score': {
                'zh': '风险分数',
                'en': 'Risk Score',
            },
            'verdict': {
                'zh': '结论',
                'en': 'Verdict',
            },
            
            # ─── Verdicts ──────────────────────────────────────
            'do_not_install': {
                'zh': '❌ DO NOT INSTALL',
                'en': '❌ DO NOT INSTALL',
            },
            'caution_advised': {
                'zh': '⚠️  建议审查后安装',
                'en': '⚠️  Review before installing',
            },
            'safe_to_install': {
                'zh': '✅ 可安全安装',
                'en': '✅ Safe to install',
            },
            
            # ─── Scan Steps ──────────────────────────────────────
            'scan_step': {
                'zh': '步骤',
                'en': 'Step',
            },
            'threat_intel': {
                'zh': '威胁情报匹配',
                'en': 'Threat Intel Match',
            },
            'static_analysis': {
                'zh': '静态分析',
                'en': 'Static Analysis',
            },
            'social_engineering': {
                'zh': '社会工程学检测',
                'en': 'Social Engineering Detection',
            },
            'credential_theft': {
                'zh': '凭证窃取检测',
                'en': 'Credential Theft Detection',
            },
            
            # ─── Findings ──────────────────────────────────────
            'findings': {
                'zh': '详细发现',
                'en': 'Detailed Findings',
            },
            'location': {
                'zh': '位置',
                'en': 'Location',
            },
            'source': {
                'zh': '来源',
                'en': 'Source',
            },
            'fix': {
                'zh': '修复',
                'en': 'Fix',
            },
            
            # ─── Layer Results ──────────────────────────────────────
            'layer_results': {
                'zh': '各层检测结果',
                'en': 'Layer-by-Layer Results',
            },
            'clean': {
                'zh': '✅ 正常',
                'en': '✅ Clean',
            },
            'issues_found': {
                'zh': '⚠️  {count} 个问题',
                'en': '⚠️  {count} issues',
            },
            
            # ─── User-Friendly Templates ──────────────────────────────────────
            'safe_title': {
                'zh': '✅ {skill} 安全检测通过',
                'en': '✅ {skill} Passed Security Check',
            },
            'safe_conclusion': {
                'zh': '本次检测未发现安全隐患，可以放心使用。',
                'en': 'No security issues found. Safe to use.',
            },
            'risk_title': {
                'zh': '🔴 {skill} 发现安全风险',
                'en': '🔴 {skill} Security Risks Detected',
            },
            'risk_do_not_install': {
                'zh': '不建议直接安装或继续使用。',
                'en': 'DO NOT install or continue using.',
            },
            'risk_suggestions': {
                'zh': '**建议**：\n1. 先停用这个 skill\n2. 联系 skill 的开发者确认是否为正常行为\n3. 在确认安全前不要重新启用',
                'en': '**Recommendations**:\n1. Disable this skill immediately\n2. Contact the developer to verify\n3. Do not re-enable until confirmed safe',
            },
            'caution_title': {
                'zh': '⚠️  {skill} 需要留意',
                'en': '⚠️  {skill} Needs Attention',
            },
            'caution_message': {
                'zh': '这个 skill **没有发现明确的恶意行为**，但包含一些敏感功能。\n\n**建议**：如果你信任这个 skill 的来源，可以继续使用。如果不确定，建议先暂停使用。',
                'en': 'This skill **has no clear malicious behavior**, but contains sensitive capabilities.\n\n**Recommendation**: If you trust the source, you can continue using it. If unsure, consider pausing use.',
            },
            
            # ─── Footer ──────────────────────────────────────
            'footer': {
                'zh': '---\n**X Skill Scanner v6.3** by 吸音 | AI Agent 技能安全扫描器 | https://github.com/1997xxx/X-Skill-Scanner',
                'en': '---\n**X Skill Scanner v6.3** by Xi Yin | AI Agent Skill Security Scanner | https://github.com/1997xxx/X-Skill-Scanner',
            },
            
            # ─── Mode A (Batch Scan) ──────────────────────────────────────
            'mode_a_summary': {
                'zh': '🔍 Skill 安全扫描结果\n\n共扫描 {count} 个 Skill：',
                'en': '🔍 Skill Security Scan Results\n\nScanned {count} skills:',
            },
            'skill_name': {
                'zh': 'Skill 名称',
                'en': 'Skill Name',
            },
            'source_label': {
                'zh': '来源',
                'en': 'Source',
            },
            'detection_result': {
                'zh': '检测结果',
                'en': 'Detection Result',
            },
            'safe_result': {
                'zh': '✅ 未发现风险',
                'en': '✅ No risks found',
            },
            'caution_result': {
                'zh': '⚠️  需关注',
                'en': '⚠️  Needs attention',
            },
            'risk_result': {
                'zh': '🔴 发现风险',
                'en': '🔴 Risks detected',
            },
            'detail_section': {
                'zh': '\n## 🔴 高风险技能详情',
                'en': '\n## 🔴 High-Risk Skill Details',
            },
            'scan_complete': {
                'zh': '扫描完成',
                'en': 'Scan complete',
            },
        }
    
    def t(self, key, **kwargs):
        """Translate a key to current language"""
        if key not in self.translations:
            return key
        
        trans = self.translations[key].get(self.lang, self.translations[key].get('en', key))
        
        # Format with kwargs
        if kwargs:
            try:
                trans = trans.format(**kwargs)
            except KeyError:
                pass
        
        return trans
    
    def set_lang(self, lang):
        """Set language"""
        if lang in ('zh', 'zh-CN', 'zh-TW'):
            self.lang = 'zh'
        elif lang in ('en', 'en-US', 'en-GB'):
            self.lang = 'en'
        else:
            self.lang = lang
    
    def detect_lang(self, text):
        """Detect language from text"""
        if not text:
            return 'zh'
        
        # Check for Chinese characters
        import re
        if re.search(r'[\u4e00-\u9fff]', text):
            return 'zh'
        
        # Default to English for Latin script
        return 'en'


# Convenience function
_i18n = None

def get_i18n(lang='zh'):
    global _i18n
    if _i18n is None or _i18n.lang != lang:
        _i18n = I18n(lang)
    return _i18n

def t(key, **kwargs):
    """Translate using global i18n instance"""
    return get_i18n().t(key, **kwargs)