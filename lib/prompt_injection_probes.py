#!/usr/bin/env python3
"""
提示词注入测试探针 v1.0
Prompt Injection Test Probes

检测技能是否容易受到提示词注入攻击：
- 系统提示词覆盖
- 角色劫持
- 指令注入
- 上下文泄漏
- DAN/Jailbreak 模式

基于 AgentSeal 225+ 探针和 OWASP Top 10 for LLM 分类。
"""

import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ProbeResult:
    """探针结果"""
    probe_id: str
    category: str
    severity: str
    description: str
    matched_text: str = ""
    confidence: float = 0.8


# ─── 探针数据库 ──────────────────────────────────────────────
PROMPT_INJECTION_PROBES = [
    # === 系统提示词覆盖 ===
    {
        'id': 'PI_001',
        'category': 'system_override',
        'severity': 'CRITICAL',
        'pattern': r'(?i)(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above|earlier|initial)\s+(?:instructions?|prompts?|directives?|rules?|commands?)',
        'description': '尝试忽略/忘记先前指令',
    },
    {
        'id': 'PI_002',
        'category': 'system_override',
        'severity': 'CRITICAL',
        'pattern': r'(?i)(?:you\s+are\s+now|from\s+now\s+on|henceforth|starting\s+now)\s+(?:a|an|the)',
        'description': '角色重新定义 — 试图覆盖 AI 身份',
    },
    {
        'id': 'PI_003',
        'category': 'system_override',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:new\s+system\s+prompt|system\s*:\s*\[|<\|system\|>|<\|im_start\|>system)',
        'description': '模拟系统提示词格式',
    },
    {
        'id': 'PI_004',
        'category': 'system_override',
        'severity': 'CRITICAL',
        'pattern': r'(?i)override\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)',
        'description': '显式要求覆盖系统提示词',
    },

    # === 角色劫持 ===
    {
        'id': 'PI_010',
        'category': 'role_hijack',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:act\s+as|pretend\s+to\s+be|roleplay\s+as|simulate\s+being)\s+(?:a\s+)?(?:developer|admin|administrator|system|root|owner|creator)',
        'description': '冒充开发者/管理员角色',
    },
    {
        'id': 'PI_011',
        'category': 'role_hijack',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:I\s+am\s+your\s+(?:creator|developer|owner|maker|programmer)|this\s+is\s+a\s+(?:test|debug|development)\s+mode)',
        'description': '声称是创建者/开发者以获取特权',
    },
    {
        'id': 'PI_012',
        'category': 'role_hijack',
        'severity': 'MEDIUM',
        'pattern': r'(?i)(?:debug\s+mode|developer\s+mode|test\s+mode|safe\s+mode\s+off)',
        'description': '尝试启用调试/开发模式',
    },

    # === DAN / Jailbreak ===
    {
        'id': 'PI_020',
        'category': 'jailbreak',
        'severity': 'CRITICAL',
        'pattern': r'(?i)\bDAN\b.*(?:do\s+anything\s+now|mode|protocol)',
        'description': 'DAN (Do Anything Now) 越狱模式',
    },
    {
        'id': 'PI_021',
        'category': 'jailbreak',
        'severity': 'CRITICAL',
        'pattern': r'(?i)(?:hypothetical|fictional|imaginary|simulated)\s+(?:scenario|response|answer)',
        'description': '假设场景绕过 — 通过虚构情境规避安全限制',
    },
    {
        'id': 'PI_022',
        'category': 'jailbreak',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:no\s+ethical|without\s+restrictions|unfiltered|uncensored|unrestricted)',
        'description': '要求无限制/无伦理约束的响应',
    },
    {
        'id': 'PI_023',
        'category': 'jailbreak',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:step[-\s]?by[-\s]?step\s+reasoning|chain\s+of\s+thought|think\s+out\s+loud|show\s+your\s+work)',
        'description': '强制暴露推理过程',
    },

    # === 指令注入 ===
    {
        'id': 'PI_030',
        'category': 'instruction_injection',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:execute|run|perform)\s+(?:the\s+)?(?:following\s+)?(?:command|code|script|task)',
        'description': '命令执行注入',
    },
    {
        'id': 'PI_031',
        'category': 'instruction_injection',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:send|post|upload|transfer|exfiltrate)\s+(?:the\s+)?(?:following\s+)?(?:data|file|content|information)',
        'description': '数据外传注入',
    },
    {
        'id': 'PI_032',
        'category': 'instruction_injection',
        'severity': 'CRITICAL',
        'pattern': r'(?i)(?:read|access|retrieve|fetch|extract)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:file|memory|config|database|credentials?)',
        'description': '敏感数据读取注入',
    },
    {
        'id': 'PI_033',
        'category': 'instruction_injection',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:delete|remove|erase|destroy|wipe)\s+(?:the\s+)?(?:following\s+)?(?:file|data|record|log|history)',
        'description': '数据删除注入',
    },

    # === 上下文泄漏 ===
    {
        'id': 'PI_040',
        'category': 'context_leak',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:repeat|output|print|return|show)\s+(?:the\s+)?(?:above|previous|first|initial|original)\s+(?:text|message|prompt|instructions?)',
        'description': '尝试重复/泄露原始提示词',
    },
    {
        'id': 'PI_041',
        'category': 'context_leak',
        'severity': 'CRITICAL',
        'pattern': r'(?i)(?:what\s+are\s+your\s+|tell\s+me\s+your\s+|reveal\s+your\s+)(?:instructions?|rules?|system\s+prompt|guidelines?|constraints?)',
        'description': '直接询问系统指令/规则',
    },
    {
        'id': 'PI_042',
        'category': 'context_leak',
        'severity': 'HIGH',
        'pattern': r'(?i)(?:encode|base64|hex|rot13|cipher)\s+(?:the\s+)?(?:above|previous|entire)\s+(?:conversation|prompt|text|message)',
        'description': '通过编码方式泄露对话内容',
    },
    {
        'id': 'PI_043',
        'category': 'context_leak',
        'severity': 'MEDIUM',
        'pattern': r'(?i)(?:summarize|translate|rewrite|rephrase)\s+(?:the\s+)?(?:entire|full|complete|above)\s+(?:conversation|dialogue|chat|prompt)',
        'description': '通过转换操作间接泄露上下文',
    },

    # === Markdown/HTML 注入 ===
    {
        'id': 'PI_050',
        'category': 'format_injection',
        'severity': 'MEDIUM',
        'pattern': r'<\s*(?:script|img|iframe|object|embed|svg)\b',
        'description': 'HTML 标签注入',
    },
    {
        'id': 'PI_051',
        'category': 'format_injection',
        'severity': 'LOW',
        'pattern': r'\[[^\]]*\]\(javascript:',
        'description': 'Markdown JavaScript 协议注入',
    },
]


class PromptInjectionTester:
    """提示词注入测试器 — v3.7 优化：排除规则定义上下文"""

    def __init__(self):
        self.probes = PROMPT_INJECTION_PROBES

    @staticmethod
    def _is_rule_definition_line(line: str) -> bool:
        """判断一行是否处于规则定义上下文中（非实际注入漏洞）"""
        stripped = line.strip()
        markers = [
            r'"?pattern"?\s*[:=]', r'"?regex"?\s*[:=]',
            r'"?indicator"?\s*[:=]', r'"name"\s*:',
            r'"description"\s*:', r'"severity"\s*:',
            r'rules\s*:', r'THREAT_PATTERNS',
            r'r["\']',
            r'"reason"\s*:',          # JSON reference data (high-risk-skills.json)
            r'"category"\s*:',        # JSON category field
        ]
        return any(re.search(m, stripped, re.IGNORECASE) for m in markers)

    @staticmethod
    def _is_json_data_file(file_path: Path) -> bool:
        """判断文件是否为 JSON 参考数据文件"""
        if file_path.suffix.lower() != '.json':
            return False
        fname_lower = file_path.name.lower()
        patterns = ['high-risk-skills', 'malicious', 'known-', 'threat-', 'ioc',
                     'blocklist', 'blacklist', 'whitelist', 'reference', 'database']
        return any(p in fname_lower for p in patterns)

    def test_skill(self, dir_path: Path, path_filter=None) -> List[ProbeResult]:
        """扫描技能文件中的提示词注入模式"""
        from path_filter import PathFilter as PF
        pf = path_filter or PF()
        results = []

        for fp in dir_path.rglob('*'):
            if not fp.is_file():
                continue
            if fp.suffix.lower() not in ('.py', '.js', '.ts', '.md', '.yaml', '.yml', '.json', '.txt'):
                continue
            if pf.should_ignore(fp, dir_path):
                continue

            try:
                content = fp.read_text(encoding='utf-8')
            except Exception:
                continue

            # 优化：JSON 参考数据文件直接跳过（包含大量恶意技能描述文本）
            if self._is_json_data_file(fp):
                continue
            
            fname_lower = fp.name.lower()
            is_security_tool = any(kw in fname_lower for kw in ['scanner', 'analyzer', 'detector', 'audit', 'security'])

            for probe in self.probes:
                for match in re.finditer(probe['pattern'], content):
                    # 获取匹配位置所在行
                    pos = match.start()
                    line_start = content.rfind('\n', 0, pos) + 1
                    matched_line = content[line_start:content.find('\n', pos)].strip()
                    
                    # 跳过规则定义上下文
                    if is_security_tool and self._is_rule_definition_line(matched_line):
                        continue
                    
                    results.append(ProbeResult(
                        probe_id=probe['id'],
                        category=probe['category'],
                        severity=probe['severity'],
                        description=f'{probe["description"]} (in {fp.name})',
                        matched_text=match.group(0)[:100],
                        confidence=0.75,
                    ))

        return results

    def get_categories(self) -> Dict[str, int]:
        """获取探针类别统计"""
        cats = {}
        for p in self.probes:
            cat = p['category']
            cats[cat] = cats.get(cat, 0) + 1
        return cats
