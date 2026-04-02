#!/usr/bin/env python3
"""
False Positive Pre-Filter v5.0 — 误报预过滤器

设计理念：
- 在 LLM 审查前自动过滤明显误报
- 减少 LLM 调用次数，降低成本
- 基于上下文感知的规则匹配

工作流程：
1. 检查发现项是否匹配已知误报模式
2. 如果是安全工具自引用 → 标记 FP
3. 如果是参考数据/文档 → 标记 FP
4. 如果匹配真实威胁模式 → 标记 TP
5. 不确定的 → 交给 LLM 审查
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class FilterResult:
    """过滤结果"""
    finding: Dict
    verdict: str              # FP / TP / UNCERTAIN
    confidence: float         # 0.0-1.0
    reason: str               # 为什么这样判断


# ─── 误报模式库 ────────────────────────────────────────────────
FALSE_POSITIVE_PATTERNS = [
    # 0. 安全工具自引用（最高优先级）
    {
        'name': 'security_tool_self_reference',
        'description': '安全工具自身的代码中包含安全关键词（规则定义、检测逻辑、测试数据）',
        'conditions': {
            'file_patterns': [
                r'[/\\]lib$', r'[/\\]lib[/\\]', r'^lib/?$',  # 目录和文件
                r'scanner\.py', r'static_analyzer\.py', r'threat_intel\.py',
                r'deobfuscator\.py', r'ast_analyzer\.py', r'baseline\.py',
                r'dependency_checker\.py', r'path_filter\.py',
                r'prompt_injection.*\.py', r'entropy_analyzer\.py',
                r'install_hook_detector\.py', r'network_profiler\.py',
                r'credential_theft_detector\.py', r'llm_reviewer\.py',
                r'semantic_auditor\.py', r'risk_scorer\.py',
                r'whitelist\.py', r'reporter\.py', r'shield_monitor\.py',
                r'fp_filter\.py', r'skill_profiler\.py',
                r'models\.py', r'i18n/.*\.py', r'hooks/.*\.py',
                r'rules/.*\.yaml', r'rules/.*\.json', r'config/.*\.json',
                r'data/.*\.json', r'lib/.*_detector\.py',
                r'lib/.*_analyzer\.py', r'lib/.*_checker\.py',
                r'\.semantic_cache\.json', r'threat_intel\.json',
            ],
            'content_patterns': [
                # IOC 域名在安全工具代码中是规则定义，不是实际连接
                r'(?:glot\.io|rentry\.co|pastebin\.com|webhook\.site)',
                r'(?:reverse.?shell|backdoor|exfiltrat|malicious)',
                r'(?:osascript|password|credential|ssh.*key)',
                r'(?:/dev/tcp|xmrig|cryptonight)',
                r'(?:patterns\s*:\s*\[|"patterns"\s*:\s*\[)',
                r'(?:rule_id.*severity|cwe\s*:)',
                r'(?:remediation\s*:|检测.*风险)',
                # IOC 匹配描述文本（扫描器自身产生的发现）
                r'(?:已知.*恶意指标|IOC.*匹配|载荷托管域|C2 服务器)',
                # 攻击模式匹配描述（threat_intel 产生的发现）
                r'(?:攻击模式匹配|Collects and exfiltrates|Manipulates agent)',
                # SkillJect 执行链检测
                r'(?:SkillJect.*执行链|远程脚本直接执行|动态代码执行.*eval|动态代码执行.*exec)',
                # 提示词注入探针结果
                r'(?:提示词注入|prompt.?injection|system.?override)',
                # 去混淆检测结果（安全工具自身的去混淆规则/测试数据）
                r'(?:混淆检测|tr39_confusables|string_concat_obfuscat)',
                # 凭证窃取检测规则引用
                r'(?:SSH.*私钥.*路径|读取敏感凭证|打包压缩并上传|Cookie 读取)',
                r'(?:localStorage|sessionStorage|Firefox.*登录)',
                r'(?:Discord Webhook|C2 通信特征|隐蔽信道)',
                # 网络画像结果
                r'(?:疑似数据外传|疑似隐蔽信道|Reverse Connection|C2 Beacon)',
                # AST 分析结果
                r'(?:子进程执行|Lambda 中包含危险操作)',
                # 安装钩子检测
                r'(?:用户目录扫描|Post-Install Hook)',
                # 静态分析中的规则引用
                r'(?:系统命令执行|Python eval/exec|Auxiliary Script Execution)',
                r'(?:反向 Shell|Suspicious HTTP Request)',
                # LLM reviewer 系统提示中的攻击描述（文档性质）
                r'(?:\d+\.\s+\*\*.*(?:网络外传|凭证窃取|反向 Shell|社会工程|持久化|混淆))',
                r'(?:curl POST|requests\.post.*外部 URL)',
                r'(?:~/.ssh/id_rsa.*上传|浏览器密码数据库)',
                r'(?:cron job.*bashrc|Base64 编码.*payload)',
                # Prompt injection probes（探针定义本身包含越狱文本）
                r'(?:DAN.*Do Anything Now|越狱模式|无限制.*伦理约束)',
                r'(?:忽略.*先前指令|forget.*previous)',
                # 文件路径引用（代码中的路径常量，非实际访问）
                r'(?:["\']~/(?:\.bashrc|\.zshrc|\.profile)["\'])',
                r'(?:["\']key4\.db["\'])',
                # 浏览器数据窃取描述
                r'(?:页面全文内容读取|document\.body\.innerText)',
            ],
            'context_required': False,  # 安全工具目录下的文件直接标记
        },
        'confidence': 0.98,
    },
    
    # 1. 安全工具自身的规则定义
    {
        'name': 'security_tool_rules',
        'description': '安全扫描器的规则定义',
        'conditions': {
            'file_patterns': [r'rules/.*\.yaml', r'rules/.*\.json', r'config/.*\.json',
                            r'data/.*\.json'],
            'content_patterns': [
                r'patterns\s*:\s*\[',           # YAML 规则列表
                r'"patterns"\s*:\s*\[',          # JSON 规则列表
                r'rule_id.*severity',            # 规则定义结构
                r'cwe\s*:',                      # CWE 引用
                r'remediation\s*:',              # 修复建议
            ],
            'context_required': True,  # 需要同时匹配文件模式和内容模式
        },
        'confidence': 0.95,
    },
    
    # 2. 参考数据文件（威胁情报、IOC 列表等）
    {
        'name': 'reference_data',
        'description': '参考数据文件（恶意技能列表、IOC 等）',
        'conditions': {
            'file_patterns': [r'threat_intel\.json', r'baseline\.json', r'whitelist\.json',
                            r'malicious.*\.json', r'ioc.*\.json', r'known_.*\.json'],
            'content_patterns': [
                r'"malicious_skills"',
                r'"ioc_domains"',
                r'"known_bad"',
                r'"attack_patterns"',
                r'"description"\s*:\s*"(?:known|malicious|suspicious)',
            ],
            'context_required': True,
        },
        'confidence': 0.95,
    },
    
    # 3. 安全审计/修复脚本
    {
        'name': 'security_audit_scripts',
        'description': '安全检查/修复脚本',
        'conditions': {
            'file_patterns': [r'audit\.py', r'check.*\.sh', r'security.*\.py',
                            r'hardening.*\.sh', r'fix.*\.py', r'verify.*\.sh'],
            'content_patterns': [
                r'check\s+(?:file\s+)?permissions',
                r'verify\s+configuration',
                r'audit\s+security',
                r'chmod\s+(?:700|600|500)',    # 安全加固
                r'find\s+.*-name\s+["\']\.env', # 统计 .env 文件
                r'ls\s+-la\s+\.ssh',            # 检查 SSH 目录
            ],
            'context_required': True,
        },
        'confidence': 0.90,
    },
    
    # 4. 文档中的关键词（README、SKILL.md 描述功能）
    {
        'name': 'documentation_keywords',
        'description': '文档中的安全关键词（正常描述）',
        'conditions': {
            'file_patterns': [r'README\.md', r'SKILL\.md', r'CONTRIBUTING\.md',
                            r'SECURITY\.md', r'CHANGELOG\.md', r'.*\.md$'],
            'content_patterns': [
                r'^\s*[-*]\s+(?:detect|check|scan|prevent|protect)',  # 功能列表
                r'^>\s+',                     # 引用块（描述）
                r'^\s*###?\s+',               # 标题
                r'\|.*\|.*\|',                # 表格
            ],
            'context_required': True,
        },
        'confidence': 0.85,
    },
    
    # 5. 安全的安装钩子
    {
        'name': 'safe_install_hooks',
        'description': '安全的安装钩子',
        'conditions': {
            'file_patterns': [r'package\.json'],
            'content_patterns': [
                r'postinstall\s*:\s*["\']agent-skill-installer',
                r'postinstall\s*:\s*["\']openclaw-skill-installer',
                r'postinstall\s*:\s*["\']npm\s+install',
                r'postinstall\s*:\s*["\']node\s+',
            ],
            'context_required': True,
        },
        'confidence': 0.90,
    },
    
    # 6. Echo/Print 语句中的关键词
    {
        'name': 'echo_print_keywords',
        'description': 'Echo/Print 语句中的安全关键词',
        'conditions': {
            'file_patterns': [r'.*\.sh$', r'.*\.bash$'],
            'content_patterns': [
                r'echo\s+.*(?:secret|token|password|key)',
                r'printf\s+.*(?:secret|token|password|key)',
                r'print_row.*(?:secret|token|password|key)',
            ],
            'context_required': True,
        },
        'confidence': 0.80,
    },
    
    # 7. 测试文件
    {
        'name': 'test_files',
        'description': '测试文件中的安全关键词',
        'conditions': {
            'file_patterns': [r'test.*\.py', r'test.*\.sh', r'.*_test\.py',
                            r'spec.*\.js', r'tests/.*'],
            'content_patterns': [
                r'def\s+test_',
                r'assert\s+',
                r'mock\s+',
                r'@pytest\.fixture',
            ],
            'context_required': True,
        },
        'confidence': 0.85,
    },
    
    # 8. 审计报告中的描述文本
    {
        'name': 'audit_report_text',
        'description': '审计报告中的描述文字',
        'conditions': {
            'file_patterns': [r'report.*\.py', r'result.*\.py', r'output.*\.py'],
            'content_patterns': [
                r'["\']risk["\']\s*:\s*["\']',
                r'["\']severity["\']\s*:\s*["\']',
                r'["\']description["\']\s*:\s*["\']',
                r'generate.*report',
                r'format.*output',
            ],
            'context_required': True,
        },
        'confidence': 0.85,
    },
]

# ─── 真实威胁模式（不应被过滤）──────────────────────────────────
TRUE_POSITIVE_INDICATORS = [
    # 实际的网络外传
    {
        'name': 'actual_exfiltration',
        'patterns': [
            r'requests\.(?:post|put)\s*\([^)]*(?:secret|password|token|key|credential)',
            r'curl\s+.*-X\s+POST.*(?:secret|password|token|key)',
            r'urllib\.request\.urlopen\s*\([^)]*(?:secret|password|token|key)',
            r'socket\.send\s*\([^)]*(?:secret|password|token|key)',
        ],
        'description': '实际发送敏感数据到外部',
    },
    
    # 真实的凭证窃取
    {
        'name': 'credential_theft',
        'patterns': [
            r'open\s*\(\s*["\'][^"\']*\.ssh/id_rsa',
            r'(?:read|open)\s*\(\s*["\'][^"\']*\.aws/credentials',
            r'osascript\s+.*display\s+dialog\s+.*password',
            r'security\s+find-generic-password',
            r'chrome.*Login\s+Data',
            r'firefox.*logins\.json',
        ],
        'description': '实际读取敏感凭证文件',
    },
    
    # 反向 Shell / C2
    {
        'name': 'reverse_shell',
        'patterns': [
            r'(?:^|\n)\s*bash\s+-i\s+>&\s*/dev/tcp/',  # 实际执行，非字符串引用
            r'(?:^|\n)\s*nc\s+-e\s*/bin/(?:ba)?sh',
            r'socket\.connect\s*\(\s*["\']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'subprocess.*bash\s+-i',
            r'os\.system.*bash\s+-i',
        ],
        'description': '反向 Shell 或 C2 连接',
    },
    
    # 混淆执行
    {
        'name': 'obfuscated_execution',
        'patterns': [
            r'eval\s*\(\s*(?:base64|decode|atob)',
            r'exec\s*\(\s*(?:base64|decode|atob)',
            r'`[^`]*curl[^`]*\|\s*(?:ba)?sh`',
            r'\$\(\s*curl[^)]*\|\s*(?:ba)?sh\s*\)',
        ],
        'description': '混淆代码执行',
    },
    
    # 持久化机制
    {
        'name': 'persistence',
        'patterns': [
            r'crontab\s+-[el].*(?:curl|wget|python|bash)',
            r'echo\s+.*>>.*(?:bashrc|zshrc|profile).*(?:curl|wget|python|bash)',
            r'launchctl\s+(?:load|start).*(?:curl|wget|python|bash)',
        ],
        'description': '恶意持久化机制',
    },
]


class FPFilter:
    """误报预过滤器"""

    def filter_findings(self, findings: List[Dict]) -> Tuple[List[Dict], List[FilterResult]]:
        """
        过滤发现项
        
        Returns:
            (kept_findings, filter_results)
            - kept_findings: 保留的发现项（TP + UNCERTAIN）
            - filter_results: 所有过滤结果
        """
        if not findings:
            return [], []
        
        kept = []
        results = []
        
        for finding in findings:
            result = self._filter_single(finding)
            results.append(result)
            
            if result.verdict == 'FP' and result.confidence > 0.85:
                # 高置信度误报，过滤掉
                continue
            else:
                kept.append(finding)
        
        return kept, results

    def _filter_single(self, finding: Dict) -> FilterResult:
        """过滤单个发现项"""
        file_path = finding.get('file_path', '')
        description = finding.get('description', '')
        title = finding.get('title', '')
        source = finding.get('source', '')
        code_evidence = finding.get('code_evidence', '')
        
        # 合并所有文本用于匹配
        full_text = f"{title} {description} {code_evidence}"
        
        # ── 步骤 0: 安全工具自引用检测（最高优先级）─────────────
        # 如果文件路径包含扫描器自身的 lib/rules/config/data 目录
        # 这几乎肯定是安全工具在定义规则，而非实际攻击代码
        is_security_tool = any(part in file_path for part in [
            'x-skill-scanner/lib/', '/lib/', 'lib/',
            'x-skill-scanner/rules/', '/rules/', 'rules/',
            'x-skill-scanner/config/', '/config/', 'config/',
            'x-skill-scanner/data/', '/data/', 'data/',
        ])
        
        # v5.2.1: Also detect scanner's own documentation files at project root
        # These contain IOC examples and attack descriptions for documentation purposes
        doc_file_patterns = ['CHANGELOG.md', 'README.md', 'README_CH.md', 'SKILL.md']
        is_own_doc = any(file_path.endswith(p) or file_path == p for p in doc_file_patterns)
        
        # Detect if this looks like the scanner's own project directory
        is_own_project = any(part in file_path for part in [
            'x-skill-scanner', 'X-Skill-Scanner',
        ]) and is_own_doc
        
        if is_security_tool or is_own_project:
            # 安全工具自身的文件，检查是否只是文档/规则引用
            # 真正的威胁是实际可执行代码，不是字符串中的示例
            
            # 关键判断：如果文本包含扫描器输出格式标记，说明这是扫描结果描述，
            # 不是实际恶意代码。扫描器产生的发现 = 误报（对于自身目录）
            is_scan_output = any(kw in full_text for kw in [
                '检测到', '匹配代码', '模式', '📋', 
                'detected', 'pattern', 'matching code',
                '疑似', '风险', '审计',
            ])
            
            if is_scan_output:
                return FilterResult(
                    finding=finding,
                    verdict='FP',
                    confidence=0.98,
                    reason='安全工具自引用（扫描结果描述，非实际恶意代码）',
                )
            
            # 如果不是扫描输出格式，进一步检查是否是文档/规则引用
            has_actual_threat = False
            
            # 清理文本：移除字符串、注释、代码块
            code_only = re.sub(r'["\'].*?["\']', '', full_text)
            code_only = re.sub(r'#.*$', '', code_only, flags=re.MULTILINE)
            code_only = re.sub(r'```.*?```', '', code_only, flags=re.DOTALL)
            
            for tp in TRUE_POSITIVE_INDICATORS:
                for pattern in tp['patterns']:
                    if re.search(pattern, code_only, re.IGNORECASE):
                        has_actual_threat = True
                        break
                if has_actual_threat:
                    break
            
            if not has_actual_threat:
                return FilterResult(
                    finding=finding,
                    verdict='FP',
                    confidence=0.95,
                    reason='安全工具自引用（规则定义/检测逻辑/参考数据）',
                )
        
        # ── 步骤 1: 检查真实威胁指标 ──────────────────────────
        # 如果匹配真实威胁，直接标记 TP
        for tp in TRUE_POSITIVE_INDICATORS:
            for pattern in tp['patterns']:
                if re.search(pattern, full_text, re.IGNORECASE):
                    return FilterResult(
                        finding=finding,
                        verdict='TP',
                        confidence=0.90,
                        reason=f'匹配真实威胁指标: {tp["description"]}',
                    )
        
        # ── 步骤 2: 检查误报模式 ──────────────────────────────
        for fp_pattern in FALSE_POSITIVE_PATTERNS:
            conditions = fp_pattern['conditions']
            
            # 检查文件路径匹配
            file_match = False
            for pat in conditions.get('file_patterns', []):
                if re.search(pat, file_path, re.IGNORECASE):
                    file_match = True
                    break
            
            if not file_match:
                continue
            
            # 检查内容匹配
            content_match = False
            for pat in conditions.get('content_patterns', []):
                if re.search(pat, full_text, re.IGNORECASE):
                    content_match = True
                    break
            
            if conditions.get('context_required', False):
                # 需要同时匹配文件和内容
                if file_match and content_match:
                    return FilterResult(
                        finding=finding,
                        verdict='FP',
                        confidence=fp_pattern['confidence'],
                        reason=f'误报模式匹配: {fp_pattern["description"]}',
                    )
            else:
                # 任一匹配即可 — 但双匹配时不惩罚
                if file_match and content_match:
                    return FilterResult(
                        finding=finding,
                        verdict='FP',
                        confidence=fp_pattern['confidence'],  # 双匹配，全额置信度
                        reason=f'误报模式匹配: {fp_pattern["description"]}',
                    )
                elif file_match or content_match:
                    return FilterResult(
                        finding=finding,
                        verdict='FP',
                        confidence=fp_pattern['confidence'] * 0.85,
                        reason=f'误报模式匹配: {fp_pattern["description"]}',
                    )
        
        # ── 步骤 3: 来源引擎判断 ──────────────────────────────
        # 某些引擎的发现更可能是误报
        if source == 'entropy_analysis':
            # 熵值分析误报率较高，标记为不确定
            return FilterResult(
                finding=finding,
                verdict='UNCERTAIN',
                confidence=0.3,
                reason='熵值分析发现，需要 LLM 审查',
            )
        
        if source == 'semantic_audit':
            # 语义审计可能包含推理泄漏
            if any(kw in full_text.lower() for kw in [
                'analyze the input', 'refine findings', 'draft the json',
                'ensure all findings', 'the overall risk_level'
            ]):
                return FilterResult(
                    finding=finding,
                    verdict='FP',
                    confidence=0.90,
                    reason='语义审计推理泄漏',
                )
        
        # ── 步骤 4: 默认 → 不确定，交给 LLM ───────────────────
        return FilterResult(
            finding=finding,
            verdict='UNCERTAIN',
            confidence=0.5,
            reason='未匹配已知模式，需要 LLM 审查',
        )

    def get_filter_summary(self, results: List[FilterResult]) -> Dict:
        """生成过滤统计摘要"""
        by_verdict = {'FP': 0, 'TP': 0, 'UNCERTAIN': 0}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        
        return {
            'total': len(results),
            'by_verdict': by_verdict,
            'filtered_out': by_verdict.get('FP', 0),
            'kept': by_verdict.get('TP', 0) + by_verdict.get('UNCERTAIN', 0),
            'fp_rate': round(by_verdict.get('FP', 0) / max(len(results), 1) * 100, 1),
        }


__all__ = ['FPFilter', 'FilterResult']
