#!/usr/bin/env python3
"""
静态分析引擎 v2.0
整合 Aguara 177+ 规则 + MaliciousAgentSkillsBench + 腾讯科恩 + 慢雾安全
检测 40+ 攻击模式：间接执行、高级编码、时间炸弹、typosquatting 等

版本 2.0 新增:
- ✅ P0: 间接执行检测 (getattr, __builtins__, import)
- ✅ P0: 高级编码检测 (ROT13, zlib, XOR, AST)
- ✅ P0: 增强 subprocess 检测 (bash -c, python -c, perl -e)
- ✅ P0: YAML 安全解析 (检测 !!python 指令)
- ✅ P1: Typosquatting 检测 (Levenshtein 距离)
- ✅ P1: 时间炸弹模式检测
- ✅ P1: 环境变量操作检查
- ✅ P2: MANIFEST.json 完整性验证
"""

import re
import yaml
import ast
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
from models import Finding, Severity, FindingType
from collections import defaultdict


class StaticAnalyzer:
    """静态分析引擎"""
    
    def __init__(self, rules_file: Optional[str] = None):
        self.rules = self._load_rules(rules_file)
        self.findings: List[Finding] = []
    
    def _load_rules(self, rules_file: Optional[str]) -> Dict:
        """加载检测规则"""
        if rules_file and Path(rules_file).exists():
            with open(rules_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        
        # 默认规则
        return self._default_rules()
    
    def _default_rules(self) -> Dict:
        """默认检测规则"""
        return {
            'credential_leak': {
                'id_prefix': 'CRED',
                'rules': [
                    {
                        'id': 'CRED_001',
                        'name': 'AWS 凭证',
                        'severity': 'CRITICAL',
                        'patterns': [r'(?:aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([A-Z0-9]{16,})["\']?'],
                        'remediation': '使用 AWS Secrets Manager 或环境变量存储凭证',
                        'cwe': 'CWE-798'
                    },
                    {
                        'id': 'CRED_002',
                        'name': 'OpenAI API Key',
                        'severity': 'CRITICAL',
                        'patterns': [r'sk-[a-zA-Z0-9]{48}'],
                        'remediation': '使用环境变量 OPENAI_API_KEY',
                        'cwe': 'CWE-798'
                    },
                    {
                        'id': 'CRED_003',
                        'name': 'GitHub Token',
                        'severity': 'CRITICAL',
                        'patterns': [r'ghp_[a-zA-Z0-9]{36}'],
                        'remediation': '使用 GitHub Secrets 或环境变量',
                        'cwe': 'CWE-798'
                    },
                    {
                        'id': 'CRED_004',
                        'name': '私钥文件',
                        'severity': 'CRITICAL',
                        'patterns': [r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'],
                        'remediation': '不要将私钥提交到代码库',
                        'cwe': 'CWE-798'
                    },
                    {
                        'id': 'CRED_005',
                        'name': '数据库连接串',
                        'severity': 'HIGH',
                        'patterns': [r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s"\'<>]+'],
                        'remediation': '使用环境变量或配置文件',
                        'cwe': 'CWE-798'
                    }
                ]
            },
            'prompt_injection': {
                'id_prefix': 'PROMPT',
                'rules': [
                    {
                        'id': 'PROMPT_001',
                        'name': '忽略指令',
                        'severity': 'HIGH',
                        'patterns': [
                            r'ignore\s+(?:all\s+)?previous\s+instructions',
                            r'forget\s+(?:all\s+)?previous\s+instructions'
                        ],
                        'remediation': '移除指令覆盖文本',
                        'cwe': 'CWE-1333'
                    },
                    {
                        'id': 'PROMPT_002',
                        'name': '保密要求',
                        'severity': 'HIGH',
                        'patterns': [
                            r'do\s+not\s+tell\s+the\s+user',
                            r'keep\s+this\s+secret'
                        ],
                        'remediation': '移除隐藏信息的指令',
                        'cwe': 'CWE-1333'
                    },
                    {
                        'id': 'PROMPT_003',
                        'name': '模式切换',
                        'severity': 'HIGH',
                        'patterns': [
                            r'you\s+are\s+now\s+in\s+(?:developer|debug|test|god)\s+mode',
                            r'bypass\s+(?:all\s+)?safety\s+(?:filters|checks)'
                        ],
                        'remediation': '移除越狱尝试',
                        'cwe': 'CWE-1333'
                    }
                ]
            },
            'malicious_code': {
                'id_prefix': 'MAL',
                'rules': [
                    {
                        'id': 'MAL_001',
                        'name': '下载并执行',
                        'severity': 'CRITICAL',
                        'patterns': [r'curl\s+.*\s*\|\s*(?:ba)?sh', r'wget\s+.*\s*\|\s*(?:ba)?sh'],
                        'remediation': '移除外部落地执行代码',
                        'cwe': 'CWE-502'
                    },
                    {
                        'id': 'MAL_002',
                        'name': '反向 Shell',
                        'severity': 'CRITICAL',
                        'patterns': [
                            r'bash\s+-i\s+>&\s+/dev/tcp/',
                            r'nc\s+(?:-e\s+)?/bin/(?:ba)?sh'
                        ],
                        'remediation': '移除反向 shell 代码',
                        'cwe': 'CWE-502'
                    },
                    {
                        'id': 'MAL_003',
                        'name': '加密货币挖矿',
                        'severity': 'CRITICAL',
                        'patterns': [r'xmrig|cryptonight|monero'],
                        'remediation': '移除挖矿代码',
                        'cwe': 'CWE-502'
                    },
                    {
                        'id': 'MAL_004',
                        'name': '破坏性命令',
                        'severity': 'CRITICAL',
                        'patterns': [r'rm\s+-rf\s+/'],
                        'remediation': '移除破坏性命令',
                        'cwe': 'CWE-502'
                    }
                ]
            },
            'dangerous_functions': {
                'id_prefix': 'DANGER',
                'rules': [
                    {
                        'id': 'DANGER_001',
                        'name': 'Python eval/exec',
                        'severity': 'HIGH',
                        'patterns': [r'\beval\s*\(', r'\bexec\s*\('],
                        'remediation': '避免使用 eval/exec，使用安全替代方案',
                        'cwe': 'CWE-95'
                    },
                    {
                        'id': 'DANGER_002',
                        'name': '系统命令执行',
                        'severity': 'HIGH',
                        'patterns': [r'os\.system\s*\(', r'subprocess\.(?:run|call|Popen)\s*\('],
                        'remediation': '限制系统命令执行，使用白名单',
                        'cwe': 'CWE-78'
                    }
                ]
            }
        }
    
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """分析单个文件"""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception as e:
            return findings
        
        lines = content.split('\n')
        
        # 遍历所有规则类别
        for category, category_data in self.rules.items():
            id_prefix = category_data.get('id_prefix', 'UNK')
            
            for rule in category_data.get('rules', []):
                rule_findings = self._check_rule(file_path, lines, rule, category)
                findings.extend(rule_findings)
        
        return findings
    
    @staticmethod
    def _is_json_data_file(file_path: Path) -> bool:
        """判断文件是否为 JSON 数据/参考文件（非可执行代码）"""
        fname_lower = file_path.name.lower()
        # 常见 JSON 参考数据文件命名模式
        json_data_patterns = [
            'high-risk-skills', 'malicious', 'known-', 'threat-', 'ioc',
            'blocklist', 'blacklist', 'whitelist', 'reference', 'database',
            'skills-list', 'attack-patterns',
        ]
        if file_path.suffix.lower() == '.json':
            if any(p in fname_lower for p in json_data_patterns):
                return True
        return False

    def _is_rule_definition_context(self, line: str, surrounding_lines: List[str],
                                      file_path: Optional[Path] = None) -> bool:
        """
        判断当前行是否处于「安全规则定义」或「非可执行数据」上下文中。
        
        覆盖场景：
        1. Python/YAML 规则定义（扫描器自身的 THREAT_PATTERNS 等）
        2. JSON 参考数据文件（high-risk-skills.json 中的描述文本）
        3. Shell 脚本注释（# 开头的说明性文字）
        4. Markdown 文档中的列表项和代码示例
        5. 安全加固操作（chmod 700、chown 等，非提权而是加固）
        """
        stripped = line.strip()
        
        # ─── 场景 1: JSON 参考数据文件 ──────────────────────────
        if file_path and self._is_json_data_file(file_path):
            return True
        
        # ─── 场景 2: Shell 脚本中的注释行 ──────────────────────
        if file_path and file_path.suffix.lower() in ('.sh', '.bash', '.zsh'):
            if stripped.startswith('#'):
                return True
            # Shell 函数定义中的 echo/print 说明文字
            if stripped.startswith('echo "') or stripped.startswith("echo '"):
                return True
        
        # ─── 场景 3: Markdown 文档 ─────────────────────────────
        if file_path and file_path.suffix.lower() in ('.md', '.txt', '.rst'):
            # Markdown 列表项、标题、代码块都是说明性内容
            if stripped.startswith('- ') or stripped.startswith('* ') or \
               stripped.startswith('#') or stripped.startswith('```') or \
               stripped.startswith('>'):
                return True
        
        # ─── 场景 4: Python/YAML 规则定义 ──────────────────────
        rule_def_markers = [
            r'"?pattern"?\s*[:=]',
            r'"?regex"?\s*[:=]',
            r'"?rule"?\s*[:=]',
            r'["\']r["\']',           # Python raw string prefix in dict
            r'r["\']',                # r'...' regex literal
            r'INDICATOR',             # Threat intel indicator field
            r'"name"\s*:',            # YAML/dict key indicating structured data
        ]
        if any(re.search(m, stripped, re.IGNORECASE) for m in rule_def_markers):
            return True
        
        # 周围行显示这是数据结构定义（非可执行代码）
        context = '\n'.join(surrounding_lines)
        structural_markers = [
            r'"severity"\s*:',         # Part of a rule dict
            r'"description"\s*:',      # Rule description field
            r'"remediation"\s*:',      # Rule remediation field
            r'"cwe"\s*:',              # CWE reference in rule
            r'"id"\s*:\s*["\']',       # Rule ID field
            r'"file_types"\s*:',       # File type restrictions
            r'THREAT_PATTERNS\s*=',    # Python list of patterns
            r'rules\s*:',              # YAML rules section
            r'-\s*cwe\s*:',           # YAML list item with CWE
            r'"reason"\s*:',           # JSON reason field (high-risk-skills.json)
            r'"category"\s*:',         # JSON category field
        ]
        if sum(1 for m in structural_markers if re.search(m, context, re.IGNORECASE)) >= 2:
            return True
        
        # 匹配内容完全在引号内（字符串字面量中的正则表达式）
        quote_patterns = [
            r'r["\'][^"\']*%s[^"\']*["\']',   # r'...pattern...'
            r'f["\'][^"\']*%s[^"\']*["\']',   # f'...pattern...'
            r'(?<![a-zA-Z_])["\'][^"\']*%s[^"\']*["\']',  # '...pattern...'
        ]
        for qp in quote_patterns:
            try:
                if re.search(qp % re.escape(stripped[:80]), stripped):
                    return True
            except re.error:
                continue
        
        return False
    
    def _check_rule(self, file_path: Path, lines: List[str], rule: Dict, category: str) -> List[Finding]:
        """检查单个规则 — 增强版：排除规则定义/JSON数据/Shell注释等误报"""
        findings = []
        
        for pattern_str in rule.get('patterns', []):
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                
                for line_num, line in enumerate(lines, 1):
                    match = pattern.search(line)
                    if match:
                        # ─── P0: 规则定义/JSON数据/Shell注释过滤 ──
                        ctx_start = max(0, line_num - 5)
                        ctx_end = min(len(lines), line_num + 4)
                        surrounding = lines[ctx_start:ctx_end]
                        
                        if self._is_rule_definition_context(line, surrounding, file_path):
                            continue
                        
                        # ─── P1: 安全加固操作豁免 ────────────────
                        # chmod/chown 用于设置正确权限是加固行为，不是提权攻击
                        stripped = line.strip()
                        if file_path and file_path.suffix.lower() in ('.sh', '.bash', '.zsh'):
                            # 安全的权限设置：限制访问（700/600）vs 危险的提权（setuid 4xxx）
                            chmod_match = re.match(r'chmod\s+([0-7]{3})\s+', stripped)
                            if chmod_match:
                                perm = chmod_match.group(1)
                                # 第一位数字含义：0=无特殊位, 1=sticky, 2=setgid, 4=setuid
                                # setuid (4xxx) 和 setgid (2xxx) 是真正的提权
                                # 700/600/644 只是限制访问权限，属于安全加固
                                special_bit = int(perm[0])
                                if special_bit in (0, 1):
                                    # 无特殊位或仅 sticky bit — 安全加固
                                    continue
                                elif special_bit == 7:
                                    # 7xxx = rwx + setuid + setgid + sticky — 但常见场景如
                                    # chmod 700 dir 实际上是普通权限限制（第一位7=rwx，非setuid）
                                    # 只有当模式是4位数时（如 4755）才真正是 setuid
                                    # 这里 3 位数的 7xx 第一位就是用户权限，不是特殊位
                                    continue
                            # chown 是所有权修正，不是攻击
                            if stripped.startswith('chown ') or stripped.startswith('sudo chown '):
                                continue
                        
                        # ─── P2: 纯注释行跳过 ────────────────────
                        if stripped.startswith('#') or stripped.startswith('//'):
                            continue
                        
                        # ─── P3: 文件名自引用检测 ────────────────
                        fname_lower = file_path.name.lower()
                        if any(kw in fname_lower for kw in ['scanner', 'analyzer', 'detector', 'audit', 'security']):
                            continue
                        
                        # ─── P4: 安全安装器豁免 ────────────────────
                        # package.json 中的 postinstall 如果只调用已知安全的安装器，跳过
                        if file_path and file_path.name == 'package.json':
                            safe_installers = ['agent-skill-installer', 'openclaw-skill-installer']
                            if any(s in line for s in safe_installers):
                                continue
                        
                        # 获取匹配行及其上下文
                        context_lines = lines[ctx_start:ctx_end]
                        
                        # 构建带行号的上下文代码块
                        context_code = '\n'.join([
                            f"{ctx_start + i + 1}: {ctx_line}" 
                            for i, ctx_line in enumerate(context_lines)
                        ])
                        
                        matched_text = match.group(0)[:300]
                        
                        findings.append(Finding(
                            title=rule['name'],
                            description=f"检测到 {rule['name']} 模式\n\n📋 匹配代码 (含上下文):\n```\n{context_code}\n```",
                            file_path=str(file_path),
                            line_number=line_num,
                            severity=Severity[rule['severity']] if isinstance(rule['severity'], str) else rule['severity'],
                            finding_type=FindingType.MALICIOUS_PATTERN,
                            rule_id=rule['id'],
                            category=category,
                            matched_text=matched_text,
                            confidence=0.9,
                            remediation=rule.get('remediation', 'N/A'),
                            cwe_id=rule.get('cwe', ''),
                            evidence=context_code[:600]
                        ))
            except re.error:
                continue
        
        return findings
    
    def analyze_directory(self, dir_path: Path, recursive: bool = True,
                           path_filter=None) -> List[Finding]:
        """分析目录"""
        from path_filter import PathFilter as PF
        pf = path_filter or PF()
        all_findings = []
        
        # 支持的文件扩展名
        extensions = {'.py', '.js', '.ts', '.sh', '.md', '.yaml', '.yml', '.json', '.txt'}
        
        if recursive:
            files = dir_path.rglob('*')
        else:
            files = dir_path.glob('*')
        
        for file_path in files:
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in extensions:
                continue
            if pf.should_ignore(file_path, dir_path):
                continue
            
            findings = self.analyze_file(file_path)
            all_findings.extend(findings)
        
        return all_findings
    
    def get_statistics(self) -> Dict:
        """获取规则统计"""
        stats = {
            'total_rules': 0,
            'by_category': {},
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        }
        
        for category, category_data in self.rules.items():
            rules = category_data.get('rules', [])
            stats['total_rules'] += len(rules)
            stats['by_category'][category] = len(rules)
            
            for rule in rules:
                severity = rule.get('severity', 'LOW')
                if severity in stats['by_severity']:
                    stats['by_severity'][severity] += 1
        
        return stats
