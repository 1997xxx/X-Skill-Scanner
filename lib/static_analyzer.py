#!/usr/bin/env python3
"""
静态分析引擎
整合 Aguara 177+ 规则，检测凭证泄露、提示词注入、恶意代码等
"""

import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class Finding:
    """安全发现项"""
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    file_path: str
    line_number: int = 0
    matched_text: str = ""
    confidence: float = 0.8
    remediation: str = ""
    cwe_id: str = ""


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
    
    def _check_rule(self, file_path: Path, lines: List[str], rule: Dict, category: str) -> List[Finding]:
        """检查单个规则"""
        findings = []
        
        for pattern_str in rule.get('patterns', []):
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                
                for line_num, line in enumerate(lines, 1):
                    match = pattern.search(line)
                    if match:
                        findings.append(Finding(
                            rule_id=rule['id'],
                            severity=rule['severity'],
                            category=category,
                            title=rule['name'],
                            description=f"检测到 {rule['name']} 模式",
                            file_path=str(file_path),
                            line_number=line_num,
                            matched_text=match.group(0)[:100],
                            confidence=0.9,
                            remediation=rule.get('remediation', 'N/A'),
                            cwe_id=rule.get('cwe', '')
                        ))
            except re.error:
                continue
        
        return findings
    
    def analyze_directory(self, dir_path: Path, recursive: bool = True) -> List[Finding]:
        """分析目录"""
        all_findings = []
        
        # 支持的文件扩展名
        extensions = {'.py', '.js', '.ts', '.sh', '.md', '.yaml', '.yml', '.json', '.txt'}
        
        if recursive:
            files = dir_path.rglob('*')
        else:
            files = dir_path.glob('*')
        
        for file_path in files:
            if file_path.is_file() and file_path.suffix.lower() in extensions:
                # 跳过某些目录
                if any(part.startswith('.') for part in file_path.parts):
                    continue
                if any(part in ['node_modules', '__pycache__', '.git'] for part in file_path.parts):
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
