#!/usr/bin/env python3
"""
语义审计引擎
使用 OpenClaw llm-task 工具进行深度代码意图分析
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class SemanticFinding:
    """语义审计发现项"""
    severity: str
    category: str
    title: str
    description: str
    file_path: str
    risk_assessment: str
    confidence: float
    remediation: str


class SemanticAuditor:
    """语义审计引擎"""
    
    def __init__(self, timeout_ms: int = 60000, max_tokens: int = 1500, thinking: str = "low"):
        self.timeout_ms = timeout_ms
        self.max_tokens = max_tokens
        self.thinking = thinking
        self.findings: List[SemanticFinding] = []
    
    def audit_file(self, file_path: Path, content: str) -> List[SemanticFinding]:
        """
        审计单个文件
        
        使用 OpenClaw llm-task 工具进行语义分析
        """
        findings = []
        
        # 构建审计提示词
        prompt = self._build_audit_prompt(file_path.name, content)
        
        # 调用 llm-task
        result = self._call_llm_task(prompt)
        
        if result:
            findings.extend(self._parse_result(file_path, result))
        
        return findings
    
    def _build_audit_prompt(self, filename: str, content: str) -> str:
        """构建审计提示词"""
        return f"""你是一个 AI 安全审计专家。请分析以下技能代码文件，识别潜在的安全风险。

文件：{filename}

代码内容：
```
{content[:8000]}  # 限制长度
```

请分析以下方面：
1. 是否有恶意行为意图（数据窃取、凭证泄露、反向 shell 等）
2. 是否有过度权限请求
3. 是否有可疑的网络通信
4. 是否有代码混淆或隐藏逻辑
5. 是否有提示词注入尝试

请按以下 JSON 格式返回分析结果：
{{
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "findings": [
        {{
            "severity": "LOW|MEDIUM|HIGH|CRITICAL",
            "category": "credential_leak|data_exfil|malicious_code|prompt_injection|other",
            "title": "简短标题",
            "description": "详细描述",
            "confidence": 0.0-1.0,
            "remediation": "修复建议"
        }}
    ],
    "summary": "总体评估总结"
}}

如果没有发现风险，返回：{{"risk_level": "LOW", "findings": [], "summary": "未发现明显安全风险"}}
"""
    
    def _call_llm_task(self, prompt: str) -> Optional[Dict]:
        """调用 OpenClaw llm-task 工具"""
        try:
            # 使用 OpenClaw llm-task 命令
            cmd = [
                'openclaw', 'llm-task',
                '--prompt', prompt,
                '--timeout', str(self.timeout_ms // 1000),
                '--json'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_ms // 1000 + 10
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                print(f"⚠️  LLM 调用失败：{result.stderr}", file=sys.stderr)
                return None
        
        except subprocess.TimeoutExpired:
            print(f"⚠️  LLM 调用超时 ({self.timeout_ms}ms)", file=sys.stderr)
            return None
        except Exception as e:
            print(f"⚠️  LLM 调用错误：{e}", file=sys.stderr)
            return None
    
    def _parse_result(self, file_path: Path, result: Dict) -> List[SemanticFinding]:
        """解析 LLM 返回结果"""
        findings = []
        
        llm_findings = result.get('findings', [])
        
        for finding in llm_findings:
            findings.append(SemanticFinding(
                severity=finding.get('severity', 'MEDIUM'),
                category=finding.get('category', 'other'),
                title=finding.get('title', '未知风险'),
                description=finding.get('description', 'N/A'),
                file_path=str(file_path),
                risk_assessment=result.get('risk_level', 'UNKNOWN'),
                confidence=finding.get('confidence', 0.5),
                remediation=finding.get('remediation', '需要人工审查')
            ))
        
        return findings
    
    def audit_directory(self, dir_path: Path, recursive: bool = True) -> List[SemanticFinding]:
        """审计目录"""
        all_findings = []
        
        extensions = {'.py', '.js', '.ts', '.sh', '.md', '.yaml', '.yml'}
        
        if recursive:
            files = dir_path.rglob('*')
        else:
            files = dir_path.glob('*')
        
        for file_path in files:
            if file_path.is_file() and file_path.suffix.lower() in extensions:
                # 跳过某些目录
                if any(part.startswith('.') for part in file_path.parts):
                    continue
                
                try:
                    content = file_path.read_text(encoding='utf-8')
                    if len(content) > 100:  # 跳过太短的文件
                        findings = self.audit_file(file_path, content)
                        all_findings.extend(findings)
                except Exception as e:
                    continue
        
        return all_findings
    
    def quick_assess(self, code: str) -> Dict:
        """快速风险评估（不调用 LLM，基于规则）"""
        risk_indicators = {
            'credential_patterns': [
                r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
                r'password\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']'
            ],
            'network_patterns': [
                r'requests\.post\([^)]*http',
                r'fetch\([^)]*http',
                r'curl\s+'
            ],
            'dangerous_patterns': [
                r'eval\s*\(',
                r'exec\s*\(',
                r'os\.system\s*\('
            ]
        }
        
        import re
        risk_score = 0
        indicators = []
        
        for category, patterns in risk_indicators.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    risk_score += 1
                    indicators.append(category)
        
        if risk_score == 0:
            risk_level = "LOW"
        elif risk_score <= 2:
            risk_level = "MEDIUM"
        elif risk_score <= 4:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'indicators': list(set(indicators)),
            'requires_llm_audit': risk_level in ['HIGH', 'CRITICAL']
        }
