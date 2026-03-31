#!/usr/bin/env python3
"""语义审计引擎 v3.1 — Provider API 直接调用 + Gateway fallback"""

import json, hashlib, re, sys, os
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import urllib.request, urllib.error

def _p(*args, **kwargs):
    kwargs.setdefault('file', sys.stderr)
    print(*args, **kwargs)

@dataclass
class SemanticFinding:
    severity: str; category: str; title: str; description: str; file_path: str
    line: Optional[int] = None; evidence: Optional[str] = None
    confidence: float = 0.5; remediation: str = "需要人工审查"

QUICK_RISK_PATTERNS = [
    (r'api[_\-]?key\s*=\s*["\x27][^"\x27]{8,}["\x27]', 'credential_leak', 'API Key 硬编码', 25),
    (r'password\s*=\s*["\x27][^"\x27]+["\x27]', 'credential_leak', '密码硬编码', 20),
    (r'token\s*=\s*["\x27][^"\x27]{10,}["\x27]', 'credential_leak', 'Token 硬编码', 20),
    (r'secret\s*=\s*["\x27][^"\x27]+["\x27]', 'credential_leak', '密钥硬编码', 25),
    (r'requests\.(post|get)\([^)]*http', 'suspicious_network', 'HTTP 外传请求', 10),
    (r'http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'suspicious_network', 'IP 直连', 20),
    (r'\beval\s*\(', 'malicious_code', 'Eval 执行', 30),
    (r'\bexec\s*\(', 'malicious_code', '代码执行', 30),
    (r'os\.system\s*\(', 'malicious_code', '系统命令', 25),
    (r'subprocess.*shell\s*=\s*True', 'malicious_code', 'Shell 注入', 30),
    (r'curl\s+.*\|\s*(bash|sh|zsh)', 'malicious_code', 'Curl Pipe Shell', 35),
    (r'wget\s+.*\|\s*(bash|sh|zsh)', 'malicious_code', 'Wget Pipe Shell', 35),
    (r'base64\s*(-D|--decode)', 'code_obfuscation', 'Base64 解码执行', 30),
]

SYSTEM_PROMPT = """你是 AI 安全审计专家，专注于检测 Agent Skills 中的安全风险。

【重要】你必须且只能返回纯 JSON，不要包含任何其他文字、解释或推理过程。

JSON 格式要求：
{
  "risk_level": "LOW 或 MEDIUM 或 HIGH 或 CRITICAL",
  "findings": [
    {
      "severity": "CRITICAL 或 HIGH 或 MEDIUM 或 LOW",
      "category": "credential_leak 或 data_exfil 或 malicious_code 或 prompt_injection 或 excessive_permissions 或 suspicious_network 或 code_obfuscation 或 social_engineering",
      "title": "简短标题（中文）",
      "description": "详细描述（中文）",
      "line": 行号数字,
      "evidence": "相关代码片段",
      "confidence": 0.0到1.0的数字,
      "remediation": "修复建议（中文）"
    }
  ],
  "summary": "总体评估（中文）"
}

如果没有发现风险，返回: {"risk_level":"LOW","findings":[],"summary":"未发现安全风险"}

现在开始分析，只返回 JSON："""

class SemanticAuditor:
    def __init__(self, provider_url=None, provider_api_key=None, provider_model=None,
                 provider_api_type="openai-chat", timeout_ms=180000, 
                 cache_enabled=True, cache_ttl_hours=24, llm_enabled=True):
        self.provider_url = provider_url
        self.provider_api_key = provider_api_key
        self.provider_model = provider_model
        self.provider_api_type = provider_api_type
        if not all([self.provider_url, self.provider_api_key, self.provider_model]):
            self._auto_discover_provider()
        self.timeout_ms = timeout_ms
        self.llm_enabled = llm_enabled
        self.cache_enabled = cache_enabled
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self._cache = {}
        self._cache_file = Path(__file__).parent / '.semantic_cache.json'
        self._load_cache()
        self.findings = []
        self._log_config()

    def _auto_discover_provider(self):
        try:
            config_path = Path.home() / '.openclaw' / 'openclaw.json'
            if not config_path.exists(): return
            with open(config_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            providers = cfg.get('models', {}).get('providers', {})
            for prov_id, prov_cfg in providers.items():
                api_key = prov_cfg.get('apiKey')
                base_url = prov_cfg.get('baseUrl')
                api_type = prov_cfg.get('api', 'openai-chat')
                models_list = prov_cfg.get('models', [])
                if api_key and base_url and models_list:
                    model_id = models_list[0].get('id', '')
                    if not self.provider_api_key: self.provider_api_key = api_key
                    if not self.provider_model: self.provider_model = model_id
                    
                    # Probe to find the correct URL and API type
                    detected_url, detected_type = self._probe_api_type(base_url, api_key, model_id)
                    
                    if detected_url and detected_type:
                        self.provider_url = detected_url
                        self.provider_api_type = detected_type
                        _p(f"🔌 自动发现 Provider: {prov_id} ({model_id}) [{detected_type}]")
                    else:
                        # Fallback: use config values
                        if not self.provider_url: self.provider_url = base_url
                        if api_type in ('anthropic-messages', 'anthropic'):
                            self.provider_api_type = 'openai-completions'  # safer default
                        else:
                            self.provider_api_type = api_type
                        _p(f"🔌 自动发现 Provider: {prov_id} ({model_id}) [fallback: {self.provider_api_type}]")
                    return
        except Exception as e:
            _p(f"⚠️  Provider 自动发现失败: {e}")

    def _probe_api_type(self, base_url, api_key, model_id):
        """Probe the API to find a working endpoint. Returns (url, api_type) or (None, None)."""
        base = base_url.rstrip('/')
        
        # Build candidate URLs to test
        candidates = []
        
        # If baseUrl looks like it already has a path component, derive root
        # e.g., https://host/api/anthropic → try https://host/v1/chat/completions
        if '/api/' in base:
            root = base[:base.index('/api/')]
            candidates.append(f'{root}/v1/chat/completions')
        
        # Also try standard patterns
        if not base.endswith('/v1/chat/completions'):
            candidates.append(f'{base}/v1/chat/completions')
        candidates.append(base)  # try bare URL
        
        # Deduplicate while preserving order
        seen = set()
        unique_candidates = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique_candidates.append(c)
        
        for url in unique_candidates:
            # Test as OpenAI-compatible (most common)
            try:
                payload = {
                    'model': model_id,
                    'max_tokens': 10,
                    'messages': [{'role': 'user', 'content': 'hi'}]
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode('utf-8'),
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': f'Bearer {api_key}'
                    },
                    method='POST'
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = json.loads(resp.read().decode('utf-8'))
                    if 'choices' in body:
                        return (url, 'openai-completions')
            except Exception:
                pass
            
            # Test as Anthropic messages
            try:
                msg_url = url if url.endswith('/messages') else f'{url}/messages'
                payload = {
                    'model': model_id,
                    'max_tokens': 10,
                    'system': 'hi',
                    'messages': [{'role': 'user', 'content': 'hi'}]
                }
                req = urllib.request.Request(
                    msg_url,
                    data=json.dumps(payload).encode('utf-8'),
                    headers={
                        'Content-Type': 'application/json',
                        'x-api-key': api_key,
                        'anthropic-version': '2023-06-01'
                    },
                    method='POST'
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = json.loads(resp.read().decode('utf-8'))
                    if 'content' in body:
                        return (msg_url, 'anthropic-messages')
            except Exception:
                pass
        
        return (None, None)

    def _log_config(self):
        has_provider = bool(self.provider_url and self.provider_api_key and self.provider_model)
        mode = "provider" if has_provider else "rules-only"
        _p(f"🧠 语义审计模式: {mode}")
        if has_provider:
            _p(f"   Provider: {self.provider_url} | Model: {self.provider_model}")

    def _load_cache(self):
        if not self.cache_enabled: return
        try:
            if self._cache_file.exists():
                with open(self._cache_file, 'r', encoding='utf-8') as f:
                    self._cache = json.load(f)
        except Exception: self._cache = {}

    def _save_cache(self):
        if not self.cache_enabled: return
        try:
            with open(self._cache_file, 'w', encoding='utf-8') as f:
                json.dump(self._cache, f, ensure_ascii=False, indent=2)
        except Exception: pass

    def _cache_key(self, file_path, content):
        h = hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
        return f"{file_path}:{h}"

    def _cache_valid(self, entry):
        if not entry: return False
        cached = datetime.fromisoformat(entry.get('cached_at', '2000-01-01'))
        return datetime.now() - cached < self.cache_ttl

    def _call_llm(self, prompt, system_prompt=None, max_tokens=1500, temperature=0.1):
        # Use Provider API auto-discovered from openclaw.json
        # Every OpenClaw user has at least one provider configured (required for OpenClaw itself)
        if self.provider_url and self.provider_api_key and self.provider_model:
            result = self._call_provider(prompt, system_prompt, max_tokens, temperature)
            if result is not None: return result
        
        _p("⚠️  未检测到 LLM Provider 配置，跳过语义审计")
        _p("   提示: 请确保 ~/.openclaw/openclaw.json 中配置了 models.providers")
        return None

    def _call_provider(self, prompt, system_prompt, max_tokens, temperature):
        try:
            if self.provider_api_type == "anthropic-messages":
                return self._call_anthropic(prompt, system_prompt, max_tokens, temperature)
            else:
                return self._call_openai_compat(prompt, system_prompt, max_tokens, temperature)
        except Exception as e:
            _p(f"⚠️  Provider API 调用失败: {e}")
            return None

    def _call_anthropic(self, prompt, system_prompt, max_tokens, temperature):
        payload = {"model": self.provider_model, "max_tokens": max_tokens,
                   "temperature": temperature, "messages": [{"role": "user", "content": prompt}]}
        if system_prompt: payload["system"] = system_prompt
        # baseUrl may already include the full path (e.g., /api/anthropic/messages)
        # Try without appending /messages first, then fall back to appending
        url = self.provider_url.rstrip('/')
        if not url.endswith('/messages'):
            url = url + '/messages'
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={"Content-Type": "application/json", "x-api-key": self.provider_api_key,
                     "anthropic-version": "2023-06-01"}, method='POST')
        with urllib.request.urlopen(req, timeout=self.timeout_ms / 1000.0) as resp:
            body = json.loads(resp.read().decode('utf-8'))
            for block in body.get('content', []):
                if block.get('type') == 'text':
                    return self._parse_json(block['text'])
        return None

    def _call_openai_compat(self, prompt, system_prompt, max_tokens, temperature):
        messages = []
        if system_prompt: messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        payload = {"model": self.provider_model, "messages": messages,
                   "max_tokens": max_tokens, "temperature": temperature}
        
        # If provider_url already contains the full endpoint path, use it directly
        url = self.provider_url.rstrip('/')
        if not (url.endswith('/chat/completions') or url.endswith('/completions')):
            url = f"{url}/chat/completions"
        
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.provider_api_key}"}, method='POST')
        with urllib.request.urlopen(req, timeout=self.timeout_ms / 1000.0) as resp:
            body = json.loads(resp.read().decode('utf-8'))
            choices = body.get('choices', [])
            if choices:
                msg = choices[0].get('message', {})
                # Reasoning models put ALL output in reasoning_content
                # We need to extract structured findings from there
                content = msg.get('content', '')
                reasoning = msg.get('reasoning_content', '')
                
                # Try content first (if model outputs JSON directly)
                if content.strip():
                    result = self._parse_json(content)
                    if result: return result
                
                # Fall back to reasoning_content extraction
                if reasoning.strip():
                    result = self._parse_json(reasoning)
                    if result: return result
                    # If reasoning model didn't output JSON, extract structured findings
                    return self._extract_from_reasoning_text(reasoning)
        return None

    def _parse_json(self, content):
        if not content: return None
        
        # Try direct parse first
        try: return json.loads(content)
        except json.JSONDecodeError: pass
        
        # Try extracting from markdown code blocks
        m = re.search(r'```(?:json)?\s*([\s\S]*?)```', content)
        if m:
            try: return json.loads(m.group(1))
            except json.JSONDecodeError: pass
        
        # For reasoning models: find JSON objects by tracking brace depth
        start_idx = -1
        depth = 0
        in_string = False
        escape_next = False
        
        for i, char in enumerate(content):
            if escape_next:
                escape_next = False
                continue
            if char == '\\':
                escape_next = True
                continue
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            
            if char == '{':
                if depth == 0:
                    start_idx = i
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0 and start_idx != -1:
                    candidate = content[start_idx:i+1]
                    try:
                        result = json.loads(candidate)
                        if isinstance(result, dict) and ('risk_level' in result or 'findings' in result or 'risks' in result or 'vulnerabilities' in result):
                            return result
                    except json.JSONDecodeError:
                        pass
                    start_idx = -1
        
        # If no JSON found, extract structured findings from reasoning text
        # This handles cases where reasoning models think through everything but never output JSON
        return self._extract_from_reasoning_text(content)
    
    def _extract_from_reasoning_text(self, text):
        """从推理模型的 thinking process 中提取安全发现。
        
        策略：先尝试从全文中提取 JSON 对象，失败后再用结构化提取。
        严格过滤推理过程文本（步骤编号、指令性动词等）。
        """
        # ── 策略 1: 先从全文中找 JSON 对象 ──
        start_idx = -1
        depth = 0
        in_string = False
        escape_next = False
        
        for i, char in enumerate(text):
            if escape_next:
                escape_next = False
                continue
            if char == '\\':
                escape_next = True
                continue
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == '{':
                if depth == 0:
                    start_idx = i
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0 and start_idx != -1:
                    candidate = text[start_idx:i+1]
                    try:
                        result = json.loads(candidate)
                        if isinstance(result, dict) and ('risk_level' in result or 'findings' in result):
                            return self._parse_result(result, '')
                    except json.JSONDecodeError:
                        pass
                    start_idx = -1
        
        # ── 策略 2: 结构化提取（严格过滤）──
        findings = []
        seen_categories = {}
        
        category_keywords = {
            'malicious_code': [
                r'remote\s*code\s*execution', r'RCE', r'curl.*\|\s*bash',
                r'eval\s*\(', r'exec\s*\(', r'os\.system',
                r'远程代码执行', r'恶意代码', r'malicious\s*(code|binary)',
                r'untrusted\s+binary', r'\.exe\b',
            ],
            'credential_leak': [
                r'credential', r'password', r'secret', r'token',
                r'API\s*key', r'凭证', r'密码', r'密钥',
                r'insecure\s+storage', r'\.env\b',
            ],
            'suspicious_network': [
                r'http://\d', r'raw\s*IP', r'IP\s*直连',
                r'suspicious\s*network', r'可疑连接',
            ],
            'excessive_permissions': [
                r'To[sS]', r'Terms\s*of\s*Service', r'excessive\s*permission',
                r'violat',
            ],
            'social_engineering': [
                r'urgency', r'紧迫', r'社会工程', r'decoy', r'伪装',
            ],
            'code_obfuscation': [
                r'obfuscat', r'混淆', r'base64', r'encoded',
            ],
        }
        
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        # 按段落拆分
        paragraphs = re.split(r'\n{2,}', text)
        
        for para in paragraphs:
            # ── 严格过滤推理过程文本 ──
            skip_patterns = [
                r'^\d+\.\s+\*\*',              # "1. **Analyze...**"
                r'(?:Analyze|Determine|Check|Review|Draft|Ensure|Verify)\s+(?:the|all|proper)',
                r'JSON\s*(?:syntax|format|valid|schema)',
                r'trailing\s*comma',
                r'match(?:es)?\s+(?:the\s+)?schema',
                r'File\s+Name:',
                r'Description:\s+Automated',
                r'Critical\s+Section',
                r'Since\s+there\s+are\s+CRITICAL',
                r'the\s+overall.*risk_level.*must\s+be',
                r'^\s*```',
                r'^\s*\*\s+severity:',           # 小写单独属性行
                r'^\s*\*\s+category:',
                r'^\s*\*\s+title:',
                r'^\s*\*\s+description:',
                r'^\s*\*\s+line:',
                r'^\s*\*\s+evidence:',
                r'^\s*\*\s+confidence:',
                r'^\s*\*\s+remediation:',
                r'Refine\s+Findings',
                r'Draft\s+the\s+JSON',
                r'Ensure\s+(?:all|valid|proper)',
            ]
            if any(re.search(p, para, re.IGNORECASE) for p in skip_patterns):
                continue
            
            # ── 查找 Severity 标记 ──
            sev_match = None
            for pattern, sev in [('CRITICAL', 'CRITICAL'), ('HIGH', 'HIGH'), 
                                  ('MEDIUM', 'MEDIUM'), ('LOW', 'LOW')]:
                if re.search(rf'\b{pattern}\b', para):
                    sev_match = sev
                    break
            
            if not sev_match:
                continue
            
            # ── 确定 category ──
            category = 'malicious_code'
            for cat, keywords in category_keywords.items():
                for kw in keywords:
                    if re.search(kw, para, re.IGNORECASE):
                        category = cat
                        break
                if category != 'malicious_code':
                    break
            
            # ── 只提取 Evidence/Line 行 ──
            evidence_match = re.search(r'(?:Evidence|evidence):\s*(.+?)(?:\n|$)', para)
            evidence = evidence_match.group(1).strip() if evidence_match else ''
            
            line_match = re.search(r'(?:Line|line):\s*(.+?)(?:\n|$)', para)
            line_info = line_match.group(1).strip() if line_match else ''
            
            if not evidence and not line_info:
                continue
            
            # ── 构建简洁描述 ──
            desc_parts = []
            if evidence:
                desc_parts.append(evidence[:150])
            if line_info:
                desc_parts.append(f'位置: {line_info}')
            description = '. '.join(desc_parts)[:150]
            
            # ── 标题 ──
            title_map = {
                'malicious_code': '恶意代码检测',
                'credential_leak': '凭证泄露风险',
                'suspicious_network': '可疑网络连接',
                'excessive_permissions': '过度权限/违反服务条款',
                'social_engineering': '社会工程学攻击',
                'code_obfuscation': '代码混淆',
            }
            title = title_map.get(category, '潜在安全风险')
            
            # ── 去重：同 category 只保留最高严重等级 ──
            if category in seen_categories:
                existing_sev = severity_order.get(seen_categories[category]['severity'], 0)
                new_sev = severity_order.get(sev_match, 0)
                if new_sev > existing_sev:
                    seen_categories[category] = {
                        'severity': sev_match, 'title': title,
                        'description': description, 'confidence': 0.75,
                        'remediation': '需要人工审查',
                    }
            else:
                seen_categories[category] = {
                    'severity': sev_match, 'title': title,
                    'description': description, 'confidence': 0.75,
                    'remediation': '需要人工审查',
                }
        
        for cat, finding in seen_categories.items():
            findings.append({
                'severity': finding['severity'],
                'category': cat,
                'title': finding['title'][:120],
                'description': finding['description'],
                'confidence': finding['confidence'],
                'remediation': finding['remediation'],
            })
        
        # ── Fallback: 关键词扫描（带上下文提取）──
        if not findings:
            fallback_checks = [
                (r'(?:remote\s*code\s*execution|RCE|curl.*\|\s*bash)',
                 'CRITICAL', 'malicious_code', '远程代码执行风险'),
                (r'(?:credential|password|secret|token|\.env\b|凭证|密码|密钥)',
                 'HIGH', 'credential_leak', '凭证泄露风险'),
            ]
            for pattern, sev, cat, title in fallback_checks:
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    # 智能提取上下文：优先找行边界，避免截断单词
                    lines_before = text[:m.start()].split('\n')
                    lines_after = text[m.end():].split('\n')
                    
                    # 取前后各 2-3 行
                    context_lines = lines_before[-2:] + lines_after[:3]
                    context = '\n'.join(context_lines).strip()
                    
                    # 如果太短，尝试更大的窗口
                    if len(context) < 50:
                        start = max(0, m.start() - 150)
                        end = min(len(text), m.end() + 200)
                        context = text[start:end].strip()
                    
                    # 清理多行空白
                    context = re.sub(r'\n{3,}', '\n\n', context)
                    
                    # 截取时确保不截断单词（找最近的空格）
                    if len(context) > 300:
                        cut_at = context.rfind(' ', 0, 300)
                        if cut_at > 200:
                            context = context[:cut_at] + '...'
                        else:
                            context = context[:300] + '...'
                    
                    findings.append({
                        'severity': sev, 'category': cat,
                        'title': title,
                        'description': f'📋 检测到相关模式:\n```\n{context}\n```',
                        'confidence': 0.7, 'remediation': '需要人工审查'
                    })
        
        if findings:
            severities = [f['severity'] for f in findings]
            if 'CRITICAL' in severities:
                risk_level = 'CRITICAL'
            elif 'HIGH' in severities:
                risk_level = 'HIGH'
            elif 'MEDIUM' in severities:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            return {
                'risk_level': risk_level,
                'findings': findings,
                'summary': f'从推理分析中提取到 {len(findings)} 个安全问题'
            }
        
        return None

    def quick_assess(self, code):
        risk_score = 0; indicators = []
        for pattern, category, desc, score in QUICK_RISK_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                risk_score += score
                indicators.append({'category': category, 'description': desc, 'score': score})
        if risk_score < 25: level = "LOW"
        elif risk_score < 50: level = "MEDIUM"
        elif risk_score < 75: level = "HIGH"
        else: level = "CRITICAL"
        return {'risk_level': level, 'risk_score': risk_score, 'indicators': indicators,
                'needs_llm': risk_score >= 25}

    def analyze_with_llm(self, code, file_path):
        user_prompt = (f"请分析以下技能代码的安全风险：\n\n文件: {file_path}\n\n"
                       f"代码内容:\n'''\n{code[:12000]}\n'''\n\n请返回严格的 JSON 格式审计报告。")
        result = self._call_llm(prompt=user_prompt, system_prompt=SYSTEM_PROMPT,
                                max_tokens=1500, temperature=0.1)
        if not result: return []
        return self._parse_result(result, file_path)

    def _parse_result(self, result, file_path):
        findings = []
        severity_map = {'Critical': 'CRITICAL', 'critical': 'CRITICAL', 
                      'High': 'HIGH', 'high': 'HIGH',
                      'Medium': 'MEDIUM', 'medium': 'MEDIUM',
                      'Low': 'LOW', 'low': 'LOW'}
        
        # Format 1: Standard {"risk_level": ..., "findings": [...]}
        for f in result.get('findings', []):
            try:
                findings.append(SemanticFinding(
                    severity=f.get('severity', 'MEDIUM'), category=f.get('category', 'other'),
                    title=f.get('title', '未知风险'), description=f.get('description', 'N/A'),
                    file_path=f.get('file', file_path), line=f.get('line'),
                    evidence=f.get('evidence'), confidence=float(f.get('confidence', 0.5)),
                    remediation=f.get('remediation', '需要人工审查')))
            except Exception as e:
                _p(f"⚠️  解析发现项失败: {e}")
        
        # Format 2: {"risks": [...]}
        if not findings:
            for r in result.get('risks', []):
                try:
                    sev = severity_map.get(r.get('risk_level', r.get('severity', 'MEDIUM')), 'MEDIUM')
                    findings.append(SemanticFinding(
                        severity=sev, category='malicious_code',
                        title=r.get('type', r.get('title', '未知风险')),
                        description=r.get('description', 'N/A'),
                        file_path=file_path, line=None,
                        evidence=r.get('evidence'), confidence=0.8,
                        remediation='需要人工审查'))
                except Exception as e:
                    _p(f"⚠️  解析风险项失败: {e}")
        
        # Format 3: {"audit_result": ..., "vulnerabilities": [...]}
        if not findings:
            for v in result.get('vulnerabilities', []):
                try:
                    sev = severity_map.get(v.get('severity', 'MEDIUM'), 'MEDIUM')
                    findings.append(SemanticFinding(
                        severity=sev, category='malicious_code',
                        title=v.get('type', v.get('title', '未知风险')),
                        description=v.get('description', 'N/A'),
                        file_path=file_path, line=None,
                        evidence=v.get('evidence'), confidence=0.85,
                        remediation='需要人工审查'))
                except Exception as e:
                    _p(f"⚠️  解析漏洞项失败: {e}")
        
        return findings

    def audit_file(self, file_path, content):
        ck = self._cache_key(str(file_path), content)
        if ck in self._cache and self._cache_valid(self._cache[ck]):
            _p(f"📋 缓存命中: {file_path.name}")
            return [SemanticFinding(**f) for f in self._cache[ck]['findings']]
        findings = []
        quick = self.quick_assess(content)
        if quick['needs_llm'] and self.llm_enabled:
            _p(f"🔍 LLM 深度分析: {file_path.name} (quick score={quick['risk_score']})")
            findings = self.analyze_with_llm(content, str(file_path))
        elif quick['needs_llm']:
            _p(f"⚠️  LLM 已禁用，跳过深度分析: {file_path.name}")
        else:
            _p(f"✅ 快速检查通过: {file_path.name}")
        if findings:
            self._cache[ck] = {'findings': [asdict(f) for f in findings],
                               'cached_at': datetime.now().isoformat()}
            self._save_cache()
        return findings

    def audit_directory(self, dir_path, recursive=True, path_filter=None):
        from path_filter import PathFilter as PF
        pf = path_filter or PF()
        all_findings = []; extensions = {'.py', '.js', '.ts', '.sh', '.md', '.yaml', '.yml'}
        files = list(dir_path.rglob('*') if recursive else dir_path.glob('*'))
        file_list = [fp for fp in files if fp.is_file() and fp.suffix.lower() in extensions
                     and not pf.should_ignore(fp, dir_path)]
        _p(f"📁 发现 {len(file_list)} 个文件待审计")
        for i, fp in enumerate(file_list):
            try:
                content = fp.read_text(encoding='utf-8')
                if len(content) > 100:
                    _p(f"[{i+1}/{len(file_list)}] 审计: {fp.name}")
                    all_findings.extend(self.audit_file(fp, content))
            except Exception as e:
                _p(f"⚠️  审计失败 {fp}: {e}")
        return all_findings

    def clear_cache(self):
        self._cache = {}
        if self._cache_file.exists(): self._cache_file.unlink()
        _p("✅ 缓存已清除")