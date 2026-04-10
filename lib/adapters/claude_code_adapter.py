#!/usr/bin/env python3
"""
Claude Code Adapter - Claude Code (claude) CLI 的适配器实现

使用 claude CLI 的 --print 选项执行审查任务
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from ..agent_adapter import AgentAdapter, AdapterType, ReviewTask, ReviewResult


class ClaudeCodeAdapter(AgentAdapter):
    """Claude Code 适配器"""

    PLATFORM_NAME = "claude"
    ADAPTER_TYPE = AdapterType.CLAUDE_CODE

    # Claude Code CLI 路径
    CLI_PATHS = [
        'claude',
        '/usr/local/bin/claude',
        str(Path.home() / '.claude' / 'bin' / 'claude'),
    ]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.cli_path = self.config.get('cli_path', 'claude')
        self.result_dir = Path(self.config.get('result_dir', '/tmp/claude_reviews'))
        self._cli_version: Optional[str] = None

    def initialize(self) -> bool:
        """初始化 Claude Code 适配器"""
        # 查找 CLI
        if not self._find_cli():
            return False

        # 检查版本
        if not self._check_version():
            return False

        # 确保结果目录存在
        try:
            self.result_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        self._initialized = True
        return True

    def _find_cli(self) -> bool:
        """查找 Claude CLI"""
        # 尝试配置的路径
        for cli in [self.cli_path] + self.CLI_PATHS:
            try:
                result = subprocess.run(
                    [cli, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.cli_path = cli
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return False

    def _check_version(self) -> bool:
        """检查 CLI 版本"""
        try:
            result = subprocess.run(
                [self.cli_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self._cli_version = result.stdout.strip()
                return True
        except Exception:
            pass
        return False

    def is_available(self) -> bool:
        """检查适配器是否可用"""
        return self._initialized and self._cli_version is not None

    def submit_review_task(self, prompt: str, context: Dict) -> str:
        """提交审查任务"""
        task_id = f"claude_review_{int(time.time() * 1000)}"

        # 构建完整的 prompt
        full_prompt = self._build_review_prompt(prompt, context)

        # 创建任务对象
        task = ReviewTask(
            task_id=task_id,
            prompt=full_prompt,
            context=context,
            status="running"
        )
        self._tasks[task_id] = task

        # 异步执行审查
        self._execute_review_async(task_id, full_prompt)

        return task_id

    def _build_review_prompt(self, prompt: str, context: Dict) -> str:
        """构建审查 prompt"""
        skill_name = context.get('skill_name', 'unknown')
        findings_count = context.get('findings_count', 0)

        return f"""你是一位资深安全工程师，正在审查 AI Agent Skill 的安全扫描结果。

## 技能信息
- 名称: {skill_name}
- 发现数量: {findings_count}

## 待审查发现

{prompt}

## 你的任务

对每条发现做出判断，返回 JSON 数组，每个元素包含：
{{
  "id": "发现的唯一标识",
  "verdict": "TP" | "FP" | "HUMAN_REVIEW",
  "confidence": 0.0-1.0,
  "reasoning": "简短理由（中文，50字以内）",
  "true_severity": "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"（如果与原始不同则修改）
}}

常见误报模式：
1. 安全工具自身的规则定义
2. 参考数据文件（JSON 列出已知恶意技能名）
3. 安全审计/修复脚本
4. 文档中的关键词
5. 安全的安装钩子
6. 负面示例/反例

⚠️ IMPORTANT: 只返回 JSON 数组，不要任何其他文本。"""

    def _execute_review_async(self, task_id: str, prompt: str):
        """异步执行审查"""
        # 写入临时文件
        prompt_file = self.result_dir / f"{task_id}_prompt.txt"
        result_file = self.result_dir / f"{task_id}_result.json"

        try:
            prompt_file.write_text(prompt, encoding='utf-8')

            # 构建 Claude CLI 命令
            cmd = [
                self.cli_path,
                '--print',
                '--no-color',
                f'请读取文件 {prompt_file} 中的审查任务，执行安全审查，将结果直接输出为 JSON 数组格式（不要任何其他文本）。'
            ]

            # 异步执行
            subprocess.Popen(
                cmd,
                stdout=open(result_file, 'w'),
                stderr=subprocess.PIPE,
                env={**os.environ, 'NO_COLOR': '1'}
            )

        except Exception as e:
            print(f"Claude review execution failed: {e}", file=sys.stderr)
            task = self._tasks.get(task_id)
            if task:
                task.status = "failed"

    def get_review_result(self, task_id: str, timeout: int = 60) -> List[ReviewResult]:
        """获取审查结果"""
        if task_id not in self._tasks:
            return []

        task = self._tasks[task_id]
        result_file = self.result_dir / f"{task_id}_result.json"

        start_time = time.time()

        while time.time() - start_time < timeout:
            if result_file.exists() and result_file.stat().st_size > 0:
                try:
                    content = result_file.read_text(encoding='utf-8')
                    results = self._parse_json_response(content)
                    task.status = "completed"
                    task.completed_at = time.time()
                    return results
                except Exception as e:
                    print(f"Failed to parse result: {e}", file=sys.stderr)

            time.sleep(0.5)

        # 超时，返回空结果
        task.status = "timeout"
        return []

    def _parse_json_response(self, content: str) -> List[ReviewResult]:
        """解析 JSON 响应"""
        import re

        results = []

        # 提取 JSON 数组
        match = re.search(r'\[[\s\S]*\]', content)
        if not match:
            return results

        try:
            data = json.loads(match.group())
            if not isinstance(data, list):
                data = [data]

            for item in data:
                results.append(ReviewResult(
                    finding_id=item.get('id', item.get('rule_id', '')),
                    verdict=item.get('verdict', 'HUMAN_REVIEW'),
                    confidence=item.get('confidence', 0.5),
                    reasoning=item.get('reasoning', ''),
                    true_severity=item.get('true_severity'),
                    summary=item.get('summary', item.get('reasoning', ''))
                ))
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}", file=sys.stderr)

        return results

    def close(self):
        """清理资源"""
        # 清理临时文件
        for task_id in self._tasks:
            for suffix in ['_prompt.txt', '_result.json']:
                f = self.result_dir / f"{task_id}{suffix}"
                if f.exists():
                    try:
                        f.unlink()
                    except Exception:
                        pass

        super().close()