#!/usr/bin/env python3
"""
OpenClaw Adapter - OpenClaw 平台的适配器实现

使用 sessions_spawn API 与 OpenClaw 子 Agent 通信
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from ..agent_adapter import AgentAdapter, AdapterType, ReviewTask, ReviewResult


class OpenClawAdapter(AgentAdapter):
    """OpenClaw 适配器"""

    PLATFORM_NAME = "openclaw"
    ADAPTER_TYPE = AdapterType.OPENCLAW

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.task_dir = Path(self.config.get('task_dir', '~/.openclaw/tasks')).expanduser()
        self.result_dir = Path(self.config.get('result_dir', '~/.openclaw/results')).expanduser()
        self._sessions_spawn_available = False

    def initialize(self) -> bool:
        """初始化 OpenClaw 适配器"""
        try:
            # 检查是否在 OpenClaw 环境中运行
            import sys

            # 检查 sessions_spawn 是否可用
            if 'openclaw' in sys.modules or self._check_sessions_spawn():
                self._sessions_spawn_available = True

            # 确保目录存在
            self.task_dir.mkdir(parents=True, exist_ok=True)
            self.result_dir.mkdir(parents=True, exist_ok=True)

            self._initialized = True
            return True

        except Exception as e:
            print(f"OpenClaw adapter init failed: {e}", file=sys.stderr)
            self._initialized = False
            return False

    def _check_sessions_spawn(self) -> bool:
        """检查 sessions_spawn 是否可用"""
        try:
            # 尝试导入 OpenClaw 模块
            from openclaw import sessions_spawn
            return True
        except ImportError:
            # 检查环境变量
            return bool(os.environ.get('OPENCLAW_SESSION_ID'))

    def is_available(self) -> bool:
        """检查适配器是否可用"""
        if not self._initialized:
            return False
        return self._sessions_spawn_available or self._check_fallback_mode()

    def _check_fallback_mode(self) -> bool:
        """检查是否可以使用 fallback 模式（写入任务文件）"""
        return self.task_dir.exists() or self.task_dir.parent.exists()

    def submit_review_task(self, prompt: str, context: Dict) -> str:
        """提交审查任务"""
        task_id = f"openclaw_review_{int(time.time() * 1000)}"

        # 创建任务文件
        task_data = {
            'task_id': task_id,
            'mode': 'security_review',
            'prompt': prompt,
            'context': context,
            'skill_name': context.get('skill_name', 'unknown'),
            'findings_count': context.get('findings_count', 0),
            'platform': 'openclaw',
        }

        task_file = self.task_dir / f"{task_id}.json"
        try:
            task_file.parent.mkdir(parents=True, exist_ok=True)
            task_file.write_text(json.dumps(task_data, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception as e:
            # 尝试使用临时目录
            import tempfile
            temp_dir = Path(tempfile.gettempdir()) / 'openclaw_tasks'
            temp_dir.mkdir(parents=True, exist_ok=True)
            task_file = temp_dir / f"{task_id}.json"
            task_file.write_text(json.dumps(task_data, ensure_ascii=False, indent=2), encoding='utf-8')

        # 创建任务对象
        task = ReviewTask(
            task_id=task_id,
            prompt=prompt,
            context=context,
            status="pending"
        )
        self._tasks[task_id] = task

        # 尝试使用 sessions_spawn
        if self._sessions_spawn_available:
            self._submit_via_sessions_spawn(task_id, prompt, context)

        return task_id

    def _submit_via_sessions_spawn(self, task_id: str, prompt: str, context: Dict):
        """通过 sessions_spawn 提交任务"""
        try:
            from openclaw import sessions_spawn

            # 构建任务描述
            task_description = f"""请执行安全审查任务：

1. 读取任务文件 ~/.openclaw/tasks/{task_id}.json
2. 分析其中的安全发现，进行二次审查
3. 将审查结果写入 ~/.openclaw/results/{task_id}_result.json

审查标准：
- TP (True Positive): 确认是真实威胁
- FP (False Positive): 误报（安全工具自身、文档示例等）
- HUMAN_REVIEW: 需要人工审查

请返回 JSON 格式的审查结果。"""

            sessions_spawn(
                task=task_description,
                mode='background'
            )

            task = self._tasks.get(task_id)
            if task:
                task.status = "running"

        except Exception as e:
            print(f"sessions_spawn failed: {e}", file=sys.stderr)

    def get_review_result(self, task_id: str, timeout: int = 60) -> List[ReviewResult]:
        """获取审查结果"""
        if task_id not in self._tasks:
            return []

        task = self._tasks[task_id]
        start_time = time.time()

        # 尝试读取结果文件
        result_file = self.result_dir / f"{task_id}_result.json"

        # 也检查临时目录
        if not result_file.exists():
            import tempfile
            temp_dir = Path(tempfile.gettempdir()) / 'openclaw_tasks'
            result_file = temp_dir / f"{task_id}_result.json"

        while time.time() - start_time < timeout:
            if result_file.exists():
                try:
                    result_data = json.loads(result_file.read_text(encoding='utf-8'))
                    task.status = "completed"
                    task.completed_at = time.time()
                    return self._parse_results(result_data)
                except Exception as e:
                    print(f"Failed to read result: {e}", file=sys.stderr)

            # 检查 sessions_spawn 是否完成
            if task.status == "running" and self._sessions_spawn_available:
                # 等待子 Agent 完成
                time.sleep(1)
                continue

            # 如果是 fallback 模式，直接返回空结果让主程序处理
            if not self._sessions_spawn_available:
                task.status = "completed"
                return []

            time.sleep(0.5)

        # 超时
        task.status = "timeout"
        return []

    def _parse_results(self, result_data: Dict) -> List[ReviewResult]:
        """解析结果数据"""
        results = []

        # 支持多种格式
        findings = result_data.get('findings', result_data.get('results', []))

        for item in findings:
            results.append(ReviewResult(
                finding_id=item.get('id', item.get('rule_id', '')),
                verdict=item.get('verdict', 'HUMAN_REVIEW'),
                confidence=item.get('confidence', 0.5),
                reasoning=item.get('reasoning', ''),
                true_severity=item.get('true_severity'),
                summary=item.get('summary', item.get('reasoning', ''))
            ))

        return results

    def close(self):
        """清理资源"""
        super().close()
        self._sessions_spawn_available = False