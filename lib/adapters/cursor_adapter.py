#!/usr/bin/env python3
"""
Cursor/Windsurf Adapter - Cursor IDE 和 Windsurf 的适配器实现

使用 cursor/windsurf CLI 执行审查任务
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


class CursorAdapter(AgentAdapter):
    """Cursor IDE 适配器"""

    PLATFORM_NAME = "cursor"
    ADAPTER_TYPE = AdapterType.CURSOR

    CLI_PATHS = ['cursor', '/usr/local/bin/cursor']

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.cli_path = self.config.get('cli_path', 'cursor')
        self.result_dir = Path(self.config.get('result_dir', '/tmp/cursor_reviews'))
        self._cli_version: Optional[str] = None

    def initialize(self) -> bool:
        if not self._find_cli():
            return False
        if not self._check_version():
            return False
        try:
            self.result_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._initialized = True
        return True

    def _find_cli(self) -> bool:
        for cli in [self.cli_path] + self.CLI_PATHS:
            try:
                result = subprocess.run([cli, '--version'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.cli_path = cli
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return False

    def _check_version(self) -> bool:
        try:
            result = subprocess.run([self.cli_path, '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self._cli_version = result.stdout.strip()
                return True
        except Exception:
            pass
        return False

    def is_available(self) -> bool:
        return self._initialized and self._cli_version is not None

    def submit_review_task(self, prompt: str, context: Dict) -> str:
        task_id = f"cursor_review_{int(time.time() * 1000)}"
        task = ReviewTask(
            task_id=task_id,
            prompt=prompt,
            context=context,
            status="running"
        )
        self._tasks[task_id] = task

        # Cursor 使用 MCP 协议，这里简化处理
        self._execute_via_mcp(task_id, prompt, context)

        return task_id

    def _execute_via_mcp(self, task_id: str, prompt: str, context: Dict):
        """通过 Cursor MCP 执行"""
        # 写入任务文件
        task_file = self.result_dir / f"{task_id}_task.json"
        result_file = self.result_dir / f"{task_id}_result.json"

        try:
            task_file.parent.mkdir(parents=True, exist_ok=True)
            task_data = {
                'task_id': task_id,
                'prompt': prompt,
                'context': context,
            }
            task_file.write_text(json.dumps(task_data, ensure_ascii=False, indent=2), encoding='utf-8')

            # Cursor CLI 目前不支持自动化执行，记录任务等待手动处理
            print(f"Cursor task created: {task_file}", file=sys.stderr)

        except Exception as e:
            print(f"Cursor task creation failed: {e}", file=sys.stderr)

    def get_review_result(self, task_id: str, timeout: int = 60) -> List[ReviewResult]:
        if task_id not in self._tasks:
            return []

        task = self._tasks[task_id]
        result_file = self.result_dir / f"{task_id}_result.json"

        start_time = time.time()
        while time.time() - start_time < timeout:
            if result_file.exists() and result_file.stat().st_size > 0:
                try:
                    content = result_file.read_text(encoding='utf-8')
                    results = self._parse_results(content)
                    task.status = "completed"
                    task.completed_at = time.time()
                    return results
                except Exception as e:
                    print(f"Parse error: {e}", file=sys.stderr)
            time.sleep(0.5)

        task.status = "timeout"
        return []

    def _parse_results(self, content: str) -> List[ReviewResult]:
        import re
        results = []
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
        except json.JSONDecodeError:
            pass
        return results


class WindsurfAdapter(CursorAdapter):
    """Windsurf 适配器"""

    PLATFORM_NAME = "windsurf"
    ADAPTER_TYPE = AdapterType.WINDSURF

    CLI_PATHS = ['windsurf', '/usr/local/bin/windsurf']

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.cli_path = self.config.get('cli_path', 'windsurf')
        self.result_dir = Path(self.config.get('result_dir', '/tmp/windsurf_reviews'))