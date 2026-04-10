#!/usr/bin/env python3
"""
QClaw/CoPaw Adapter - QClaw 和 CoPaw 的适配器实现

QClaw: 蚂蚁内部的 AI Agent 平台
CoPaw: 蚂蚁内部的另一个 AI Agent 平台
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


class QClawAdapter(AgentAdapter):
    """QClaw 适配器"""

    PLATFORM_NAME = "qclaw"
    ADAPTER_TYPE = AdapterType.QCLAW

    CLI_PATHS = ['qclaw', '/usr/local/bin/qclaw', str(Path.home() / 'bin' / 'qclaw')]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.cli_path = self.config.get('cli_path', 'qclaw')
        self.result_dir = Path(self.config.get('result_dir', '/tmp/qclaw_reviews'))
        self._api_endpoint = self.config.get('api_endpoint', 'http://localhost:8080')
        self._cli_version: Optional[str] = None

    def initialize(self) -> bool:
        # QClaw 可能作为服务运行，检查 API 或 CLI
        if self._check_api():
            self._initialized = True
            return True

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

    def _check_api(self) -> bool:
        """检查 QClaw API 是否可用"""
        try:
            import requests
            response = requests.get(f"{self._api_endpoint}/health", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

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
        return self._initialized

    def submit_review_task(self, prompt: str, context: Dict) -> str:
        task_id = f"qclaw_review_{int(time.time() * 1000)}"

        task = ReviewTask(
            task_id=task_id,
            prompt=prompt,
            context=context,
            status="pending"
        )
        self._tasks[task_id] = task

        # 优先使用 API
        if self._check_api():
            self._submit_via_api(task_id, prompt, context)
        elif self._cli_version:
            self._submit_via_cli(task_id, prompt, context)

        return task_id

    def _submit_via_api(self, task_id: str, prompt: str, context: Dict):
        """通过 API 提交任务"""
        try:
            import requests

            payload = {
                'task_id': task_id,
                'prompt': prompt,
                'context': context,
                'skill_name': context.get('skill_name', 'unknown'),
                'findings_count': context.get('findings_count', 0),
            }

            response = requests.post(
                f"{self._api_endpoint}/api/review",
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                task = self._tasks.get(task_id)
                if task:
                    task.status = "running"

        except Exception as e:
            print(f"QClaw API submission failed: {e}", file=sys.stderr)

    def _submit_via_cli(self, task_id: str, prompt: str, context: Dict):
        """通过 CLI 提交任务"""
        try:
            task_file = self.result_dir / f"{task_id}_task.json"
            task_file.parent.mkdir(parents=True, exist_ok=True)

            task_data = {
                'task_id': task_id,
                'prompt': prompt,
                'context': context,
            }
            task_file.write_text(json.dumps(task_data, ensure_ascii=False, indent=2), encoding='utf-8')

            # 使用 qclaw CLI 执行
            cmd = [self.cli_path, 'review', '--task-file', str(task_file)]
            subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            task = self._tasks.get(task_id)
            if task:
                task.status = "running"

        except Exception as e:
            print(f"QClaw CLI submission failed: {e}", file=sys.stderr)

    def get_review_result(self, task_id: str, timeout: int = 60) -> List[ReviewResult]:
        if task_id not in self._tasks:
            return []

        task = self._tasks[task_id]

        # 尝试从 API 获取
        if self._check_api():
            return self._get_from_api(task_id, timeout)

        # 从文件获取
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
                except Exception:
                    pass
            time.sleep(0.5)

        task.status = "timeout"
        return []

    def _get_from_api(self, task_id: str, timeout: int) -> List[ReviewResult]:
        """从 API 获取结果"""
        try:
            import requests
            response = requests.get(
                f"{self._api_endpoint}/api/review/{task_id}",
                timeout=timeout
            )
            if response.status_code == 200:
                data = response.json()
                task = self._tasks.get(task_id)
                if task:
                    task.status = "completed"
                    task.completed_at = time.time()
                return self._parse_results(json.dumps(data.get('results', [])))
        except Exception as e:
            print(f"QClaw API result fetch failed: {e}", file=sys.stderr)

        task = self._tasks.get(task_id)
        if task:
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


class CoPawAdapter(QClawAdapter):
    """CoPaw 适配器"""

    PLATFORM_NAME = "copaw"
    ADAPTER_TYPE = AdapterType.COPAW

    CLI_PATHS = ['copaw', '/usr/local/bin/copaw', str(Path.home() / 'bin' / 'copaw')]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.cli_path = self.config.get('cli_path', 'copaw')
        self.result_dir = Path(self.config.get('result_dir', '/tmp/copaw_reviews'))
        self._api_endpoint = self.config.get('api_endpoint', 'http://localhost:9090')