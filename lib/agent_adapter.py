#!/usr/bin/env python3
"""
Agent Adapter - 跨平台 AI Agent 适配器抽象层

支持多种 AI Agent 平台的 LLM 审查：
- OpenClaw (sessions_spawn)
- Claude Code (claude CLI)
- Cursor (cursor CLI)
- Windsurf (windsurf CLI)
- QClaw (qclaw CLI)
- CoPaw (copaw CLI)
- GitHub Copilot (API)

设计理念：
- 抽象接口：统一的适配器接口
- 插件式架构：按需加载平台适配器
- 自动检测：自动识别当前环境
- 优雅降级：主适配器不可用时自动切换
"""

import os
import json
import time
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class AdapterType(Enum):
    """适配器类型"""
    OPENCLAW = "openclaw"
    CLAUDE_CODE = "claude"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    QCLAW = "qclaw"
    COP_AW = "copaw"
    GITHUB_COPILOT = "github_copilot"
    CUSTOM = "custom"


@dataclass
class ReviewTask:
    """审查任务"""
    task_id: str
    prompt: str
    context: Dict[str, Any]
    status: str = "pending"  # pending, running, completed, failed
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None


@dataclass
class ReviewResult:
    """单条发现的审查结果"""
    finding_id: str
    verdict: str           # TP / FP / HUMAN_REVIEW
    confidence: float     # 0.0-1.0
    reasoning: str        # 中文理由
    true_severity: Optional[str] = None
    summary: str = ""


@dataclass
class AdapterStatus:
    """适配器状态"""
    platform: str
    available: bool
    priority: int
    error: Optional[str] = None


class AgentAdapter(ABC):
    """Agent 平台适配器抽象基类"""

    PLATFORM_NAME: str = "unknown"
    ADAPTER_TYPE: AdapterType = AdapterType.CUSTOM

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._initialized = False
        self._tasks: Dict[str, ReviewTask] = {}

    @property
    def name(self) -> str:
        return self.PLATFORM_NAME

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @abstractmethod
    def initialize(self) -> bool:
        """初始化适配器，返回是否成功"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """检查适配器是否可用"""
        pass

    @abstractmethod
    def submit_review_task(self, prompt: str, context: Dict) -> str:
        """
        提交审查任务

        Args:
            prompt: 审查任务 prompt
            context: 额外上下文 (skill_name, findings_count 等)

        Returns:
            task_id: 任务标识符
        """
        pass

    @abstractmethod
    def get_review_result(self, task_id: str, timeout: int = 60) -> List[ReviewResult]:
        """
        获取审查结果

        Args:
            task_id: submit_review_task 返回的任务 ID
            timeout: 超时时间（秒）

        Returns:
            审查结果列表
        """
        pass

    def cancel_task(self, task_id: str) -> bool:
        """取消任务（可选实现）"""
        if task_id in self._tasks:
            self._tasks[task_id].status = "cancelled"
            return True
        return False

    def list_tasks(self) -> List[ReviewTask]:
        """列出所有任务"""
        return list(self._tasks.values())

    def close(self):
        """清理资源"""
        self._tasks.clear()
        self._initialized = False


class HeuristicAdapter(AgentAdapter):
    """启发式审查适配器 - 纯规则，不依赖外部服务"""

    PLATFORM_NAME = "heuristic"
    ADAPTER_TYPE = AdapterType.CUSTOM

    # 负面示例模式
    NEGATIVE_PATTERNS = [
        r'(?i)never\s+(do|run|execute|install|enable)',
        r'(?i)do\s+not\s+(disable|turn\s*off|remove|bypass|skip)',
        r'(?i)avoid\s+(disabling|turning\s*off|removing)',
        r'(?i)(should|must|will)\s+not\s+(disable|turn\s*off)',
        r'(?i)warning[:\s].*(?:not|never|avoid|don\'t)',
        r'注意[：:]?.*不?要',
        r'禁止', r'切勿', r'不要', r'请勿',
        r'反例', r'反面示例', r'错误示例',
        r'(?i)bad\s+(example|practice)',
        r'(?i)anti[- ]pattern',
    ]

    def initialize(self) -> bool:
        self._initialized = True
        return True

    def is_available(self) -> bool:
        return True  # 始终可用

    def submit_review_task(self, prompt: str, context: Dict) -> str:
        import uuid
        task_id = f"heuristic_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        task = ReviewTask(
            task_id=task_id,
            prompt=prompt,
            context=context,
            status="pending"
        )
        self._tasks[task_id] = task
        return task_id

    def get_review_result(self, task_id: str, timeout: int = 60) -> List[ReviewResult]:
        if task_id not in self._tasks:
            return []

        task = self._tasks[task_id]
        task.status = "running"

        # 从 prompt 中提取 findings
        findings = self._extract_findings_from_prompt(task.prompt)
        results = []

        for finding in findings:
            result = self._heuristic_review(finding)
            results.append(result)

        task.status = "completed"
        task.completed_at = time.time()

        return results

    def _extract_findings_from_prompt(self, prompt: str) -> List[Dict]:
        """从 prompt 中提取发现列表"""
        findings = []

        # 简单解析：查找 "发现 N" 段落
        import re
        pattern = r'### 发现 \d+\n(.*?)(?=### 发现|\Z)'
        matches = re.findall(pattern, prompt, re.DOTALL)

        for match in matches:
            finding = {}
            # 提取字段
            for line in match.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace('- ', '').replace(' ', '_')
                    value = value.strip()
                    finding[key] = value

            if finding:
                findings.append(finding)

        return findings

    def _heuristic_review(self, finding: Dict) -> ReviewResult:
        """启发式审查单条发现"""
        rule_id = finding.get('rule_id', finding.get('id', ''))
        title = finding.get('title', '')
        severity = finding.get('severity', 'UNKNOWN')
        file_path = finding.get('file', '')
        line_num = finding.get('line_number', '0')

        # 默认假设为真阳性
        verdict = "TP"
        confidence = 0.7
        reasoning = "启发式审查：未发现误报模式"

        # 检查是否为负面示例
        if file_path and line_num:
            try:
                line_num = int(line_num)
                fp = Path(file_path)
                if fp.exists():
                    lines = fp.read_text(encoding='utf-8', errors='ignore').split('\n')
                    start = max(0, line_num - 10)
                    end = min(len(lines), line_num + 10)
                    context = '\n'.join(lines[start:end]).lower()

                    for pattern in self.NEGATIVE_PATTERNS:
                        if re.search(pattern, context):
                            verdict = "FP"
                            confidence = 0.85
                            reasoning = "检测到负面示例模式"
                            break
            except Exception:
                pass

        return ReviewResult(
            finding_id=rule_id or title[:20],
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            true_severity=severity if verdict == "TP" else None,
            summary=reasoning
        )


class AgentAdapterFactory:
    """适配器工厂"""

    # 环境变量到平台的映射
    ENV_PLATFORM_MAP = {
        'OPENCLAW': AdapterType.OPENCLAW,
        'CODEBUDDY': 'codebuddy',
        'CURSOR': AdapterType.CURSOR,
        'WINDSURF': AdapterType.WINDSURF,
        'CLAUDE': AdapterType.CLAUDE_CODE,
        'ANTHROPIC_API_KEY': AdapterType.CLAUDE_CODE,
        'QCLAW': AdapterType.QCLAW,
        'COPAW': AdapterType.COP_AW,
        'GITHUB_TOKEN': AdapterType.GITHUB_COPILOT,
    }

    _adapters: Dict[str, type] = {}
    _initialized: bool = False

    @classmethod
    def register(cls, platform: str, adapter_class: type):
        """注册适配器"""
        cls._adapters[platform.lower()] = adapter_class

    @classmethod
    def create(cls, platform: str, config: Optional[Dict] = None) -> AgentAdapter:
        """创建适配器实例"""
        platform = platform.lower()

        if platform not in cls._adapters:
            raise ValueError(f"不支持的平台: {platform}，可用平台: {list(cls._adapters.keys())}")

        adapter = cls._adapters[platform](config)
        adapter.initialize()
        return adapter

    @classmethod
    def auto_detect(cls, config: Optional[Dict] = None) -> AgentAdapter:
        """自动检测并创建适配器"""

        # 1. 检查环境变量
        for env_var, platform in cls.ENV_PLATFORM_MAP.items():
            if os.environ.get(env_var):
                try:
                    adapter = cls.create(str(platform), config)
                    if adapter.is_available():
                        return adapter
                except Exception:
                    pass

        # 2. 检查进程环境
        try:
            import sys
            if 'openclaw' in sys.modules:
                return cls.create('openclaw', config)
        except Exception:
            pass

        # 3. 尝试检测 CLI 可用性
        for platform in ['claude', 'cursor', 'windsurf', 'qclaw', 'copaw']:
            try:
                adapter = cls.create(platform, config)
                if adapter.is_available():
                    return adapter
            except Exception:
                pass

        # 4. 降级到启发式
        return HeuristicAdapter(config)

    @classmethod
    def get_available_adapters(cls, config: Optional[Dict] = None) -> List[AdapterStatus]:
        """获取所有可用适配器及其状态"""
        results = []
        seen_platforms = set()  # 去重

        for platform in cls._adapters.keys():
            if platform in seen_platforms:
                continue
            seen_platforms.add(platform)

            try:
                adapter = cls.create(platform, config)
                results.append(AdapterStatus(
                    platform=platform,
                    available=adapter.is_available(),
                    priority=cls._get_platform_priority(platform)
                ))
            except Exception as e:
                results.append(AdapterStatus(
                    platform=platform,
                    available=False,
                    priority=999,
                    error=str(e)
                ))

        return sorted(results, key=lambda x: x.priority)

    @classmethod
    def _get_platform_priority(cls, platform: str) -> int:
        """获取平台优先级"""
        priorities = {
            'openclaw': 1,
            'claude': 2,
            'cursor': 3,
            'windsurf': 4,
            'qclaw': 5,
            'copaw': 6,
            'github_copilot': 7,
        }
        return priorities.get(platform, 100)


# 注册内置适配器
def _register_builtin_adapters():
    """注册内置适配器"""
    # 延迟导入避免循环依赖
    try:
        from .adapters import (
            OpenClawAdapter,
            ClaudeCodeAdapter,
            CursorAdapter,
            WindsurfAdapter,
            QClawAdapter,
            CoPawAdapter,
        )

        AgentAdapterFactory.register('openclaw', OpenClawAdapter)
        AgentAdapterFactory.register('claude', ClaudeCodeAdapter)
        AgentAdapterFactory.register('claude_code', ClaudeCodeAdapter)
        AgentAdapterFactory.register('cursor', CursorAdapter)
        AgentAdapterFactory.register('windsurf', WindsurfAdapter)
        AgentAdapterFactory.register('qclaw', QClawAdapter)
        AgentAdapterFactory.register('copaw', CoPawAdapter)

    except ImportError as e:
        import sys
        print(f"Warning: 部分适配器不可用: {e}", file=sys.stderr)

    # 始终注册启发式适配器（降级方案）
    if 'heuristic' not in AgentAdapterFactory._adapters:
        AgentAdapterFactory.register('heuristic', HeuristicAdapter)


# 自动注册
_register_builtin_adapters()


# 便捷函数
def create_adapter(platform: str = "auto", config: Optional[Dict] = None) -> AgentAdapter:
    """创建适配器的便捷函数"""
    if platform == "auto":
        return AgentAdapterFactory.auto_detect(config)
    return AgentAdapterFactory.create(platform, config)


def get_available_adapters(config: Optional[Dict] = None) -> List[AdapterStatus]:
    """获取可用适配器的便捷函数"""
    return AgentAdapterFactory.get_available_adapters(config)