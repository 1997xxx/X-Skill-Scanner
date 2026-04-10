#!/usr/bin/env python3
"""
Platform Registry - 跨平台 AI Agent 适配器注册中心

统一管理各平台的检测、配置获取和 skill 扫描。

支持的平台:
- OpenClaw (蚂蚁)
- Claude Code
- Cursor
- Windsurf
- QClaw
- CoPaw
- CodeBuddy
- 其他 AI Agent

设计原则:
1. 自动检测 - 智能识别当前平台
2. 插件式架构 - 按需加载平台适配器
3. 优雅降级 - 主平台不可用时自动切换
4. 统一接口 - 一致的配置获取方式
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod


class PlatformType(Enum):
    """平台类型"""
    OPENCLAW = "openclaw"
    CLAUDE_CODE = "claude_code"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    QCLAW = "qclaw"
    COP_AW = "copaw"
    CODEBUDDY = "codebuddy"
    CUSTOM = "custom"


@dataclass
class LLMConfig:
    """LLM 配置"""
    provider: str
    base_url: str
    model: str
    api_key: str = ""
    api_type: str = "openai-chat"
    has_api_key: bool = False
    key_prefix: str = ""
    config_source: str = ""


@dataclass
class PlatformInfo:
    """平台信息"""
    platform: PlatformType
    name: str
    detected: bool
    config: Optional[LLMConfig] = None
    skills_dirs: List[Path] = field(default_factory=list)
    error: Optional[str] = None


class BasePlatformAdapter(ABC):
    """平台适配器基类"""

    PLATFORM_TYPE: PlatformType = PlatformType.CUSTOM
    PLATFORM_NAME: str = "unknown"

    # 平台特征 (用于自动检测)
    DETECT_ENVS: List[str] = []  # 环境变量名
    DETECT_FILES: List[str] = []  # 特征文件
    DETECT_PROCS: List[str] = []  # 特征进程

    # Skill 目录
    SKILLS_DIRS: List[Path] = []

    def __init__(self):
        self._detected = False
        self._llm_config: Optional[LLMConfig] = None

    @property
    def platform_type(self) -> PlatformType:
        return self.PLATFORM_TYPE

    @property
    def platform_name(self) -> str:
        return self.PLATFORM_NAME

    def detect(self) -> bool:
        """
        检测是否在当前平台环境中

        Returns:
            True 如果检测成功
        """
        if self._detected:
            return True

        # 1. 检查环境变量
        for env_var in self.DETECT_ENVS:
            if os.environ.get(env_var):
                self._detected = True
                return True

        # 2. 检查特征文件
        for file_path in self.DETECT_FILES:
            path = Path(file_path).expanduser()
            if path.exists():
                self._detected = True
                return True

        # 3. 检查特征进程
        for proc_name in self.DETECT_PROCS:
            if self._is_process_running(proc_name):
                self._detected = True
                return True

        return False

    def _is_process_running(self, name: str) -> bool:
        """检查进程是否运行"""
        try:
            import subprocess
            result = subprocess.run(
                ['pgrep', '-f', name],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_llm_config(self) -> Optional[LLMConfig]:
        """
        获取 LLM 配置

        子类需要实现此方法

        Returns:
            LLMConfig 或 None
        """
        return self._llm_config

    def get_api_key(self) -> str:
        """
        获取 API Key (处理加密/引用)

        子类需要实现此方法

        Returns:
            API Key 字符串
        """
        config = self.get_llm_config()
        return config.api_key if config else ""

    def get_skills_dirs(self) -> List[Path]:
        """
        获取平台的 skills 目录列表

        Returns:
            Path 列表
        """
        # 过滤存在的目录
        return [p.expanduser() for p in self.SKILLS_DIRS if p.expanduser().exists()]

    def _resolve_env_var(self, value: str) -> str:
        """
        解析环境变量引用

        支持格式: ${ENV_VAR} 或 $ENV_VAR
        """
        if not value:
            return value

        # 处理 ${VAR} 格式
        import re
        pattern = r'\$\{([^}]+)\}'
        matches = re.findall(pattern, value)
        for var_name in matches:
            env_value = os.environ.get(var_name, '')
            value = value.replace(f'${{{var_name}}}', env_value)

        # 处理 $VAR 格式
        pattern = r'\$(\w+)'
        matches = re.findall(pattern, value)
        for var_name in matches:
            if f'${{{var_name}}}' not in value:  # 避免重复替换
                env_value = os.environ.get(var_name, '')
                value = value.replace(f'${var_name}', env_value)

        return value


class PlatformRegistry:
    """平台注册中心"""

    _adapters: Dict[PlatformType, BasePlatformAdapter] = {}
    _detected_platform: Optional[PlatformType] = None

    @classmethod
    def register(cls, adapter: BasePlatformAdapter):
        """注册平台适配器"""
        cls._adapters[adapter.platform_type] = adapter

    @classmethod
    def detect_platform(cls) -> Optional[PlatformType]:
        """
        自动检测当前平台

        Returns:
            PlatformType 或 None
        """
        if cls._detected_platform:
            return cls._detected_platform

        # 按优先级检测
        for platform_type, adapter in cls._adapters.items():
            if adapter.detect():
                cls._detected_platform = platform_type
                return platform_type

        return None

    @classmethod
    def get_adapter(cls, platform: Optional[PlatformType] = None) -> Optional[BasePlatformAdapter]:
        """
        获取平台适配器

        Args:
            platform: 指定平台，None 则自动检测

        Returns:
            BasePlatformAdapter 或 None
        """
        if platform is None:
            platform = cls.detect_platform()

        if platform:
            return cls._adapters.get(platform)

        return None

    @classmethod
    def get_llm_config(cls, platform: Optional[PlatformType] = None) -> Optional[LLMConfig]:
        """获取 LLM 配置"""
        adapter = cls.get_adapter(platform)
        if adapter:
            return adapter.get_llm_config()
        return None

    @classmethod
    def get_api_key(cls, platform: Optional[PlatformType] = None) -> str:
        """获取 API Key"""
        adapter = cls.get_adapter(platform)
        if adapter:
            return adapter.get_api_key()
        return ""

    @classmethod
    def get_all_skills_dirs(cls) -> List[Path]:
        """获取所有平台的 skills 目录"""
        dirs = []
        for adapter in cls._adapters.values():
            dirs.extend(adapter.get_skills_dirs())
        return dirs

    @classmethod
    def get_platform_info(cls) -> PlatformInfo:
        """
        获取当前平台完整信息

        Returns:
            PlatformInfo
        """
        platform_type = cls.detect_platform()

        if not platform_type:
            return PlatformInfo(
                platform=PlatformType.CUSTOM,
                name="unknown",
                detected=False,
                error="未检测到支持的 AI Agent 平台"
            )

        adapter = cls._adapters.get(platform_type)
        if not adapter:
            return PlatformInfo(
                platform=platform_type,
                name=platform_type.value,
                detected=True,
                error="平台已检测但无适配器"
            )

        return PlatformInfo(
            platform=platform_type,
            name=adapter.platform_name,
            detected=True,
            config=adapter.get_llm_config(),
            skills_dirs=adapter.get_skills_dirs()
        )


# ─── 内置平台适配器 ──────────────────────────────────────────────

class OpenClawAdapter(BasePlatformAdapter):
    """OpenClaw 平台适配器"""

    PLATFORM_TYPE = PlatformType.OPENCLAW
    PLATFORM_NAME = "OpenClaw"

    DETECT_ENVS = ['OPENCLAW', 'OPENCLAW_SESSION_ID', 'OPENCLAW_HOME']
    DETECT_FILES = [
        '~/.openclaw/openclaw.json',
        '~/.openclaw/config.json'
    ]
    DETECT_PROCS = ['openclaw', 'claw']

    SKILLS_DIRS = [
        Path.home() / '.openclaw' / 'skills',
        Path.home() / '.openclaw' / 'workspace' / 'skills',
    ]

    def get_llm_config(self) -> Optional[LLMConfig]:
        """获取 OpenClaw 的 LLM 配置"""
        try:
            from openclaw_config import load_openclaw_config
            cfg = load_openclaw_config()
            if not cfg:
                return None

            providers = cfg.get('models', {}).get('providers', {})
            if not providers:
                return None

            # 获取默认 provider
            default_prov_id = None
            try:
                primary = cfg.get('agents', {}).get('defaults', {}).get('model', {}).get('primary')
                if primary and '/' in str(primary):
                    default_prov_id = str(primary).split('/')[0]
            except Exception:
                pass

            # 使用默认 provider 或第一个
            if default_prov_id and default_prov_id in providers:
                prov_cfg = providers[default_prov_id]
            else:
                prov_id, prov_cfg = next(iter(providers.items()))

            api_key = prov_cfg.get('apiKey', '')
            base_url = prov_cfg.get('baseUrl', '')
            models = prov_cfg.get('models', [])
            model = models[0].get('id') if models else 'gpt-4o-mini'
            # 注意：配置中的 api 字段可能不准确，默认使用 openai-chat
            # 连接检测时会自动尝试正确的端点
            api_type = 'openai-chat'  # 统一使用 chat 格式，更通用

            if api_key and base_url:
                return LLMConfig(
                    provider=default_prov_id or prov_id,
                    base_url=base_url,
                    model=model,
                    api_key=api_key,
                    api_type=api_type,
                    has_api_key=True,
                    key_prefix=api_key[:8] + "..." if len(api_key) > 8 else api_key,
                    config_source="openclaw_config"
                )
        except Exception as e:
            print(f"Warning: OpenClaw 配置获取失败: {e}", file=sys.stderr)

        return None


class ClaudeCodeAdapter(BasePlatformAdapter):
    """Claude Code 适配器"""

    PLATFORM_TYPE = PlatformType.CLAUDE_CODE
    PLATFORM_NAME = "Claude Code"

    DETECT_ENVS = ['CLAUDE_API_KEY', 'ANTHROPIC_API_KEY', 'CLAUDE_SESSION_ID']
    DETECT_FILES = [
        '~/.claude/settings.json',
        '~/.claude.json',
    ]
    DETECT_PROCS = ['claude', 'claude-code']

    SKILLS_DIRS = [
        Path.home() / '.claude' / 'skills',
        Path.cwd() / '.claude' / 'skills',
    ]

    def get_llm_config(self) -> Optional[LLMConfig]:
        """获取 Claude Code 的 LLM 配置"""
        api_key = os.environ.get('ANTHROPIC_API_KEY') or os.environ.get('CLAUDE_API_KEY')
        if not api_key:
            # 尝试从 keychain 获取
            api_key = self._get_from_keychain()

        if not api_key:
            return None

        return LLMConfig(
            provider="anthropic",
            base_url="https://api.anthropic.com",
            model="claude-sonnet-4-20250514",
            api_key=api_key,
            api_type="anthropic-messages",
            has_api_key=True,
            key_prefix=api_key[:8] + "..." if len(api_key) > 8 else api_key,
            config_source="env"
        )

    def _get_from_keychain(self) -> str:
        """从 macOS keychain 获取 API Key"""
        try:
            import subprocess
            result = subprocess.run(
                ['security', 'find-generic-password', '-s', 'Claude Code-credentials', '-w'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return ""


class CursorAdapter(BasePlatformAdapter):
    """Cursor 适配器"""

    PLATFORM_TYPE = PlatformType.CURSOR
    PLATFORM_NAME = "Cursor"

    DETECT_ENVS = ['CURSOR_API_KEY', 'OPENAI_API_KEY']
    DETECT_FILES = [
        '~/.cursor/settings.json',
        '~/.cursor/config.json',
    ]
    DETECT_PROCS = ['cursor']

    SKILLS_DIRS = [
        Path.home() / '.cursor' / 'extensions',
        Path.cwd() / '.cursor' / 'skills',
    ]

    def get_llm_config(self) -> Optional[LLMConfig]:
        """获取 Cursor 的 LLM 配置"""
        api_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('CURSOR_API_KEY')
        if not api_key:
            # 尝试从配置文件读取
            api_key = self._get_from_config()

        if not api_key:
            return None

        return LLMConfig(
            provider="openai",
            base_url="https://api.openai.com/v1",
            model="gpt-4o",
            api_key=api_key,
            api_type="openai-chat",
            has_api_key=True,
            key_prefix=api_key[:8] + "..." if len(api_key) > 8 else api_key,
            config_source="env"
        )

    def _get_from_config(self) -> str:
        """从配置文件获取 API Key"""
        config_paths = [
            Path.home() / '.cursor' / 'settings.json',
            Path.home() / '.cursor' / 'config.json',
        ]
        for config_path in config_paths:
            if config_path.exists():
                try:
                    import json
                    with open(config_path) as f:
                        data = json.load(f)
                        # 尝试常见配置路径
                        for key in ['apiKey', 'openaiApiKey', 'openai_key']:
                            if key in data:
                                return data[key]
                except Exception:
                    pass
        return ""


class WindsurfAdapter(BasePlatformAdapter):
    """Windsurf 适配器"""

    PLATFORM_TYPE = PlatformType.WINDSURF
    PLATFORM_NAME = "Windsurf"

    DETECT_ENVS = ['WINDSURF_API_KEY', 'OPENAI_API_KEY']
    DETECT_FILES = [
        '~/.windsurf/settings.json',
        '~/.windsurf/config.json',
    ]
    DETECT_PROCS = ['windsurf', 'codeium']

    SKILLS_DIRS = [
        Path.home() / '.windsurf' / 'skills',
        Path.cwd() / '.windsurf' / 'skills',
    ]

    def get_llm_config(self) -> Optional[LLMConfig]:
        """获取 Windsurf 的 LLM 配置"""
        api_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('WINDSURF_API_KEY')
        if not api_key:
            api_key = self._get_from_config()

        if not api_key:
            return None

        return LLMConfig(
            provider="openai",
            base_url="https://api.openai.com/v1",
            model="gpt-4o",
            api_key=api_key,
            api_type="openai-chat",
            has_api_key=True,
            key_prefix=api_key[:8] + "..." if len(api_key) > 8 else api_key,
            config_source="env"
        )

    def _get_from_config(self) -> str:
        """从配置文件获取 API Key"""
        config_paths = [
            Path.home() / '.windsurf' / 'settings.json',
            Path.home() / '.windsurf' / 'config.json',
        ]
        for config_path in config_paths:
            if config_path.exists():
                try:
                    import json
                    with open(config_path) as f:
                        data = json.load(f)
                        for key in ['apiKey', 'openaiApiKey', 'codeiumApiKey']:
                            if key in data:
                                return data[key]
                except Exception:
                    pass
        return ""


class QClawAdapter(BasePlatformAdapter):
    """QClaw 适配器"""

    PLATFORM_TYPE = PlatformType.QCLAW
    PLATFORM_NAME = "QClaw"

    DETECT_ENVS = ['QCLAW_API_KEY', 'QCLAW_SESSION_ID']
    DETECT_FILES = [
        '~/.qclaw/config.json',
        '~/.qclaw/settings.json',
    ]
    DETECT_PROCS = ['qclaw']

    SKILLS_DIRS = [
        Path.home() / '.qclaw' / 'skills',
    ]

    def get_llm_config(self) -> Optional[LLMConfig]:
        """获取 QClaw 的 LLM 配置"""
        api_key = os.environ.get('QCLAW_API_KEY')
        if not api_key:
            api_key = self._get_from_config()

        if not api_key:
            return None

        return LLMConfig(
            provider="qclaw",
            base_url="https://qclaw.alibaba-inc.com/v1",
            model="qwen3-plus",
            api_key=api_key,
            api_type="openai-chat",
            has_api_key=True,
            key_prefix=api_key[:8] + "..." if len(api_key) > 8 else api_key,
            config_source="env"
        )

    def _get_from_config(self) -> str:
        """从配置文件获取 API Key"""
        config_path = Path.home() / '.qclaw' / 'config.json'
        if config_path.exists():
            try:
                import json
                with open(config_path) as f:
                    data = json.load(f)
                    return data.get('apiKey', '')
            except Exception:
                pass
        return ""


# ─── 注册所有内置适配器 ──────────────────────────────────────────

def register_all_adapters():
    """注册所有内置平台适配器"""
    PlatformRegistry.register(OpenClawAdapter())
    PlatformRegistry.register(ClaudeCodeAdapter())
    PlatformRegistry.register(CursorAdapter())
    PlatformRegistry.register(WindsurfAdapter())
    PlatformRegistry.register(QClawAdapter())


# 自动注册
register_all_adapters()


# ─── 便捷函数 ────────────────────────────────────────────────────

def detect_current_platform() -> Optional[PlatformType]:
    """检测当前平台"""
    return PlatformRegistry.detect_platform()


def get_current_platform_info() -> PlatformInfo:
    """获取当前平台信息"""
    return PlatformRegistry.get_platform_info()


def get_llm_config() -> Optional[LLMConfig]:
    """获取当前平台的 LLM 配置"""
    return PlatformRegistry.get_llm_config()


def get_api_key() -> str:
    """获取当前平台的 API Key"""
    return PlatformRegistry.get_api_key()


def get_all_skills_dirs() -> List[Path]:
    """获取所有平台的 skills 目录"""
    return PlatformRegistry.get_all_skills_dirs()


__all__ = [
    'PlatformType',
    'PlatformInfo',
    'LLMConfig',
    'BasePlatformAdapter',
    'PlatformRegistry',
    'detect_current_platform',
    'get_current_platform_info',
    'get_llm_config',
    'get_api_key',
    'get_all_skills_dirs',
]