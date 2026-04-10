#!/usr/bin/env python3
"""
Environment Detector - AI Agent 环境检测模块

在 skill 使用前检测：
1. 当前 AI Agent 平台 (OpenClaw, Claude Code, Cursor, etc.)
2. LLM 配置信息 (API Key, Endpoint, Model)
3. LLM 连接状态 (是否可以正常调用)

用法:
    from env_detector import full_env_check, detect_ai_agent, get_llm_config, check_llm_connection

    # 完整检测
    report = full_env_check()

    # 单独检测
    agent_info = detect_ai_agent()
    llm_config = get_llm_config()
    connection_status = check_llm_connection()

注意: 此模块现在使用 platform_registry 作为后端来获取平台信息。
"""

import os
import sys
import json
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

# 尝试导入 platform_registry 作为后端
try:
    from platform_registry import (
        PlatformType,
        PlatformRegistry,
        get_current_platform_info as _get_platform_info,
        get_llm_config as _get_llm_config_from_registry,
        get_api_key as _get_api_key_from_registry,
    )
    _PLATFORM_REGISTRY_AVAILABLE = True
except ImportError:
    _PLATFORM_REGISTRY_AVAILABLE = False


class AgentPlatform(Enum):
    """支持的 AI Agent 平台"""
    OPENCLAW = "openclaw"
    CLAUDE_CODE = "claude_code"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    QCLAW = "qclaw"
    COP_AW = "copaw"
    GITHUB_COPILOT = "github_copilot"
    UNKNOWN = "unknown"


class ConnectionStatus(Enum):
    """连接状态"""
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNAUTHORIZED = "unauthorized"
    NOT_CONFIGURED = "not_configured"
    UNKNOWN = "unknown"


@dataclass
class AgentInfo:
    """AI Agent 信息"""
    platform: AgentPlatform
    platform_name: str
    version: Optional[str] = None
    executable_path: Optional[str] = None
    config_path: Optional[str] = None
    is_available: bool = False
    extra_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMConfig:
    """LLM 配置信息"""
    provider: str
    base_url: str
    model: str
    api_type: str
    has_api_key: bool = False
    key_prefix: str = ""  # API Key 前几位用于显示
    config_source: str = ""  # 配置来源: env / config_file / default


@dataclass
class ConnectionResult:
    """连接检测结果"""
    status: ConnectionStatus
    latency_ms: Optional[float] = None
    error_message: Optional[str] = None
    response_sample: Optional[str] = None


@dataclass
class EnvCheckReport:
    """完整环境检测报告"""
    timestamp: str
    agent_info: AgentInfo
    llm_config: Optional[LLMConfig]
    connection_result: Optional[ConnectionResult]
    is_ready: bool  # 是否可以正常使用
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _run_command(cmd: List[str], timeout: int = 5) -> tuple:
    """运行命令并返回 (returncode, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", "command not found"
    except Exception as e:
        return -1, "", str(e)


def _find_executable(name: str) -> Optional[str]:
    """查找可执行文件路径"""
    # 使用 which 命令
    rc, stdout, _ = _run_command(["which", name])
    if rc == 0 and stdout.strip():
        return stdout.strip()

    # 尝试常见路径
    common_paths = [
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}",
        f"{Path.home()}/.local/bin/{name}",
    ]
    for path in common_paths:
        if Path(path).exists():
            return path

    return None


def _get_openclaw_info() -> Optional[AgentInfo]:
    """检测 OpenClaw"""
    # 检查环境变量
    if not os.environ.get('OPENCLAW_HOME') and not os.environ.get('OPENCLAW_CONFIG_PATH'):
        # 检查默认路径
        config_path = Path.home() / '.openclaw' / 'openclaw.json'
        if not config_path.exists():
            return None

    # 尝试获取版本
    version = None
    executable_path = _find_executable('openclaw')

    # 尝试读取版本
    try:
        from openclaw_config import load_openclaw_config
        cfg = load_openclaw_config()
        if cfg:
            version = cfg.get('version') or cfg.get('app', {}).get('version')
    except Exception:
        pass

    config_path = None
    try:
        from openclaw_config import get_openclaw_config_path
        p = get_openclaw_config_path()
        if p:
            config_path = str(p)
    except Exception:
        pass

    return AgentInfo(
        platform=AgentPlatform.OPENCLAW,
        platform_name="OpenClaw",
        version=version,
        executable_path=executable_path,
        config_path=config_path,
        is_available=True
    )


def _get_claude_code_info() -> Optional[AgentInfo]:
    """检测 Claude Code"""
    executable_path = _find_executable('claude')
    if not executable_path:
        # 尝试其他可能路径
        for name in ['claude-code', 'claude-cli']:
            executable_path = _find_executable(name)
            if executable_path:
                break

    if not executable_path:
        return None

    # 尝试获取版本
    version = None
    rc, stdout, _ = _run_command([executable_path, "--version"])
    if rc == 0:
        version = stdout.strip().split('\n')[0]

    return AgentInfo(
        platform=AgentPlatform.CLAUDE_CODE,
        platform_name="Claude Code",
        version=version,
        executable_path=executable_path,
        is_available=True
    )


def _get_cursor_info() -> Optional[AgentInfo]:
    """检测 Cursor"""
    executable_path = _find_executable('cursor')
    if not executable_path:
        return None

    version = None
    rc, stdout, _ = _run_command([executable_path, "--version"])
    if rc == 0:
        version = stdout.strip().split('\n')[0]

    return AgentInfo(
        platform=AgentPlatform.CURSOR,
        platform_name="Cursor",
        version=version,
        executable_path=executable_path,
        is_available=True
    )


def _get_windsurf_info() -> Optional[AgentInfo]:
    """检测 Windsurf"""
    executable_path = _find_executable('windsurf')
    if not executable_path:
        return None

    version = None
    rc, stdout, _ = _run_command([executable_path, "--version"])
    if rc == 0:
        version = stdout.strip().split('\n')[0]

    return AgentInfo(
        platform=AgentPlatform.WINDSURF,
        platform_name="Windsurf",
        version=version,
        executable_path=executable_path,
        is_available=True
    )


def _get_qclaw_info() -> Optional[AgentInfo]:
    """检测 QClaw"""
    executable_path = _find_executable('qclaw')
    if not executable_path:
        return None

    version = None
    rc, stdout, _ = _run_command([executable_path, "--version"])
    if rc == 0:
        version = stdout.strip().split('\n')[0]

    return AgentInfo(
        platform=AgentPlatform.QCLAW,
        platform_name="QClaw",
        version=version,
        executable_path=executable_path,
        is_available=True
    )


def _get_copaw_info() -> Optional[AgentInfo]:
    """检测 CoPaw"""
    executable_path = _find_executable('copaw')
    if not executable_path:
        return None

    version = None
    rc, stdout, _ = _run_command([executable_path, "--version"])
    if rc == 0:
        version = stdout.strip().split('\n')[0]

    return AgentInfo(
        platform=AgentPlatform.COP_AW,
        platform_name="CoPaw",
        version=version,
        executable_path=executable_path,
        is_available=True
    )


def detect_ai_agent() -> AgentInfo:
    """
    检测当前 AI Agent 平台

    检测顺序（优先级）:
    1. OpenClaw - 通过配置文件和环境变量
    2. Claude Code - 通过 claude CLI
    3. Cursor - 通过 cursor CLI
    4. Windsurf - 通过 windsurf CLI
    5. QClaw - 通过 qclaw CLI
    6. CoPaw - 通过 copaw CLI

    Returns:
        AgentInfo: 检测到的 Agent 信息
    """
    # 优先使用 platform_registry
    if _PLATFORM_REGISTRY_AVAILABLE:
        try:
            platform_info = _get_platform_info()
            if platform_info.detected:
                # 映射 PlatformType 到 AgentPlatform
                platform_map = {
                    PlatformType.OPENCLAW: AgentPlatform.OPENCLAW,
                    PlatformType.CLAUDE_CODE: AgentPlatform.CLAUDE_CODE,
                    PlatformType.CURSOR: AgentPlatform.CURSOR,
                    PlatformType.WINDSURF: AgentPlatform.WINDSURF,
                    PlatformType.QCLAW: AgentPlatform.QCLAW,
                    PlatformType.COP_AW: AgentPlatform.COP_AW,
                }
                return AgentInfo(
                    platform=platform_map.get(platform_info.platform, AgentPlatform.UNKNOWN),
                    platform_name=platform_info.name,
                    is_available=True,
                    config_path=str(platform_info.skills_dirs[0]) if platform_info.skills_dirs else None
                )
        except Exception:
            pass

    # 回退到原有检测逻辑
    detectors = [
        _get_openclaw_info,
        _get_claude_code_info,
        _get_cursor_info,
        _get_windsurf_info,
        _get_qclaw_info,
        _get_copaw_info,
    ]

    for detector in detectors:
        try:
            info = detector()
            if info and info.is_available:
                return info
        except Exception:
            continue

    # 未检测到任何 Agent
    return AgentInfo(
        platform=AgentPlatform.UNKNOWN,
        platform_name="Unknown",
        is_available=False
    )


def get_llm_config() -> Optional[LLMConfig]:
    """
    获取 LLM 配置信息

    配置来源优先级:
    1. platform_registry (统一的平台适配器)
    2. 环境变量 (OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL)
    3. OpenClaw 配置文件 (openclaw.json)
    4. 其他 Agent 配置文件

    Returns:
        LLMConfig: LLM 配置信息，如果无法获取则返回 None
    """
    # 优先使用 platform_registry
    if _PLATFORM_REGISTRY_AVAILABLE:
        try:
            config = _get_llm_config_from_registry()
            if config:
                return LLMConfig(
                    provider=config.provider,
                    base_url=config.base_url,
                    model=config.model,
                    api_type=config.api_type,
                    has_api_key=config.has_api_key,
                    key_prefix=config.key_prefix,
                    config_source=config.config_source
                )
        except Exception:
            pass

    # 1. 尝试从环境变量获取
    api_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('OPENAI_API_KEY')
    base_url = os.environ.get('OPENAI_BASE_URL')
    model = os.environ.get('OPENAI_MODEL', 'gpt-4o-mini')

    if api_key and base_url:
        return LLMConfig(
            provider="openai",
            base_url=base_url,
            model=model,
            api_type="openai-chat",
            has_api_key=True,
            key_prefix=api_key[:8] + "..." if len(api_key) > 8 else api_key,
            config_source="env"
        )

    # 2. 尝试从 OpenClaw 配置获取
    try:
        from openclaw_config import load_openclaw_config
        cfg = load_openclaw_config()
        if cfg:
            providers = cfg.get('models', {}).get('providers', {})
            if providers:
                # 获取默认 provider
                default_prov_id = None
                default_model_id = None

                try:
                    primary = cfg.get('agents', {}).get('defaults', {}).get('model', {}).get('primary')
                    if primary and '/' in str(primary):
                        parts = str(primary).split('/', 1)
                        default_prov_id, default_model_id = parts[0], parts[1]
                except Exception:
                    pass

                # 使用默认 provider 或第一个
                if default_prov_id and default_prov_id in providers:
                    prov_cfg = providers[default_prov_id]
                else:
                    prov_id, prov_cfg = next(iter(providers.items()))

                api_key = prov_cfg.get('apiKey')
                base_url = prov_cfg.get('baseUrl')
                models = prov_cfg.get('models', [])
                model = default_model_id or (models[0].get('id') if models else 'gpt-4o-mini')
                api_type = prov_cfg.get('api', 'openai-chat')

                if api_key and base_url:
                    return LLMConfig(
                        provider=default_prov_id or prov_id,
                        base_url=base_url,
                        model=model,
                        api_type=api_type,
                        has_api_key=True,
                        key_prefix=api_key[:8] + "..." if len(api_key) > 8 else api_key,
                        config_source="openclaw_config"
                    )
    except Exception as e:
        print(f"Warning: 无法加载 OpenClaw 配置: {e}", file=sys.stderr)

    # 3. 尝试使用 llm_provider 模块
    try:
        from llm_provider import get_provider_config
        config = get_provider_config()
        if config:
            return LLMConfig(
                provider=config.get('type', 'unknown'),
                base_url=config.get('url', ''),
                model=config.get('model', ''),
                api_type=config.get('type', 'openai-chat'),
                has_api_key=bool(config.get('key')),
                key_prefix=config.get('key', '')[:8] + "..." if config.get('key') else "",
                config_source="llm_provider"
            )
    except Exception as e:
        print(f"Warning: 无法通过 llm_provider 获取配置: {e}", file=sys.stderr)

    return None


def check_llm_connection(config: Optional[LLMConfig] = None, timeout: int = 10) -> ConnectionResult:
    """
    检查 LLM 连接状态

    Args:
        config: LLM 配置，如果为 None 则自动获取
        timeout: 超时时间（秒）

    Returns:
        ConnectionResult: 连接检测结果
    """
    if config is None:
        config = get_llm_config()

    if config is None:
        return ConnectionResult(
            status=ConnectionStatus.NOT_CONFIGURED,
            error_message="未找到 LLM 配置"
        )

    if not config.has_api_key:
        return ConnectionResult(
            status=ConnectionStatus.NOT_CONFIGURED,
            error_message="API Key 未配置"
        )

    # 构建探测请求
    url = config.base_url.rstrip('/')
    api_type = config.api_type

    # 添加后缀 - 根据 API 类型
    if api_type == 'openai-chat':
        if '/chat/completions' not in url:
            if url.endswith('/v1'):
                url = f"{url}/chat/completions"
            elif '/api/' in url:
                base = url[:url.index('/api/')]
                url = f"{base}/v1/chat/completions"
    elif api_type == 'openai-completions':
        if '/completions' not in url:
            if url.endswith('/v1'):
                url = f"{url}/completions"
            elif '/api/' in url:
                base = url[:url.index('/api/')]
                url = f"{base}/v1/completions"

    # 构建请求体
    if api_type == 'anthropic-messages':
        payload = {
            'model': config.model,
            'max_tokens': 10,
            'messages': [{'role': 'user', 'content': 'hi'}]
        }
        headers = {
            'Content-Type': 'application/json',
            'x-api-key': '',  # 完整 key 需要从 config 获取
            'anthropic-version': '2023-06-01',
        }
    elif api_type == 'openai-completions':
        # Completions API 使用 prompt 而不是 messages
        payload = {
            'model': config.model,
            'prompt': 'hi',
            'max_tokens': 10,
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ',  # 完整 key 稍后添加
        }
    else:
        payload = {
            'model': config.model,
            'max_tokens': 10,
            'messages': [{'role': 'user', 'content': 'hi'}]
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ',  # 完整 key 稍后添加
        }

    # 发送探测请求
    start_time = datetime.now()

    try:
        # 需要从配置中获取完整 key
        full_key = _get_full_api_key(config)
        if not full_key:
            return ConnectionResult(
                status=ConnectionStatus.UNAUTHORIZED,
                error_message="无法获取完整 API Key"
            )

        if api_type == 'anthropic-messages':
            headers['x-api-key'] = full_key
        else:
            headers['Authorization'] = f'Bearer {full_key}'

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers=headers,
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency = (datetime.now() - start_time).total_seconds() * 1000

            body = json.loads(resp.read().decode('utf-8'))

            # 提取响应样本
            sample = ""
            if 'choices' in body:
                choices = body['choices']
                if choices and 'message' in choices[0]:
                    sample = choices[0]['message'].get('content', '')[:100]
            elif 'content' in body:
                content = body['content']
                if content and isinstance(content, list) and 'text' in content[0]:
                    sample = content[0]['text'][:100]

            return ConnectionResult(
                status=ConnectionStatus.OK,
                latency_ms=latency,
                response_sample=sample
            )

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return ConnectionResult(
                status=ConnectionStatus.UNAUTHORIZED,
                error_message=f"HTTP 401: API Key 无效或已过期"
            )
        elif e.code == 403:
            return ConnectionResult(
                status=ConnectionStatus.UNAUTHORIZED,
                error_message=f"HTTP 403: 权限不足"
            )
        elif e.code == 404:
            return ConnectionResult(
                status=ConnectionStatus.ERROR,
                error_message=f"HTTP 404: API 端点不存在"
            )
        elif e.code == 429:
            return ConnectionResult(
                status=ConnectionStatus.ERROR,
                error_message=f"HTTP 429: 请求频率超限"
            )
        else:
            return ConnectionResult(
                status=ConnectionStatus.ERROR,
                error_message=f"HTTP {e.code}: {e.reason}"
            )

    except urllib.error.URLError as e:
        if "timed out" in str(e.reason).lower():
            return ConnectionResult(
                status=ConnectionStatus.TIMEOUT,
                error_message=f"连接超时 ({timeout}s)"
            )
        return ConnectionResult(
            status=ConnectionStatus.ERROR,
            error_message=f"连接失败: {e.reason}"
        )

    except Exception as e:
        return ConnectionResult(
            status=ConnectionStatus.ERROR,
            error_message=f"未知错误: {str(e)}"
        )


def _get_full_api_key(config: LLMConfig) -> Optional[str]:
    """获取完整的 API Key"""
    # 优先从环境变量获取
    for env_key in ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'API_KEY']:
        key = os.environ.get(env_key)
        if key:
            return key

    # 从 OpenClaw 配置获取
    try:
        from openclaw_config import load_openclaw_config
        cfg = load_openclaw_config()
        if cfg:
            providers = cfg.get('models', {}).get('providers', {})

            # 如果配置中指定了 provider，优先使用该 provider 的 key
            if config and config.provider:
                prov_cfg = providers.get(config.provider)
                if prov_cfg:
                    key = prov_cfg.get('apiKey')
                    if key:
                        return key

            # 否则使用第一个可用的 key
            for prov_cfg in providers.values():
                key = prov_cfg.get('apiKey')
                if key:
                    return key
    except Exception:
        pass

    return None


def full_env_check() -> EnvCheckReport:
    """
    完整环境检测

    在 skill 使用前调用，检测:
    1. AI Agent 平台
    2. LLM 配置
    3. LLM 连接状态

    Returns:
        EnvCheckReport: 完整的环境检测报告
    """
    warnings = []
    errors = []

    # 1. 检测 AI Agent
    agent_info = detect_ai_agent()

    if not agent_info.is_available:
        warnings.append("未检测到已知的 AI Agent 平台")

    # 2. 获取 LLM 配置
    llm_config = get_llm_config()

    if llm_config is None:
        errors.append("无法获取 LLM 配置")
        return EnvCheckReport(
            timestamp=datetime.now().isoformat(),
            agent_info=agent_info,
            llm_config=None,
            connection_result=None,
            is_ready=False,
            warnings=warnings,
            errors=errors
        )

    if not llm_config.has_api_key:
        errors.append("API Key 未配置")

    # 3. 检查连接
    connection_result = check_llm_connection(llm_config)

    if connection_result.status != ConnectionStatus.OK:
        if connection_result.status == ConnectionStatus.NOT_CONFIGURED:
            errors.append("LLM 未配置")
        elif connection_result.status == ConnectionStatus.UNAUTHORIZED:
            errors.append("API Key 无效")
        elif connection_result.status == ConnectionStatus.TIMEOUT:
            errors.append("LLM 连接超时")
        else:
            errors.append(f"LLM 连接失败: {connection_result.error_message}")
    else:
        # 连接成功，添加一些信息
        if connection_result.latency_ms:
            latency = connection_result.latency_ms
            if latency > 5000:
                warnings.append(f"LLM 响应较慢: {latency:.0f}ms")

    # 判断是否就绪
    is_ready = (
        agent_info.is_available and
        llm_config is not None and
        llm_config.has_api_key and
        connection_result.status == ConnectionStatus.OK
    )

    return EnvCheckReport(
        timestamp=datetime.now().isoformat(),
        agent_info=agent_info,
        llm_config=llm_config,
        connection_result=connection_result,
        is_ready=is_ready,
        warnings=warnings,
        errors=errors
    )


def print_env_report(report: EnvCheckReport, verbose: bool = False):
    """打印环境检测报告"""
    print("\n" + "=" * 60)
    print("🔍 AI Agent 环境检测报告")
    print("=" * 60)

    # 时间
    print(f"\n⏰ 检测时间: {report.timestamp}")

    # Agent 信息
    print(f"\n🤖 AI Agent 平台:")
    print(f"   平台: {report.agent_info.platform_name}")
    print(f"   可用: {'✅ 是' if report.agent_info.is_available else '❌ 否'}")
    if report.agent_info.version:
        print(f"   版本: {report.agent_info.version}")
    if report.agent_info.executable_path:
        print(f"   路径: {report.agent_info.executable_path}")

    # LLM 配置
    print(f"\n⚙️ LLM 配置:")
    if report.llm_config:
        print(f"   Provider: {report.llm_config.provider}")
        print(f"   Model: {report.llm_config.model}")
        print(f"   API Type: {report.llm_config.api_type}")
        print(f"   Endpoint: {report.llm_config.base_url}")
        print(f"   API Key: {'✅ 已配置' if report.llm_config.has_api_key else '❌ 未配置'} ({report.llm_config.key_prefix})")
        print(f"   配置来源: {report.llm_config.config_source}")
    else:
        print(f"   ❌ 无法获取配置")

    # 连接状态
    print(f"\n🌐 连接状态:")
    if report.connection_result:
        status = report.connection_result.status
        if status == ConnectionStatus.OK:
            print(f"   ✅ 连接正常")
            if report.connection_result.latency_ms:
                print(f"   ⏱️ 延迟: {report.connection_result.latency_ms:.0f}ms")
        elif status == ConnectionStatus.UNAUTHORIZED:
            print(f"   ❌ 授权失败: {report.connection_result.error_message}")
        elif status == ConnectionStatus.TIMEOUT:
            print(f"   ⏰ 连接超时: {report.connection_result.error_message}")
        elif status == ConnectionStatus.NOT_CONFIGURED:
            print(f"   ❌ 未配置: {report.connection_result.error_message}")
        else:
            print(f"   ❌ 连接失败: {report.connection_result.error_message}")
    else:
        print(f"   ❌ 未检测")

    # 警告和错误
    if report.warnings:
        print(f"\n⚠️ 警告:")
        for w in report.warnings:
            print(f"   - {w}")

    if report.errors:
        print(f"\n❌ 错误:")
        for e in report.errors:
            print(f"   - {e}")

    # 最终状态
    print(f"\n" + "=" * 60)
    if report.is_ready:
        print("✅ 状态: 就绪，可以进行扫描")
    else:
        print("❌ 状态: 未就绪，请检查上述问题")
    print("=" * 60 + "\n")


# 便捷函数
__all__ = [
    'AgentPlatform',
    'ConnectionStatus',
    'AgentInfo',
    'LLMConfig',
    'ConnectionResult',
    'EnvCheckReport',
    'detect_ai_agent',
    'get_llm_config',
    'check_llm_connection',
    'full_env_check',
    'print_env_report',
]