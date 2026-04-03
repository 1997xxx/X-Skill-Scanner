#!/usr/bin/env python3
"""
LLM Provider 统一配置管理器

供 semantic_auditor 和 llm_reviewer 共用的 provider 发现层。
消除两个模块间 ~200 行重复代码，并提供全局缓存避免重复探测 API。

用法:
    from llm_provider import get_provider_config
    
    config = get_provider_config()
    # Returns: {'url': ..., 'key': ..., 'model': ..., 'type': ...}
    # type: 'openai-chat' | 'openai-completions' | 'anthropic-messages'
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Optional


def _p(*args, **kwargs):
    kwargs.setdefault('file', sys.stderr)
    print(*args, **kwargs)


# ─── 全局缓存 ──────────────────────────────────────────────
_cached_config: Optional[Dict] = None
_cache_time: float = 0
_CACHE_TTL = 300  # 5 分钟 TTL


def _infer_api_type(prov_cfg: dict) -> str:
    """从 provider 配置的 api 字段推断 API 类型
    
    支持的 api 值:
    - openai-completions → /v1/completions (prompt 格式)
    - openai-chat        → /v1/chat/completions (messages 格式，默认)
    - anthropic-messages → Anthropic Messages API
    """
    api_field = prov_cfg.get('api', '')
    mapping = {
        'openai-completions': 'openai-completions',
        'openai-chat': 'openai-chat',
        'anthropic-messages': 'anthropic-messages',
        'anthropic': 'anthropic-messages',
    }
    return mapping.get(api_field, 'openai-chat')


def _build_probe_candidates(base_url: str, api_type: str) -> list[str]:
    """根据 API 类型构建候选探测 URL 列表
    
    策略：baseUrl 本身优先（很多自定义端点已是完整 URL），
    然后才尝试拼接标准后缀。
    
    openai-completions → /completions (baseUrl 通常已有 /v1)
    openai-chat        → /chat/completions
    anthropic-messages → baseUrl 通常已是完整路径
    """
    base = base_url.rstrip('/')
    candidates = []
    
    # ⭐ 始终首先尝试 baseUrl 本身（自定义端点往往已经是完整 URL）
    candidates.append(base)
    
    if api_type == 'openai-completions':
        # 如果 baseUrl 以 /v1 结尾，追加 /completions
        if base.endswith('/v1'):
            candidates.append(f'{base}/completions')
        # 否则尝试从 /api/ 提取根 URL 再拼接
        elif '/api/' in base:
            root = base[:base.index('/api/')]
            candidates.append(f'{root}/v1/completions')
    elif api_type == 'openai-chat':
        if base.endswith('/v1'):
            candidates.append(f'{base}/chat/completions')
        elif '/api/' in base:
            root = base[:base.index('/api/')]
            candidates.append(f'{root}/v1/chat/completions')
    # anthropic-messages 等不需要额外拼接
    
    # 去重保序
    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def _probe_api(base_url: str, api_key: str, model_id: str, api_type: str) -> Optional[Dict]:
    """探测 API 端点，返回可用配置或 None
    
    根据 api_type 使用正确的请求格式：
    - openai-completions: {model, prompt, max_tokens}
    - openai-chat: {model, messages, max_tokens}
    - anthropic-messages: {model, system, messages, max_tokens}
    """
    candidates = _build_probe_candidates(base_url, api_type)
    
    for url in candidates:
        try:
            if api_type == 'anthropic-messages':
                payload = {
                    'model': model_id,
                    'max_tokens': 10,
                    'system': 'hi',
                    'messages': [{'role': 'user', 'content': 'hi'}]
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode('utf-8'),
                    headers={
                        'Content-Type': 'application/json',
                        'x-api-key': api_key,
                        'anthropic-version': '2023-06-01',
                    },
                    method='POST',
                )
            elif api_type == 'openai-completions':
                # ✅ Completions 格式：使用 prompt 而非 messages
                payload = {
                    'model': model_id,
                    'prompt': 'hi',
                    'max_tokens': 10,
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode('utf-8'),
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': f'Bearer {api_key}',
                    },
                    method='POST',
                )
            else:
                # openai-chat (默认)
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
                        'Authorization': f'Bearer {api_key}',
                    },
                    method='POST',
                )
            
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode('utf-8'))
                # Completions: {choices: [{text, ...}]}
                # Chat: {choices: [{message: {content}}]}
                # Anthropic: {content: [{text}]}
                if 'choices' in body or 'content' in body:
                    return {
                        'url': url,
                        'key': api_key,
                        'model': model_id,
                        'type': api_type,
                    }
        except Exception:
            continue
    
    return None


def _try_one_provider(prov_id: str, prov_cfg: dict, model_id: str) -> Optional[Dict]:
    """尝试单个 provider，探测成功则返回配置，失败返回 None"""
    api_key = prov_cfg.get('apiKey')
    base_url = prov_cfg.get('baseUrl')
    if not (api_key and base_url):
        return None
    
    models_list = prov_cfg.get('models', [])
    all_ids = [m.get('id', '') for m in models_list]
    if not all_ids:
        return None
    
    # 如果指定了 model_id 且不在列表中，跳过（除非列表为空 — 支持动态模型）
    if model_id and model_id not in all_ids:
        return None
    
    actual_model = model_id or all_ids[0]
    api_type = _infer_api_type(prov_cfg)
    
    detected = _probe_api(base_url, api_key, actual_model, api_type)
    if detected:
        return detected
    
    # 探测失败但仍可 fallback 使用配置值
    return {
        'url': base_url,
        'key': api_key,
        'model': actual_model,
        'type': api_type,
    }


def discover_provider(force: bool = False) -> Optional[Dict]:
    """
    自动发现 LLM provider 配置
    
    策略：优先使用 agents.defaults.model.primary，探测不通时优雅回退到前 3 个 provider。
    
    优先级:
    1. 环境变量 OPENAI_BASE_URL + OPENAI_API_KEY
    2. agents.defaults.model.primary → models.providers.<provider_id>
    3. 遍历前 3 个 provider（按配置顺序），取第一个通的
    
    返回 dict: {url, key, model, type} 或 None
    """
    global _cached_config, _cache_time
    
    # 检查缓存
    now = time.time()
    if not force and _cached_config and (now - _cache_time) < _CACHE_TTL:
        return _cached_config
    
    # ─── 1. 环境变量优先 ────────────────────────────────────
    if os.environ.get('OPENAI_BASE_URL') and os.environ.get('OPENAI_API_KEY'):
        result = {
            'url': os.environ['OPENAI_BASE_URL'],
            'key': os.environ['OPENAI_API_KEY'],
            'model': os.environ.get('OPENAI_MODEL', 'gpt-4o-mini'),
            'type': 'openai-chat',
        }
        _cached_config = result
        _cache_time = now
        return result
    
    # ─── 2. 从 openclaw.json 发现 ──────────────────────────
    try:
        from openclaw_config import load_openclaw_config, get_openclaw_config_path
        cfg = load_openclaw_config()
        if not cfg:
            config_path = get_openclaw_config_path()
            _p(f"⚠️  无法加载 OpenClaw 配置: {config_path}")
            return None
    except ImportError:
        _p("⚠️  openclaw_config 模块不可用")
        return None
    
    providers = cfg.get('models', {}).get('providers', {})
    if not providers:
        _p("⚠️  openclaw.json 中未找到 models.providers")
        return None
    
    # ─── 读取默认模型引用 ──────────────────────────────────
    default_prov_id = None
    default_model_id = None
    try:
        primary = cfg.get('agents', {}).get('defaults', {}).get('model', {}).get('primary')
        if primary and '/' in str(primary):
            parts = str(primary).split('/', 1)
            default_prov_id, default_model_id = parts[0], parts[1]
    except (AttributeError, TypeError):
        pass
    
    # 构建 model→provider 反向映射（用于跨 provider 别名解析）
    model_to_prov = {}
    for prov_id, prov_cfg in providers.items():
        for m in prov_cfg.get('models', []):
            mid = m.get('id', '')
            if mid:
                model_to_prov[mid] = prov_id
    
    # ─── Phase 1: 尝试 default provider ────────────────────
    if default_prov_id and default_model_id:
        # 如果 model 实际在另一个 provider 下，优先用那个
        resolved_prov = model_to_prov.get(default_model_id, default_prov_id)
        if resolved_prov != default_prov_id:
            _p(f"🎯 跨 provider 匹配: {default_prov_id}/{default_model_id} → {resolved_prov}")
        
        prov_cfg = providers.get(resolved_prov)
        if prov_cfg:
            _p(f"🎯 尝试默认: {resolved_prov}/{default_model_id}")
            result = _try_one_provider(resolved_prov, prov_cfg, default_model_id)
            if result:
                _p(f"✅ 默认 provider 可用: {result['model']} [{result['type']}]")
                _cached_config = result
                _cache_time = now
                return result
            else:
                _p(f"⚠️  默认 provider 不通，尝试其他…")
    
    # ─── Phase 2: 遍历前 3 个 provider ─────────────────────
    _p("🔄 回退模式：尝试前 3 个 provider")
    max_try = 3
    for i, (prov_id, prov_cfg) in enumerate(providers.items()):
        if i >= max_try:
            break
        
        # 跳过已经试过的 default provider
        if prov_id == default_prov_id:
            continue
        
        models_list = prov_cfg.get('models', [])
        if not models_list:
            continue
        
        first_model = models_list[0].get('id', '')
        _p(f"   [{i+1}] {prov_id}/{first_model} …", end='', flush=True)
        
        result = _try_one_provider(prov_id, prov_cfg, first_model)
        if result:
            _p(" ✅")
            _cached_config = result
            _cache_time = now
            return result
        else:
            _p(" ❌")
    
    _p("⚠️  所有 provider 均不可用")
    return None


def get_provider_config() -> Optional[Dict]:
    """获取 provider 配置（带缓存的入口函数）"""
    return discover_provider()


def invalidate_cache():
    """清除 provider 配置缓存（用于测试或配置变更后）"""
    global _cached_config, _cache_time
    _cached_config = None
    _cache_time = 0


__all__ = ['get_provider_config', 'discover_provider', 'invalidate_cache']
