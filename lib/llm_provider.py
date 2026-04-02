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


def _probe_api(base_url: str, api_key: str, model_id: str, api_type: str) -> Optional[Dict]:
    """探测 API 端点，返回可用配置或 None"""
    base = base_url.rstrip('/')
    
    # 构建候选 URL 列表
    candidates = []
    if '/api/' in base:
        root = base[:base.index('/api/')]
        candidates.append(f'{root}/v1/chat/completions')
    if not base.endswith('/v1/chat/completions'):
        candidates.append(f'{base}/v1/chat/completions')
    candidates.append(base)
    
    # 去重保序
    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    
    for url in unique:
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
            else:
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
                detected_type = api_type if api_type != 'openai-chat' else 'openai-chat'
                if 'choices' in body or 'content' in body:
                    return {
                        'url': url,
                        'key': api_key,
                        'model': model_id,
                        'type': detected_type,
                    }
        except Exception:
            continue
    
    return None


def discover_provider(force: bool = False) -> Optional[Dict]:
    """
    自动发现 LLM provider 配置
    
    优先级:
    1. 环境变量 OPENAI_BASE_URL + OPENAI_API_KEY
    2. OpenClaw 默认模型对应的 provider（agents.defaults.model.primary）
    3. 遍历所有 provider，取第一个能探测通的
    
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
    
    # 获取默认模型引用
    default_prov_id = None
    default_model_id = None
    try:
        primary = cfg.get('agents', {}).get('defaults', {}).get('model', {}).get('primary')
        if primary and '/' in str(primary):
            parts = str(primary).split('/', 1)
            default_prov_id, default_model_id = parts[0], parts[1]
    except (AttributeError, TypeError):
        pass
    
    # 构建反向映射
    model_to_prov = {}
    prov_models = {}
    for prov_id, prov_cfg in providers.items():
        models_list = prov_cfg.get('models', [])
        if models_list:
            all_ids = [m.get('id', '') for m in models_list]
            prov_models[prov_id] = {'first': all_ids[0], 'all': all_ids}
            for mid in all_ids:
                model_to_prov[mid] = prov_id
    
    # 解析首选 provider + model（支持跨 provider 别名）
    preferred_prov_id = default_prov_id
    preferred_model_id = default_model_id
    
    if default_model_id and default_model_id in model_to_prov:
        resolved_prov = model_to_prov[default_model_id]
        if resolved_prov != default_prov_id:
            _p(f"🎯 跨 provider 匹配默认模型: {resolved_prov}/{default_model_id}")
        preferred_prov_id = resolved_prov
        preferred_model_id = default_model_id
    elif default_model_id:
        _p(f"🎯 匹配默认模型: {default_prov_id}/{default_model_id}")
    
    # 按优先级排序：首选 provider 排第一
    ordered_ids = list(providers.keys())
    if preferred_prov_id and preferred_prov_id in ordered_ids:
        ordered_ids.remove(preferred_prov_id)
        ordered_ids.insert(0, preferred_prov_id)
    
    # ─── 3. 遍历探测 ──────────────────────────────────────
    for prov_id in ordered_ids:
        prov_cfg = providers[prov_id]
        api_key = prov_cfg.get('apiKey')
        base_url = prov_cfg.get('baseUrl')
        models_list = prov_cfg.get('models', [])
        
        if not (api_key and base_url and models_list):
            continue
        
        info = prov_models.get(prov_id, {})
        all_ids = info.get('all', [])
        
        # 选择 model
        if prov_id == preferred_prov_id and preferred_model_id in all_ids:
            model_id = preferred_model_id
        else:
            model_id = info.get('first', models_list[0].get('id', ''))
        
        api_type = _infer_api_type(prov_cfg)
        
        # 探测 API
        detected = _probe_api(base_url, api_key, model_id, api_type)
        if detected:
            _p(f"🔌 自动发现 Provider: {prov_id} ({model_id}) [{detected['type']}]")
            _cached_config = detected
            _cache_time = now
            return detected
        
        # Fallback: 使用配置值不探测
        result = {
            'url': base_url,
            'key': api_key,
            'model': model_id,
            'type': api_type,
        }
        _p(f"🔌 自动发现 Provider: {prov_id} ({model_id}) [fallback: {api_type}]")
        _cached_config = result
        _cache_time = now
        return result
    
    _p("⚠️  所有 provider 探测失败")
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
