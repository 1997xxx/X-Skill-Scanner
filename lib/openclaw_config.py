"""
OpenClaw Configuration Path Resolver

Resolves the path to openclaw.json with maximum compatibility across platforms
and deployment scenarios. Supports all OpenClaw environment variable overrides.

Precedence (highest to lowest):
1. OPENCLAW_CONFIG_PATH  — Direct config file path override
2. OPENCLAW_HOME        — Custom home directory → $OPENCLAW_HOME/openclaw.json
3. Platform default     — ~/.openclaw/openclaw.json (macOS/Linux) or
                          %USERPROFILE%\.openclaw\openclaw.json (Windows)

Usage:
    from openclaw_config import get_openclaw_config_path
    
    config_path = get_openclaw_config_path()
    if config_path:
        # Read config...
"""

import os
from pathlib import Path
from typing import Optional


def get_openclaw_home() -> Path:
    """Get the OpenClaw home directory.
    
    Respects OPENCLAW_HOME environment variable for service accounts
    and isolated deployments.
    
    Precedence: OPENCLAW_HOME > $HOME > USERPROFILE > os.homedir()
    """
    # Priority 1: Explicit override
    env_home = os.environ.get('OPENCLAW_HOME')
    if env_home:
        return Path(env_home)
    
    # Priority 2: Standard platform home
    return Path.home()


def get_openclaw_config_path() -> Optional[Path]:
    """Get the path to openclaw.json configuration file.
    
    This is the canonical way to locate OpenClaw's config file.
    Works on all platforms (macOS, Linux, Windows) and respects
    all OpenClaw environment variable overrides.
    
    Returns:
        Path to openclaw.json, or None if not found.
    """
    # Priority 1: Direct config path override
    env_config = os.environ.get('OPENCLAW_CONFIG_PATH')
    if env_config:
        p = Path(env_config)
        if p.exists():
            return p
        # If explicitly set but doesn't exist, still return it
        # so the caller can report a meaningful error
        return p
    
    # Priority 2: OPENCLAW_HOME override
    oc_home = os.environ.get('OPENCLAW_HOME')
    if oc_home:
        p = Path(oc_home) / 'openclaw.json'
        if p.exists():
            return p
    
    # Priority 3: Platform default (~/.openclaw/openclaw.json)
    # Path.home() handles USERPROFILE on Windows automatically
    default_path = Path.home() / '.openclaw' / 'openclaw.json'
    if default_path.exists():
        return default_path
    
    # Not found anywhere — return default so caller can report error
    return default_path


def get_openclaw_skills_dir() -> Optional[Path]:
    """Get the default skills directory.
    
    Checks multiple common locations in order of preference.
    
    Returns:
        Path to skills directory, or None if not found.
    """
    oc_home = get_openclaw_home()
    
    # Common skill directories (in order of preference)
    candidates = [
        oc_home / 'skills',                    # ~/.openclaw/skills/
        oc_home / 'workspace' / 'skills',       # ~/.openclaw/workspace/skills/
        oc_home / '.openclaw' / 'skills',       # nested fallback
    ]
    
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    
    return None


def _strip_json_comments(content: str) -> str:
    """Remove // line comments from JSON content while preserving strings.
    
    OpenClaw's config is JSON5-ish and may contain // comments.
    Standard json.load() fails on these. This strips them safely.
    """
    lines = content.split('\n')
    cleaned = []
    for line in lines:
        # Find // that's NOT inside a string value
        # Simple heuristic: count unescaped quotes before //
        result = []
        in_string = False
        escaped = False
        i = 0
        while i < len(line):
            char = line[i]
            if escaped:
                result.append(char)
                escaped = False
                i += 1
                continue
            if char == '\\':
                result.append(char)
                escaped = True
                i += 1
                continue
            if char == '"':
                in_string = not in_string
                result.append(char)
            elif char == '/' and i + 1 < len(line) and line[i + 1] == '/' and not in_string:
                # Found comment start — skip rest of line
                break
            else:
                result.append(char)
            i += 1
        cleaned.append(''.join(result))
    return '\n'.join(cleaned)


def load_openclaw_config() -> Optional[dict]:
    """Load and parse the OpenClaw configuration file.
    
    Handles JSON5 features like // comments that standard json.load() rejects.
    
    Returns:
        Parsed config dict, or None if file not found or invalid JSON.
    """
    import json
    
    config_path = get_openclaw_config_path()
    if not config_path or not config_path.exists():
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try standard parse first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Strip comments and retry (JSON5 compatibility)
            cleaned = _strip_json_comments(content)
            return json.loads(cleaned)
    except (json.JSONDecodeError, IOError, OSError):
        return None
