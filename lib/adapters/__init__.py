#!/usr/bin/env python3
"""
Agent Adapters - 跨平台适配器实现

各平台适配器：
- OpenClawAdapter: OpenClaw (sessions_spawn)
- ClaudeCodeAdapter: Claude Code (claude CLI)
- CursorAdapter: Cursor IDE (cursor CLI)
- WindsurfAdapter: Windsurf (windsurf CLI)
- QClawAdapter: QClaw (qclaw CLI)
- CoPawAdapter: CoPaw (copaw CLI)
"""

from .openclaw_adapter import OpenClawAdapter
from .claude_code_adapter import ClaudeCodeAdapter
from .cursor_adapter import CursorAdapter, WindsurfAdapter
from .qclaw_adapter import QClawAdapter, CoPawAdapter

__all__ = [
    'OpenClawAdapter',
    'ClaudeCodeAdapter',
    'CursorAdapter',
    'WindsurfAdapter',
    'QClawAdapter',
    'CoPawAdapter',
]