#!/usr/bin/env python3
"""
扫描路径过滤器 v1.0
Path Filter — 基于 .scannerignore 文件排除安全文件/目录

所有分析引擎共享此过滤器，避免各自维护排除列表。
格式兼容 gitignore glob 语法（支持 ! 反转模式）。
"""

import fnmatch
from pathlib import Path
from typing import List, Optional


class PathFilter:
    """扫描路径过滤器"""

    DEFAULT_IGNORES = frozenset({
        'node_modules', '__pycache__', '.git', '.venv', 'venv',
        '.tmp_scan',
    })

    def __init__(self, ignore_file: Optional[str] = None):
        self._negations: List[str] = []   # !pattern (允许的文件)
        self.patterns: List[str] = []      # 完整路径模式 (e.g. "rules/*.yaml")
        self.dir_patterns: List[str] = []   # 目录名模式 (e.g. "tests/")
        self.file_patterns: List[str] = []  # 文件名模式 (e.g. "*.md")
        self._load(ignore_file)

    def _load(self, ignore_file: Optional[str]):
        if ignore_file and Path(ignore_file).exists():
            self._parse(Path(ignore_file))
        else:
            default = Path(__file__).parent.parent / '.scannerignore'
            if default.exists():
                self._parse(default)

    def _parse(self, file_path: Path):
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            return

        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('!'):
                # 反转模式：显式允许
                self._negations.append(line[1:])
                continue

            if line.endswith('/'):
                self.dir_patterns.append(line.rstrip('/'))
            elif '/' in line or '*' in line:
                self.patterns.append(line)
            else:
                self.file_patterns.append(line)

    def should_ignore(self, file_path: Path, base_dir: Optional[Path] = None) -> bool:
        name = file_path.name
        parts = file_path.parts

        # 1. 默认忽略
        if any(p in self.DEFAULT_IGNORES for p in parts):
            return True

        # 2. 隐藏文件
        if name.startswith('.'):
            return True

        # 3. 先检查 negation（!pattern）— 显式允许优先
        for pattern in self._negations:
            if fnmatch.fnmatch(name, pattern):
                return False
            if base_dir:
                try:
                    rel = str(file_path.relative_to(base_dir))
                except ValueError:
                    rel = str(file_path)
                if fnmatch.fnmatch(rel, pattern):
                    return False

        # 4. 目录模式匹配
        for pattern in self.dir_patterns:
            if pattern in parts:
                return True

        # 5. 文件名模式匹配
        for pattern in self.file_patterns:
            if fnmatch.fnmatch(name, pattern):
                return True

        # 6. 路径模式匹配
        if base_dir:
            try:
                rel_path = str(file_path.relative_to(base_dir))
            except ValueError:
                rel_path = str(file_path)
        else:
            rel_path = str(file_path)

        for pattern in self.patterns:
            if fnmatch.fnmatch(rel_path, pattern):
                return True
            if fnmatch.fnmatch(name, pattern):
                return True

        return False
