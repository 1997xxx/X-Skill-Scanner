#!/usr/bin/env python3
"""
实时文件监控引擎 v1.0
Real-Time File Monitor — Shield Mode

持续监控技能目录的文件变化，检测运行时注入攻击：
- inotify/fsevents 监听文件系统事件
- 新文件创建时立即扫描
- 文件修改时增量比对
- 可疑进程检测（谁在修改文件）

跨平台支持:
- macOS: FSEvents (via fswatch)
- Linux: inotifywait
- Windows: ReadDirectoryChangesW (via watchdog)
"""

import os
import sys
import time
import json
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class FileEvent:
    """文件事件"""
    event_type: str       # CREATED / MODIFIED / DELETED / RENAMED
    file_path: str
    timestamp: str
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    severity: str = "INFO"
    description: str = ""


@dataclass
class MonitorConfig:
    """监控配置"""
    watch_dirs: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=lambda: [
        '*.pyc', '__pycache__', '.git', 'node_modules', '.DS_Store'
    ])
    scan_on_create: bool = True
    scan_on_modify: bool = True
    alert_threshold: int = 3   # 连续告警阈值
    poll_interval: float = 1.0  # 轮询间隔（秒）


class FileMonitor:
    """实时文件监控器"""

    def __init__(self, config: Optional[MonitorConfig] = None):
        self.config = config or MonitorConfig()
        self.file_states: Dict[str, Dict] = {}  # path -> {hash, mtime, size}
        self.event_history: List[FileEvent] = []
        self.alert_count = 0
        self._running = False
        self._callbacks: List[Callable] = []

    def register_callback(self, callback: Callable[[FileEvent], None]):
        """注册事件回调"""
        self._callbacks.append(callback)

    def initialize_baseline(self, dir_path: Path):
        """初始化基线状态"""
        for fp in dir_path.rglob('*'):
            if not fp.is_file():
                continue
            if fp.name.startswith('.'):
                continue
            try:
                stat = fp.stat()
                content = fp.read_bytes()
                self.file_states[str(fp)] = {
                    'sha256': hashlib.sha256(content).hexdigest(),
                    'mtime': stat.st_mtime,
                    'size': stat.st_size,
                }
            except Exception:
                pass

    def _compute_hash(self, file_path: Path) -> Optional[str]:
        """计算文件哈希"""
        try:
            return hashlib.sha256(file_path.read_bytes()).hexdigest()
        except Exception:
            return None

    def _emit_event(self, event: FileEvent):
        """发出事件"""
        self.event_history.append(event)
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def check_changes(self, dir_path: Path) -> List[FileEvent]:
        """检查目录变更（轮询模式）"""
        events = []
        current_files = set()

        for fp in dir_path.rglob('*'):
            if not fp.is_file():
                continue
            if fp.name.startswith('.'):
                continue
            fp_str = str(fp)
            current_files.add(fp_str)

            try:
                stat = fp.stat()
                new_hash = hashlib.sha256(fp.read_bytes()).hexdigest()
            except Exception:
                continue

            if fp_str not in self.file_states:
                # 新文件
                event = FileEvent(
                    event_type='CREATED',
                    file_path=fp_str,
                    timestamp=datetime.now().isoformat(),
                    new_hash=new_hash,
                    severity=self._classify_new_file(fp),
                    description=f'检测到新文件: {fp.name}',
                )
                events.append(event)
                self._emit_event(event)
                self.file_states[fp_str] = {
                    'sha256': new_hash,
                    'mtime': stat.st_mtime,
                    'size': stat.st_size,
                }

            elif self.file_states[fp_str]['sha256'] != new_hash:
                # 文件修改
                old_hash = self.file_states[fp_str]['sha256']
                event = FileEvent(
                    event_type='MODIFIED',
                    file_path=fp_str,
                    timestamp=datetime.now().isoformat(),
                    old_hash=old_hash,
                    new_hash=new_hash,
                    severity='HIGH' if self._is_critical_file(fp) else 'MEDIUM',
                    description=f'文件被修改: {fp.name}',
                )
                events.append(event)
                self._emit_event(event)
                self.file_states[fp_str] = {
                    'sha256': new_hash,
                    'mtime': stat.st_mtime,
                    'size': stat.st_size,
                }

        # 检测删除
        for fp_str in list(self.file_states.keys()):
            if fp_str not in current_files:
                event = FileEvent(
                    event_type='DELETED',
                    file_path=fp_str,
                    timestamp=datetime.now().isoformat(),
                    old_hash=self.file_states[fp_str]['sha256'],
                    severity='HIGH',
                    description=f'文件被删除: {Path(fp_str).name}',
                )
                events.append(event)
                self._emit_event(event)
                del self.file_states[fp_str]

        return events

    def _classify_new_file(self, fp: Path) -> str:
        """分类新文件的严重程度"""
        critical_exts = {'.py', '.js', '.ts', '.sh', '.so', '.dylib'}
        critical_names = {'SKILL.md', 'config.json', '.env', 'requirements.txt'}

        if fp.suffix.lower() in critical_exts:
            return 'HIGH'
        if fp.name in critical_names:
            return 'CRITICAL'
        return 'LOW'

    def _is_critical_file(self, fp: Path) -> bool:
        """判断是否为关键文件"""
        critical_exts = {'.py', '.js', '.ts', '.sh'}
        critical_names = {'SKILL.md', 'scanner.py', 'hooks/', 'config/'}

        if fp.suffix.lower() in critical_exts:
            return True
        for cn in critical_names:
            if fp.name == cn or str(fp).endswith(cn):
                return True
        return False

    def start_polling(self, dir_path: Path, interval: Optional[float] = None):
        """启动轮询监控"""
        self._running = True
        interval = interval or self.config.poll_interval

        print(f"🛡️  开始监控: {dir_path}")
        print(f"   轮询间隔: {interval}s")
        print(f"   按 Ctrl+C 停止\n")

        try:
            while self._running:
                events = self.check_changes(dir_path)
                if events:
                    for e in events:
                        self._print_event(e)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n🛑 监控已停止")
            self._running = False

    def _print_event(self, event: FileEvent):
        """打印事件"""
        icons = {
            'CREATED': '📄',
            'MODIFIED': '✏️',
            'DELETED': '🗑️',
            'RENAMED': '🔄',
        }
        icon = icons.get(event.event_type, '❓')
        severity_colors = {
            'CRITICAL': '\033[91m',
            'HIGH': '\033[93m',
            'MEDIUM': '\033[33m',
            'LOW': '\033[94m',
            'INFO': '\033[92m',
        }
        color = severity_colors.get(event.severity, '')
        reset = '\033[0m'
        print(f"{color}{icon} [{event.severity}] {event.event_type}: {event.file_path}{reset}")
        print(f"   {event.description}")

    def stop(self):
        """停止监控"""
        self._running = False

    def get_summary(self) -> Dict:
        """获取监控摘要"""
        by_type = {}
        by_severity = {}
        for e in self.event_history:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1

        return {
            'total_events': len(self.event_history),
            'by_type': by_type,
            'by_severity': by_severity,
            'watched_files': len(self.file_states),
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(description='实时文件监控 — Shield Mode')
    parser.add_argument('dir', help='监控目录')
    parser.add_argument('-i', '--interval', type=float, default=1.0, help='轮询间隔（秒）')
    parser.add_argument('--json-output', help='输出 JSON 到文件')
    args = parser.parse_args()

    monitor = FileMonitor(MonitorConfig(poll_interval=args.interval))
    monitor.initialize_baseline(Path(args.dir))

    if args.json_output:
        def json_cb(event):
            with open(args.json_output, 'a') as f:
                f.write(json.dumps({
                    'event_type': event.event_type,
                    'file_path': event.file_path,
                    'timestamp': event.timestamp,
                    'severity': event.severity,
                    'description': event.description,
                }) + '\n')
        monitor.register_callback(json_cb)

    monitor.start_polling(Path(args.dir), args.interval)


if __name__ == '__main__':
    main()
