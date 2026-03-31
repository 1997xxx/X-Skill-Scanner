#!/usr/bin/env python3
"""
基线追踪引擎 v1.0
Baseline Tracker — Rug-Pull Detection

记录已扫描技能的 SHA-256 指纹，检测后续变更：
- 首次扫描建立基线
- 再次扫描时比对差异
- 检测文件新增/删除/修改
- 生成变更报告
"""

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class FileHash:
    """单个文件的哈希记录"""
    path: str
    sha256: str
    size: int
    first_seen: str       # ISO timestamp
    last_modified: str    # ISO timestamp


@dataclass
class SkillBaseline:
    """技能基线记录"""
    skill_name: str
    skill_path: str
    scan_time: str
    risk_level: str
    risk_score: int
    total_files: int
    file_hashes: Dict[str, FileHash]   # relative_path -> FileHash
    metadata: Dict = None


@dataclass
class ChangeRecord:
    """变更记录"""
    change_type: str      # ADDED / MODIFIED / DELETED
    file_path: str
    old_hash: Optional[str]
    new_hash: Optional[str]
    severity: str         # CRITICAL if core files changed


class BaselineTracker:
    """基线追踪器"""

    def __init__(self, baseline_file: Optional[str] = None):
        if baseline_file is None:
            baseline_file = str(Path(__file__).parent.parent / 'data' / 'baseline.json')
        self.baseline_file = Path(baseline_file)
        self.baselines: Dict[str, SkillBaseline] = {}
        self._load()

    def _load(self):
        """加载基线数据"""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for name, bl in data.items():
                    self.baselines[name] = bl
            except (json.JSONDecodeError, KeyError):
                self.baselines = {}

    def save(self):
        """保存基线数据"""
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, 'w', encoding='utf-8') as f:
            json.dump(self.baselines, f, ensure_ascii=False, indent=2)

    def compute_file_hashes(self, dir_path: Path) -> Dict[str, FileHash]:
        """计算目录下所有文件的 SHA-256"""
        hashes = {}
        extensions = {'.py', '.js', '.ts', '.sh', '.md', '.yaml', '.yml', '.json', '.txt'}

        for fp in dir_path.rglob('*'):
            if not fp.is_file():
                continue
            if fp.name.startswith('.'):
                continue
            if any(p in ['node_modules', '__pycache__', '.git', '.tmp_scan', 'reports', 'tests', 'test'] for p in fp.parts):
                continue
            if fp.suffix.lower() not in extensions:
                continue

            try:
                content = fp.read_bytes()
                rel_path = str(fp.relative_to(dir_path))
                hashes[rel_path] = FileHash(
                    path=rel_path,
                    sha256=hashlib.sha256(content).hexdigest(),
                    size=len(content),
                    first_seen=datetime.now().isoformat(),
                    last_modified=datetime.now().isoformat(),
                )
            except Exception:
                pass

        return hashes

    def create_baseline(self, skill_name: str, skill_path: str,
                        risk_level: str, risk_score: int) -> SkillBaseline:
        """创建新基线"""
        dir_path = Path(skill_path)
        file_hashes = self.compute_file_hashes(dir_path)

        baseline = SkillBaseline(
            skill_name=skill_name,
            skill_path=skill_path,
            scan_time=datetime.now().isoformat(),
            risk_level=risk_level,
            risk_score=risk_score,
            total_files=len(file_hashes),
            file_hashes={k: asdict(v) for k, v in file_hashes.items()},
            metadata={'version': '1.0'},
        )

        self.baselines[skill_name] = asdict(baseline)
        self.save()
        print(f"📋 基线已创建: {skill_name} ({len(file_hashes)} 个文件)")
        return baseline

    def check_changes(self, skill_name: str, skill_path: str) -> Tuple[bool, List[ChangeRecord]]:
        """
        检查技能是否发生变更（Rug-Pull 检测）

        Returns:
            (has_changes, change_records)
        """
        if skill_name not in self.baselines:
            return False, []

        old_baseline = self.baselines[skill_name]
        old_hashes = old_baseline.get('file_hashes', {})
        dir_path = Path(skill_path)

        # 计算当前文件哈希
        current_hashes = {}
        for fp in dir_path.rglob('*'):
            if not fp.is_file() or fp.name.startswith('.'):
                continue
            if any(p in ['node_modules', '__pycache__', '.git', '.tmp_scan', 'reports', 'tests', 'test'] for p in fp.parts):
                continue
            try:
                content = fp.read_bytes()
                rel_path = str(fp.relative_to(dir_path))
                current_hashes[rel_path] = hashlib.sha256(content).hexdigest()
            except Exception:
                pass

        changes = []

        # 检测修改和删除
        for rel_path, old_hash_info in old_hashes.items():
            old_hash = old_hash_info['sha256'] if isinstance(old_hash_info, dict) else old_hash_info

            if rel_path not in current_hashes:
                # 文件被删除
                changes.append(ChangeRecord(
                    change_type='DELETED',
                    file_path=rel_path,
                    old_hash=old_hash,
                    new_hash=None,
                    severity=self._classify_change_severity(rel_path),
                ))
            elif current_hashes[rel_path] != old_hash:
                # 文件被修改
                changes.append(ChangeRecord(
                    change_type='MODIFIED',
                    file_path=rel_path,
                    old_hash=old_hash,
                    new_hash=current_hashes[rel_path],
                    severity=self._classify_change_severity(rel_path),
                ))

        # 检测新增文件
        for rel_path, new_hash in current_hashes.items():
            if rel_path not in old_hashes:
                changes.append(ChangeRecord(
                    change_type='ADDED',
                    file_path=rel_path,
                    old_hash=None,
                    new_hash=new_hash,
                    severity=self._classify_change_severity(rel_path),
                ))

        has_changes = len(changes) > 0
        return has_changes, changes

    def _classify_change_severity(self, file_path: str) -> str:
        """根据变更文件类型分类严重程度"""
        critical_files = {'SKILL.md', 'scanner.py', 'hooks/', 'config/'}
        important_files = {'.py', '.js', '.ts', '.sh'}

        # 核心配置文件变更 = CRITICAL
        for cf in critical_files:
            if file_path == cf or file_path.startswith(cf):
                return 'CRITICAL'

        # 代码文件变更 = HIGH
        ext = Path(file_path).suffix.lower()
        if ext in important_files:
            return 'HIGH'

        # 文档/数据变更 = MEDIUM
        return 'MEDIUM'

    def update_baseline(self, skill_name: str, skill_path: str,
                        risk_level: str, risk_score: int):
        """更新基线（确认变更后）"""
        self.create_baseline(skill_name, skill_path, risk_level, risk_score)
        print(f"🔄 基线已更新: {skill_name}")

    def get_baseline_info(self, skill_name: str) -> Optional[Dict]:
        """获取基线信息"""
        return self.baselines.get(skill_name)

    def list_baselines(self) -> List[Dict]:
        """列出所有基线"""
        result = []
        for name, bl in self.baselines.items():
            result.append({
                'skill_name': name,
                'scan_time': bl.get('scan_time'),
                'risk_level': bl.get('risk_level'),
                'total_files': bl.get('total_files'),
            })
        return result

    def remove_baseline(self, skill_name: str) -> bool:
        """移除基线"""
        if skill_name in self.baselines:
            del self.baselines[skill_name]
            self.save()
            return True
        return False
