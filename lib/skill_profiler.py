#!/usr/bin/env python3
"""
Skill Profiler v5.0 — 技能画像引擎

设计理念：
- 在深度扫描前先获取技能基本情况
- 根据画像结果决定扫描深度和策略
- 减少不必要的 LLM 调用

输出：
- skill_meta: 技能元数据（名称、作者、描述、类型）
- trust_score: 信任分数 (0-100)
- scan_strategy: 推荐的扫描策略
- risk_fingerprint: 风险指纹（快速初筛）
"""

import os
import re
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class SkillProfile:
    """技能画像结果"""
    name: str
    author: str
    description: str
    skill_type: str
    file_count: int
    total_size: int
    languages: List[str]
    has_skill_md: bool
    has_package_json: bool
    has_requirements: bool
    has_setup_py: bool
    has_install_script: bool
    repo_age_days: int          # 如果是 git 仓库
    commit_count: int           # 如果是 git 仓库
    trust_score: int            # 0-100
    scan_strategy: str          # 'full' | 'standard' | 'quick'
    risk_fingerprint: Dict      # 快速风险指标
    metadata: Dict              # 额外元数据


# ─── 信任评分因子 ─────────────────────────────────────────────
TRUST_FACTORS = {
    'has_skill_md':        {'weight': 10, 'condition': True},
    'has_readme':          {'weight': 5,  'condition': True},
    'has_license':         {'weight': 5,  'condition': True},
    'has_tests':           {'weight': 10, 'condition': True},
    'has_git_history':     {'weight': 10, 'condition': True},
    'author_known':        {'weight': 15, 'condition': True},  # 从威胁情报判断
    'reasonable_size':     {'weight': 5,  'condition': True},  # 不是超大或超小
    'common_languages':    {'weight': 5,  'condition': True},  # 主流语言
    'no_install_hooks':    {'weight': 15, 'condition': True},  # 无安装钩子
    'no_obvious_red_flags':{'weight': 20, 'condition': True},  # 无明显红旗
}


class SkillProfiler:
    """技能画像引擎 — 快速提取技能基本信息"""

    def __init__(self):
        self._threat_intel = None

    def set_threat_intel(self, threat_intel):
        """设置威胁情报实例用于作者信誉检查"""
        self._threat_intel = threat_intel

    def profile(self, target: Path) -> SkillProfile:
        """生成技能画像"""
        # ─── 基础元数据提取 ───────────────────────────────────
        meta = self._extract_metadata(target)
        
        # ─── 文件统计 ─────────────────────────────────────────
        file_stats = self._count_files(target)
        
        # ─── 语言检测 ─────────────────────────────────────────
        languages = self._detect_languages(target)
        
        # ─── Git 信息 ─────────────────────────────────────────
        git_info = self._get_git_info(target)
        
        # ─── 红旗检测（快速） ──────────────────────────────────
        red_flags = self._quick_red_flags(target)
        
        # ─── 信任评分 ─────────────────────────────────────────
        trust_score = self._calculate_trust_score(
            meta, file_stats, languages, git_info, red_flags
        )
        
        # ─── 扫描策略推荐 ──────────────────────────────────────
        scan_strategy = self._recommend_strategy(trust_score, red_flags)
        
        # ─── 风险指纹 ─────────────────────────────────────────
        risk_fp = self._build_risk_fingerprint(target, red_flags)
        
        return SkillProfile(
            name=meta.get('name', target.name),
            author=meta.get('author', ''),
            description=meta.get('description', ''),
            skill_type=meta.get('type', 'unknown'),
            file_count=file_stats['count'],
            total_size=file_stats['size'],
            languages=languages,
            has_skill_md=meta.get('has_skill_md', False),
            has_package_json=file_stats['has_package_json'],
            has_requirements=file_stats['has_requirements'],
            has_setup_py=file_stats['has_setup_py'],
            has_install_script=file_stats['has_install_script'],
            repo_age_days=git_info.get('age_days', 0),
            commit_count=git_info.get('commits', 0),
            trust_score=trust_score,
            scan_strategy=scan_strategy,
            risk_fingerprint=risk_fp,
            metadata={
                'git_remote': git_info.get('remote', ''),
                'red_flags': red_flags,
            }
        )

    def _extract_metadata(self, target: Path) -> Dict:
        """从 SKILL.md 提取元数据"""
        meta = {'name': target.name, 'author': '', 'description': '', 'type': 'unknown'}
        
        skill_md = target / 'SKILL.md' if target.is_dir() else target
        if skill_md.exists() and skill_md.is_file():
            meta['has_skill_md'] = True
            try:
                content = skill_md.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                return meta
            
            # 作者提取
            author_patterns = [
                r'Author:\s*(.+)',
                r'作者[:：]\s*(.+)',
                r'Created by[:：]?\s*(.+)',
                r'By[:：]\s*(.+)',
                r'@(\w+)',
                r'github\.com/([^/]+)/',
            ]
            for pattern in author_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    meta['author'] = match.group(1).strip().rstrip('.')
                    break
            
            # 路径推断作者
            if not meta['author']:
                path_parts = target.parts
                for i, part in enumerate(path_parts):
                    if part == 'skills' and i + 1 < len(path_parts):
                        potential = path_parts[i + 1]
                        if potential not in ('main', 'master', 'blob', 'tree'):
                            meta['author'] = potential
                            break
            
            # 描述提取
            desc_match = re.search(r'^>\s*(.+)$', content, re.MULTILINE)
            if desc_match:
                meta['description'] = desc_match.group(1).strip()
            
            # 技能类型
            if 'openclaw' in content.lower():
                meta['type'] = 'OpenClaw Skill'
            elif 'claude' in content.lower():
                meta['type'] = 'Claude Skill'
        else:
            meta['has_skill_md'] = False
            # 目录结构推断
            if (target / 'package.json').exists():
                meta['type'] = 'Node.js Package'
            elif (target / 'setup.py').exists() or (target / 'pyproject.toml').exists():
                meta['type'] = 'Python Package'
        
        return meta

    def _count_files(self, target: Path) -> Dict:
        """统计文件信息"""
        if target.is_file():
            return {
                'count': 1,
                'size': target.stat().st_size,
                'has_package_json': False,
                'has_requirements': False,
                'has_setup_py': False,
                'has_install_script': False,
            }
        
        files = list(target.rglob('*'))
        file_list = [f for f in files if f.is_file()]
        
        total_size = sum(f.stat().st_size for f in file_list)
        
        return {
            'count': len(file_list),
            'size': total_size,
            'has_package_json': any(f.name == 'package.json' for f in file_list),
            'has_requirements': any(f.name == 'requirements.txt' for f in file_list),
            'has_setup_py': any(f.name == 'setup.py' for f in file_list),
            'has_install_script': any(
                f.name in ('postinstall.sh', 'install.sh', 'setup.sh') 
                for f in file_list
            ),
        }

    def _detect_languages(self, target: Path) -> List[str]:
        """检测主要编程语言"""
        lang_map = {
            '.py': 'Python', '.sh': 'Shell', '.bash': 'Shell',
            '.js': 'JavaScript', '.ts': 'TypeScript',
            '.md': 'Markdown', '.json': 'JSON', '.yaml': 'YAML', '.yml': 'YAML',
            '.toml': 'TOML', '.ini': 'INI',
        }
        
        if target.is_file():
            return [lang_map.get(target.suffix, 'Other')]
        
        exts = set()
        for f in target.rglob('*'):
            if f.is_file() and f.suffix:
                exts.add(f.suffix.lower())
        
        return sorted(set(lang_map.get(e, e) for e in exts))

    def _get_git_info(self, target: Path) -> Dict:
        """获取 Git 仓库信息"""
        import subprocess
        
        git_dir = target / '.git' if target.is_dir() else None
        if not git_dir or not git_dir.exists():
            # 检查父目录
            git_dir = target.parent / '.git' if target.parent else None
            if not git_dir or not git_dir.exists():
                return {'age_days': 0, 'commits': 0, 'remote': ''}
        
        info = {}
        
        try:
            # 提交数
            result = subprocess.run(
                ['git', 'rev-list', '--count', 'HEAD'],
                cwd=str(target if target.is_dir() else target.parent),
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                info['commits'] = int(result.stdout.strip())
        except Exception:
            info['commits'] = 0
        
        try:
            # 首次提交时间
            result = subprocess.run(
                ['git', 'log', '--reverse', '--format=%ct', '-1'],
                cwd=str(target if target.is_dir() else target.parent),
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                import time
                first_commit = int(result.stdout.strip())
                info['age_days'] = (int(time.time()) - first_commit) // 86400
        except Exception:
            info['age_days'] = 0
        
        try:
            # 远程 URL
            result = subprocess.run(
                ['git', 'remote', 'get-url', 'origin'],
                cwd=str(target if target.is_dir() else target.parent),
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                info['remote'] = result.stdout.strip()
        except Exception:
            info['remote'] = ''
        
        return info

    def _quick_red_flags(self, target: Path) -> List[str]:
        """快速红旗检测（不依赖规则引擎）"""
        flags = []
        
        if target.is_file():
            return flags
        
        files = {f.name for f in target.rglob('*') if f.is_file()}
        
        # 可疑文件
        suspicious_files = {
            '.env', 'passwords.txt', 'credentials.json', 'keylog.py',
            'exfil.sh', 'backdoor.py', 'reverse_shell.py',
        }
        for sf in suspicious_files:
            if sf in files:
                flags.append(f'suspicious_file:{sf}')
        
        # 检查 SKILL.md 中的明显恶意指令
        skill_md = target / 'SKILL.md'
        if skill_md.exists():
            try:
                content = skill_md.read_text(encoding='utf-8', errors='ignore').lower()
                malicious_patterns = [
                    ('ignore all previous instructions', 'prompt_injection'),
                    ('disregard all safety', 'safety_bypass'),
                    ('you are now in developer mode', 'mode_switch'),
                    ('do not tell the user', 'secret_keeping'),
                ]
                for pattern, flag_name in malicious_patterns:
                    if pattern in content:
                        flags.append(f'md_{flag_name}')
            except Exception:
                pass
        
        # 检查安装脚本
        for script_name in ('postinstall.sh', 'install.sh', 'setup.sh'):
            script = target / script_name
            if script.exists():
                try:
                    content = script.read_text(encoding='utf-8', errors='ignore')
                    if re.search(r'curl.*\|\s*(ba)?sh', content):
                        flags.append('install_script_pipe_exec')
                    if re.search(r'rm\s+-rf\s+/', content):
                        flags.append('install_script_destructive')
                except Exception:
                    pass
        
        # 异常大的文件
        for f in target.rglob('*'):
            if f.is_file() and f.stat().st_size > 50 * 1024 * 1024:  # > 50MB
                flags.append(f'large_file:{f.name}')
        
        return flags

    def _calculate_trust_score(
        self, meta, file_stats, languages, git_info, red_flags
    ) -> int:
        """计算信任分数 (0-100)"""
        score = 50  # 基础分
        
        # 正面因素
        if meta.get('has_skill_md'):
            score += 10
        if meta.get('author'):
            score += 5
        
        # 作者信誉检查
        if self._threat_intel and meta.get('author'):
            is_bad, _ = self._threat_intel.check_author(meta['author'])
            if is_bad:
                score -= 30
            else:
                score += 10
        
        # Git 历史
        if git_info.get('commits', 0) > 5:
            score += 10
        if git_info.get('age_days', 0) > 30:
            score += 5
        
        # 测试文件
        if file_stats.get('has_package_json') or file_stats.get('has_requirements'):
            score += 5
        
        # 红旗扣分
        score -= len(red_flags) * 15
        
        # 大小异常
        total_size = file_stats.get('size', 0)
        if total_size > 10 * 1024 * 1024:  # > 10MB
            score -= 10
        elif total_size < 100:  # 太小
            score -= 5
        
        return max(0, min(100, score))

    def _recommend_strategy(self, trust_score: int, red_flags: List[str]) -> str:
        """根据信任分数推荐扫描策略"""
        if trust_score >= 70 and not red_flags:
            return 'quick'       # 快速扫描，跳过 LLM
        elif trust_score >= 40:
            return 'standard'    # 标准扫描 + LLM 审查 MEDIUM+
        else:
            return 'full'        # 完整扫描 + LLM 审查所有发现


    def _build_risk_fingerprint(self, target: Path, red_flags: List[str]) -> Dict:
        """构建风险指纹"""
        fp = {
            'red_flags': red_flags,
            'flag_count': len(red_flags),
            'risk_level': 'low',
        }
        
        if len(red_flags) >= 3:
            fp['risk_level'] = 'high'
        elif len(red_flags) >= 1:
            fp['risk_level'] = 'medium'
        
        # 快速哈希
        if target.is_dir():
            files_hash = hashlib.md5()
            for f in sorted(target.rglob('*')):
                if f.is_file():
                    files_hash.update(str(f.relative_to(target)).encode())
            fp['structure_hash'] = files_hash.hexdigest()[:12]
        
        return fp


__all__ = ['SkillProfiler', 'SkillProfile']
