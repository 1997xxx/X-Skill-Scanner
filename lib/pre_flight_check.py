#!/usr/bin/env python3
"""
Pre-flight Legality Check — 技能合法性前置校验

在正式扫描前快速验证目标是否为一个合法的 OpenClaw skill。
检测非 skill 文件（恶意 zip、二进制投递包等），避免后续引擎误判。

设计原则：
- 快速失败：不合法直接拒绝，不进入 12 层扫描管线
- 零依赖：只用标准库，不调用 LLM
- 明确告警：给出具体原因和修复建议

v5.1 新增 — 教训来源：natan89/awesome-openclaw-skills 恶意 zip 事件
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# ─── 二进制可执行文件扩展名 ──────────────────────────────
BINARY_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.drv', '.ocx',   # Windows
    '.so', '.dylib', '.bundle',                # macOS/Linux
    '.elf',                                    # Linux ELF
    '.bin', '.com', '.scr', '.pif',            # Other executables
    '.msi', '.bat', '.cmd', '.ps1',            # Windows installers/scripts
    '.app',                                    # macOS app bundle
}

# ─── 危险文件模式（文件名关键词） ────────────────────────
DANGEROUS_PATTERNS = [
    re.compile(r'compiler\.exe', re.I),
    re.compile(r'application\.(cmd|bat|ps1)', re.I),
    re.compile(r'setup\.(exe|msi|bat)', re.I),
    re.compile(r'install\.(exe|msi|bat|cmd)', re.I),
    re.compile(r'loader\.(exe|dll)', re.I),
    re.compile(r'dropper\.(exe|dll)', re.I),
    re.compile(r'stealer\.(exe|py|js)', re.I),
]

# ─── 已知混淆/投毒模式 ──────────────────────────────────
OBFUSCATION_INDICATORS = [
    ('dynasm', 'LuaJIT DynASM (可能被滥用于代码混淆)'),
    ('base64_decode', 'Base64 解码调用'),
    ('eval(', 'eval() 动态执行'),
    ('exec(', 'exec() 动态执行'),
]


class PreFlightCheck:
    """前置合法性检查 — Gatekeeper for skill installation"""

    def validate(self, target_path: Path) -> Dict:
        """
        验证目标是否为合法的 OpenClaw skill。

        Returns:
            {
                'passed': bool,
                'findings': [...],
                'verdict': 'PASS' | 'BLOCK',
                'message': str,
            }
        """
        findings: List[Dict] = []

        # ─── v5.5.1: 检测批量扫描模式（多技能目录）─────────────
        is_batch_mode = False
        sub_skills: List[Path] = []
        
        if target_path.is_dir():
            # 检查是否包含多个子目录，每个子目录有自己的 SKILL.md
            sub_dirs = [d for d in target_path.iterdir() if d.is_dir()]
            for sd in sub_dirs:
                if (sd / 'SKILL.md').exists():
                    sub_skills.append(sd)
            
            if len(sub_skills) >= 2:
                is_batch_mode = True

        # ─── 检查 1: 必须有 SKILL.md（单技能模式）────────────
        has_skill_md = False
        if is_batch_mode:
            # 批量模式：不要求根目录有 SKILL.md
            has_skill_md = True
        elif target_path.is_dir():
            skill_md = target_path / 'SKILL.md'
            has_skill_md = skill_md.exists() and skill_md.is_file()
        elif target_path.is_file():
            # 单文件场景（极少见，但允许 .md 文件作为 skill）
            has_skill_md = target_path.suffix.lower() == '.md'

        if not has_skill_md:
            findings.append({
                'id': 'PFC-001',
                'severity': 'CRITICAL',
                'category': 'structure',
                'title': '缺少 SKILL.md — 不是有效的 OpenClaw Skill',
                'title_en': 'Missing SKILL.md — Not a valid OpenClaw Skill',
                'file': str(target_path),
                'line': 0,
                'description': (
                    f'目标目录 {target_path.name} 中没有找到 SKILL.md 文件。'
                    '所有 OpenClaw skills 必须包含 SKILL.md 作为技能定义文件。'
                    '这可能是伪装成 skill 的恶意文件包。'
                ),
                'recommendation': '不要安装此文件。合法的 OpenClaw skill 一定包含 SKILL.md。',
            })

        # ─── 检查 2: 二进制可执行文件 ────────────────────
        binary_files = []
        dangerous_files = []

        if target_path.is_dir():
            for f in target_path.rglob('*'):
                if f.is_file():
                    suffix = f.suffix.lower()
                    name = f.name

                    # 检查二进制扩展名
                    if suffix in BINARY_EXTENSIONS:
                        binary_files.append(str(f.relative_to(target_path)))

                    # 检查危险文件名模式
                    for pattern in DANGEROUS_PATTERNS:
                        if pattern.search(name):
                            dangerous_files.append({
                                'path': str(f.relative_to(target_path)),
                                'pattern': pattern.pattern,
                            })
                            break
        elif target_path.is_file():
            suffix = target_path.suffix.lower()
            if suffix in BINARY_EXTENSIONS:
                binary_files.append(target_path.name)
            for pattern in DANGEROUS_PATTERNS:
                if pattern.search(target_path.name):
                    dangerous_files.append({
                        'path': target_path.name,
                        'pattern': pattern.pattern,
                    })
                    break

        if binary_files:
            findings.append({
                'id': 'PFC-002',
                'severity': 'HIGH',
                'category': 'binary',
                'title': f'发现 {len(binary_files)} 个二进制可执行文件',
                'title_en': f'Found {len(binary_files)} binary executable file(s)',
                'file': ', '.join(binary_files[:5]),
                'line': 0,
                'description': (
                    f'OpenClaw skills 是纯文本配置/脚本文件，不应包含编译后的二进制可执行文件。'
                    f'发现的二进制文件: {", ".join(binary_files[:5])}'
                    '这通常是恶意软件投递的特征。'
                ),
                'recommendation': '不要运行这些文件。如果是合法 skill，它们不应该存在。',
            })

        if dangerous_files:
            for df in dangerous_files:
                findings.append({
                    'id': 'PFC-003',
                    'severity': 'CRITICAL',
                    'category': 'dangerous_name',
                    'title': f'危险文件名: {df["path"]}',
                    'title_en': f'Dangerous filename: {df["path"]}',
                    'file': df['path'],
                    'line': 0,
                    'description': (
                        f'文件名匹配已知恶意软件模式 ({df["pattern"]})。'
                        '常见的恶意软件投递使用此类命名约定。'
                    ),
                    'recommendation': '立即删除此文件，不要执行。',
                })

        # ─── 检查 3: 自启动机制 ──────────────────────────
        autostart_findings = self._check_autostart(target_path)
        findings.extend(autostart_findings)

        # ─── 检查 4: 仅有二进制文件，无源代码 ─────────────
        if target_path.is_dir():
            code_files = list(target_path.rglob('*.py')) + \
                         list(target_path.rglob('*.js')) + \
                         list(target_path.rglob('*.ts')) + \
                         list(target_path.rglob('*.sh'))
            
            all_files = [f for f in target_path.rglob('*') if f.is_file()]
            binary_count = sum(1 for f in all_files if f.suffix.lower() in BINARY_EXTENSIONS)
            
            if len(all_files) > 0 and len(code_files) == 0 and binary_count > 0:
                findings.append({
                    'id': 'PFC-005',
                    'severity': 'CRITICAL',
                    'category': 'no_source',
                    'title': '仅包含二进制文件，无源代码',
                    'title_en': 'Contains only binary files, no source code',
                    'file': str(target_path),
                    'line': 0,
                    'description': (
                        f'目标包含 {len(all_files)} 个文件，其中 {binary_count} 个是二进制文件，'
                        '但没有发现任何源代码文件（.py/.js/.ts/.sh）。'
                        '这是典型的恶意软件投递特征 — 用合法名称包装纯二进制 payload。'
                    ),
                    'recommendation': '绝对不要安装或执行此文件包。',
                })

        # ─── 裁决 ─────────────────────────────────────────
        critical_count = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in findings if f['severity'] == 'HIGH')

        passed = critical_count == 0
        verdict = 'PASS' if passed else 'BLOCK'

        return {
            'passed': passed,
            'verdict': verdict,
            'findings': findings,
            'critical': critical_count,
            'high': high_count,
            'is_batch_mode': is_batch_mode,
            'sub_skills': [str(s) for s in sub_skills] if is_batch_mode else [],
            'message': self._summary(passed, critical_count, high_count, findings, is_batch_mode),
        }

    def _check_autostart(self, target_path: Path) -> List[Dict]:
        """检查自启动机制（批处理、shell RC、cron 等）
        
        v5.5.1 修复：只检查可执行代码文件（.py/.sh/.js/.ts），
        排除 Markdown/文本/配置文件中的关键词误报。
        """
        findings = []

        if not target_path.is_dir():
            return findings

        # 只检查代码文件，跳过文档和配置
        CODE_EXTS = {'.py', '.sh', '.bash', '.js', '.ts', '.jsx', '.tsx',
                     '.bat', '.cmd', '.ps1', '.rb', '.pl'}
        SKIP_EXTS = {'.md', '.txt', '.rst', '.log', '.json', '.yaml', '.yml',
                     '.toml', '.xml', '.html', '.css', '.csv', '.sql',
                     '.lock', '.png', '.jpg', '.gif', '.svg', '.ico',
                     '.woff', '.ttf', '.eot', '.wasm'}

        autostart_patterns = {
            r'^start\s+.*\.(exe|dll|bat|cmd)': 'Windows 自动启动命令',
            r'^open\s+-a\s+': 'macOS 应用自动启动',
            r'chmod\s+\+x': '赋予执行权限',
            r'\b(crontab|at\s+|launchctl|systemctl)\b': '系统级定时/服务注入',
            r'\.(bashrc|zshrc|profile|bash_profile)$': 'Shell 配置文件修改',
        }

        for f in target_path.rglob('*'):
            if not f.is_file():
                continue

            suffix = f.suffix.lower()
            
            # 跳过文档和配置文件
            if suffix in SKIP_EXTS:
                continue
            
            # 只检查代码文件或无扩展名文件
            if suffix not in CODE_EXTS and suffix != '':
                continue
            
            # 只检查小文本文件（避免读大二进制文件）
            try:
                if f.stat().st_size > 1024 * 100:  # > 100KB 跳过
                    continue
                content = f.read_text(errors='ignore')
            except Exception:
                continue

            rel_path = str(f.relative_to(target_path))

            for pattern, desc in autostart_patterns.items():
                if re.search(pattern, content, re.I | re.M):
                    findings.append({
                        'id': 'PFC-004',
                        'severity': 'HIGH',
                        'category': 'autostart',
                        'title': f'发现自启动机制: {desc}',
                        'title_en': f'Autostart mechanism detected: {desc}',
                        'file': rel_path,
                        'line': 0,
                        'description': (
                            f'文件 {rel_path} 包含可能的自启动机制: {desc}。'
                            '这可能是恶意软件确保持久化的手段。'
                        ),
                        'recommendation': '审查此文件的完整内容，确认是否为恶意行为。',
                    })
                    break  # 每个文件只报告一次

        return findings

    def _summary(self, passed: bool, critical: int, high: int, findings: List[Dict], is_batch_mode: bool = False) -> str:
        if passed:
            return '✅ 前置合法性检查通过 — 目标看起来是一个合法的 OpenClaw skill'
        
        issues = []
        if critical > 0:
            issues.append(f'{critical} 个严重问题')
        if high > 0:
            issues.append(f'{high} 个高危问题')
        
        return f'❌ 前置合法性检查未通过 — 发现 {", ".join(issues)}，阻止进入扫描管线'
