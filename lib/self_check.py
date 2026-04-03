#!/usr/bin/env python3
"""
自检核心模块 + LLM 配置可用性检查

跨平台兼容 (macOS / Linux / Windows)。
用法: python self_check.py [--no-llm]

退出码: 0 = 全部通过, 1 = 关键模块失败
"""

import os
import sys
from pathlib import Path


def find_lib_dir() -> Path:
    """找到 lib 目录路径（跨平台）"""
    # 方法 1: __file__ (作为脚本运行时有效)
    try:
        return Path(__file__).resolve().parent
    except NameError:
        pass

    # 方法 2: 环境变量 XSS_SCAN_PATH
    env_path = os.environ.get('XSS_SCAN_PATH', '')
    if env_path:
        p = Path(env_path) / 'lib'
        if p.is_dir():
            return p

    # 方法 3: 从当前工作目录推断
    cwd = Path.cwd()
    for candidate in [cwd / 'lib', cwd.parent / 'lib']:
        if (candidate / 'scanner.py').is_file():
            return candidate

    # 方法 4: 从默认安装路径查找
    home = Path.home()
    for base in [home / '.openclaw' / 'skills' / 'x-skill-scanner',
                 home / '.openclaw' / 'workspace' / 'skills' / 'x-skill-scanner']:
        p = base / 'lib'
        if p.is_dir() and (p / 'scanner.py').is_file():
            return p

    return Path('.')


def check_module(name: str, attr: str = None):
    """检查模块是否可导入，可选检查特定属性"""
    try:
        mod = __import__(name)
        if attr:
            if hasattr(mod, attr):
                return f'✅ {name} OK (has {attr})'
            return f'⚠️  {name} loaded but missing {attr}'
        return f'✅ {name} OK'
    except Exception as e:
        return f'❌ {name} FAIL: {e}'


def check_llm_provider():
    """检查 LLM Provider 配置是否可用"""
    try:
        from llm_provider import discover_provider
        cfg = discover_provider(force=True)
        if cfg:
            return f'✅ LLM Provider OK ({cfg["model"]}, type={cfg["type"]})'
        return '⚠️  LLM Provider 不可用 — 将跳过语义审计（不影响基础扫描）'
    except Exception as e:
        return f'⚠️  LLM Provider 检测失败: {e} — 将跳过语义审计'


def main():
    no_llm = '--no-llm' in sys.argv
    lib_dir = find_lib_dir()

    # 确保 lib 目录在 Python 路径中
    lib_str = str(lib_dir)
    if lib_str not in sys.path:
        sys.path.insert(0, lib_str)

    checks = [
        ('static_analyzer', None),
        ('llm_reviewer', 'LLMReviewer'),
        ('semantic_auditor', 'SemanticAuditor'),
        ('dependency_checker', None),
        ('deobfuscator', None),
    ]

    results = []

    # 模块导入检查
    for name, attr in checks:
        results.append(check_module(name, attr))

    # LLM Provider 检查（可选跳过）
    if not no_llm:
        results.append(check_llm_provider())
    else:
        results.append('ℹ️  LLM Provider 检查已跳过 (--no-llm)')

    # 输出结果
    for r in results:
        print(r)

    critical = [r for r in results if r.startswith('❌')]
    ok_count = sum(1 for r in results if r.startswith('✅'))
    warn_count = sum(1 for r in results if r.startswith('⚠️'))

    print()
    if critical:
        print(f'⚠️  {len(critical)} 个关键模块异常，请检查')
        sys.exit(1)
    else:
        msg = f'🎉 全部 {ok_count} 个核心模块正常'
        if warn_count:
            msg += f'，{warn_count} 个非关键警告'
        print(msg)
        sys.exit(0)


if __name__ == '__main__':
    main()
