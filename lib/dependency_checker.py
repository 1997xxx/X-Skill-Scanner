#!/usr/bin/env python3
"""
依赖安全检查引擎 v1.0
Dependency Security Checker

检测技能依赖中的已知漏洞：
- Python requirements.txt / setup.py / pyproject.toml
- Node.js package.json
- 基于本地 CVE 数据库匹配（无需网络）
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class DependencyFinding:
    """依赖安全发现项"""
    rule_id: str
    title: str
    severity: str
    description: str
    file_path: str
    package_name: str
    installed_version: str
    safe_version: str = ""
    cve_ids: List[str] = None
    remediation: str = "升级到安全版本"


# ─── 已知高危依赖 CVE 数据库 (精简版) ──────────────────────
KNOWN_VULNERABILITIES = {
    # Python 包
    'requests': [
        {'cve': 'CVE-2023-32681', 'affected': '<2.31.0', 'safe': '>=2.31.0',
         'desc': 'Unintended leak of Proxy-Authorization header'},
    ],
    'urllib3': [
        {'cve': 'CVE-2023-45803', 'affected': '<2.0.7', 'safe': '>=2.0.7',
         'desc': 'Request body not stripped after redirect from 303'},
        {'cve': 'CVE-2023-43804', 'affected': '<2.0.6', 'safe': '>=2.0.6',
         'desc': 'Cookie header leaking via cross-origin redirect'},
    ],
    'flask': [
        {'cve': 'CVE-2023-30861', 'affected': '<2.3.2', 'safe': '>=2.3.2',
         'desc': 'Session cookie sent over HTTP for permanent sessions'},
    ],
    'django': [
        {'cve': 'CVE-2023-36053', 'affected': '<4.2.3', 'safe': '>=4.2.3',
         'desc': 'Potential ReDoS in EmailValidator'},
    ],
    'pillow': [
        {'cve': 'CVE-2023-44271', 'affected': '<10.0.1', 'safe': '>=10.0.1',
         'desc': 'Denial of service via untrusted image'},
    ],
    'numpy': [
        {'cve': 'CVE-2021-41496', 'affected': '<1.22.0', 'safe': '>=1.22.0',
         'desc': 'Buffer overflow in array operations'},
    ],
    'pyyaml': [
        {'cve': 'CVE-2020-14343', 'affected': '<5.4', 'safe': '>=5.4',
         'desc': 'Arbitrary code execution via yaml.load()'},
    ],
    'jinja2': [
        {'cve': 'CVE-2024-22195', 'affected': '<3.1.3', 'safe': '>=3.1.3',
         'desc': 'Cross-site scripting via xmlattr filter'},
    ],
    'cryptography': [
        {'cve': 'CVE-2023-49083', 'affected': '<41.0.6', 'safe': '>=41.0.6',
         'desc': 'NULL dereference during PKCS12 parsing'},
    ],
    'setuptools': [
        {'cve': 'CVE-2024-6345', 'affected': '<70.0.0', 'safe': '>=70.0.0',
         'desc': 'Remote code execution via package index'},
    ],
    # Node.js 包
    'express': [
        {'cve': 'CVE-2024-29041', 'affected': '<4.19.2', 'safe': '>=4.19.2',
         'desc': 'Open redirect vulnerability'},
    ],
    'lodash': [
        {'cve': 'CVE-2021-23337', 'affected': '<4.17.21', 'safe': '>=4.17.21',
         'desc': 'Command injection via template function'},
    ],
    'axios': [
        {'cve': 'CVE-2023-45857', 'affected': '<1.6.0', 'safe': '>=1.6.0',
         'desc': 'CSRF token exposure via cross-domain requests'},
    ],
    'node-fetch': [
        {'cve': 'CVE-2022-0235', 'affected': '<2.6.7', 'safe': '>=2.6.7',
         'desc': 'Exposure of sensitive information to unauthorized actor'},
    ],
    'minimist': [
        {'cve': 'CVE-2021-44906', 'affected': '<1.2.6', 'safe': '>=1.2.6',
         'desc': 'Prototype pollution'},
    ],
    'semver': [
        {'cve': 'CVE-2022-25883', 'affected': '<7.5.2', 'safe': '>=7.5.2',
         'desc': 'Regular expression denial of service'},
    ],
    'follow-redirects': [
        {'cve': 'CVE-2024-28849', 'affected': '<1.15.6', 'safe': '>=1.15.6',
         'desc': 'Exposure of sensitive information via proxy authorization'},
    ],
}


def parse_version(ver_str: str) -> Tuple[int, ...]:
    """解析版本号字符串为元组"""
    ver_str = ver_str.strip().lstrip('v')
    parts = []
    for p in ver_str.split('.'):
        match = re.match(r'(\d+)', p)
        if match:
            parts.append(int(match.group(1)))
    return tuple(parts) if parts else (0,)


def version_compare(v1: str, v2: str) -> int:
    """比较两个版本号: -1 (v1<v2), 0 (相等), 1 (v1>v2)"""
    t1 = parse_version(v1)
    t2 = parse_version(v2)
    if t1 < t2:
        return -1
    elif t1 > t2:
        return 1
    return 0


class DependencyChecker:
    """依赖安全检查器"""

    def __init__(self):
        self.findings: List[DependencyFinding] = []
        self.custom_db: Dict[str, List[Dict]] = {}

    def load_custom_db(self, db_path: str):
        """加载自定义 CVE 数据库"""
        path = Path(db_path)
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                self.custom_db = json.load(f)

    def check_directory(self, dir_path: Path) -> List[DependencyFinding]:
        """扫描目录中的依赖文件"""
        findings = []

        # Python 依赖
        req_file = dir_path / 'requirements.txt'
        if req_file.exists():
            findings.extend(self._check_requirements(req_file))

        setup_file = dir_path / 'setup.py'
        if setup_file.exists():
            findings.extend(self._check_setup_py(setup_file))

        pyproject_file = dir_path / 'pyproject.toml'
        if pyproject_file.exists():
            findings.extend(self._check_pyproject(pyproject_file))

        # Node.js 依赖
        pkg_file = dir_path / 'package.json'
        if pkg_file.exists():
            findings.extend(self._check_package_json(pkg_file))

        # 递归检查子目录（最多一层）
        for subdir in dir_path.iterdir():
            if subdir.is_dir() and subdir.name not in ('node_modules', '__pycache__', '.git'):
                sub_req = subdir / 'requirements.txt'
                if sub_req.exists():
                    findings.extend(self._check_requirements(sub_req))
                sub_pkg = subdir / 'package.json'
                if sub_pkg.exists():
                    findings.extend(self._check_package_json(sub_pkg))

        self.findings.extend(findings)
        return findings

    def _check_requirements(self, file_path: Path) -> List[DependencyFinding]:
        """检查 requirements.txt"""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            return findings

        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue

            # 解析: package==1.2.3, package>=1.2.3, package~=1.2.3
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*[=~<>!]+\s*([0-9][0-9a-zA-Z.*]*)', line)
            if match:
                pkg_name = match.group(1).lower()
                pkg_version = match.group(2)
                findings.extend(self._check_package(pkg_name, pkg_version, str(file_path)))

        return findings

    def _check_setup_py(self, file_path: Path) -> List[DependencyFinding]:
        """检查 setup.py 中的 install_requires"""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            return findings

        # 简单正则提取 install_requires 中的包
        requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if requires_match:
            deps = re.findall(r'["\']([a-zA-Z0-9_-]+)\s*[=~<>!]+\s*([0-9][0-9a-zA-Z.*]*)["\']',
                              requires_match.group(1))
            for pkg_name, pkg_version in deps:
                findings.extend(self._check_package(pkg_name.lower(), pkg_version, str(file_path)))

        return findings

    def _check_pyproject(self, file_path: Path) -> List[DependencyFinding]:
        """检查 pyproject.toml 中的依赖"""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            return findings

        # 查找 dependencies = [...] 或 [project.dependencies]
        deps_section = re.search(r'(?:dependencies\s*=\s*\[|\[project\.dependencies\])(.*?)(?:\]|\n\[)',
                                 content, re.DOTALL)
        if deps_section:
            deps = re.findall(r'["\']([a-zA-Z0-9_-]+)\s*[=~<>!]+\s*([0-9][0-9a-zA-Z.*]*)["\']',
                              deps_section.group(1))
            for pkg_name, pkg_version in deps:
                findings.extend(self._check_package(pkg_name.lower(), pkg_version, str(file_path)))

        return findings

    def _check_package_json(self, file_path: Path) -> List[DependencyFinding]:
        """检查 package.json"""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                pkg = json.load(f)
        except Exception:
            return findings

        for section in ('dependencies', 'devDependencies', 'peerDependencies'):
            deps = pkg.get(section, {})
            for pkg_name, version_spec in deps.items():
                # 提取版本号: ^1.2.3, ~1.2.3, >=1.2.3, 1.2.3
                version_match = re.search(r'[~^>=<]*\s*([0-9][0-9a-zA-Z.-]*)', version_spec)
                if version_match:
                    version = version_match.group(1)
                    findings.extend(self._check_package(pkg_name.lower(), version, str(file_path)))

        return findings

    def _check_package(self, pkg_name: str, version: str,
                       file_path: str) -> List[DependencyFinding]:
        """检查单个包的已知漏洞"""
        findings = []

        # 合并内置和自定义数据库
        all_vulns = {**KNOWN_VULNERABILITIES, **self.custom_db}

        vulns = all_vulns.get(pkg_name, [])
        for vuln in vulns:
            affected = vuln.get('affected', '')
            safe = vuln.get('safe', '')

            # 解析 affected 版本范围
            is_affected = False
            if affected.startswith('<'):
                threshold = affected.lstrip('<').strip()
                is_affected = version_compare(version, threshold) < 0
            elif affected.startswith('<='):
                threshold = affected.lstrip('<=').strip()
                is_affected = version_compare(version, threshold) <= 0

            if is_affected:
                findings.append(DependencyFinding(
                    rule_id='DEP_001',
                    title=f'已知漏洞: {pkg_name}@{version}',
                    severity='HIGH',
                    description=vuln.get('desc', f'{pkg_name} {version} 存在已知漏洞'),
                    file_path=file_path,
                    package_name=pkg_name,
                    installed_version=version,
                    safe_version=safe,
                    cve_ids=[vuln.get('cve', '')],
                    remediation=f'升级 {pkg_name} 到 {safe}',
                ))

        return findings

    def get_summary(self) -> Dict:
        """获取依赖检查摘要"""
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        packages_checked = set()

        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            packages_checked.add(f.package_name)

        return {
            'total_findings': len(self.findings),
            'by_severity': by_severity,
            'packages_with_vulns': list(packages_checked),
        }
