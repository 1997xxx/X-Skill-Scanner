#!/usr/bin/env python3
"""
安装钩子检测引擎 v1.0 — Install Hook Detection Engine
v3.3 新增：参考 SecureClaw / AegisScan 的安装行为分析能力

检测技能在安装/加载阶段可能执行的恶意操作：
- setup.py / pyproject.toml 中的 install hooks
- package.json 中的 postinstall/preinstall 脚本
- .bashrc/.zshrc 修改
- cron job 注入
- 环境变量篡改
- 文件系统持久化
"""

import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class InstallHookFinding:
    """安装钩子发现项"""
    rule_id: str
    title: str
    severity: str
    description: str
    file_path: str
    line_number: int
    hook_type: str
    category: str
    confidence: float = 0.85
    remediation: str = "需要人工审查"


# ─── 安装钩子文件模式 ──────────────────────────────────────────
HOOK_FILES = {
    'setup.py', 'setup.cfg', 'pyproject.toml',
    'package.json', 'Makefile', 'Dockerfile',
    '.bashrc', '.zshrc', '.profile', '.bash_profile',
    'install.sh', 'install.py', 'post_install.sh',
    'pre_install.sh', 'hooks.py',
}

# ─── 危险钩子模式 ──────────────────────────────────────────────
DANGEROUS_HOOK_PATTERNS = [
    # Python setup.py hooks
    (r'cmdclass\s*=\s*\{.*install.*:', 'PYTHON_INSTALL_HOOK', 'Python 安装命令覆盖'),
    (r'setup\(.*install_requires', 'PYTHON_DEPENDENCY_INJECTION', 'Python 依赖注入'),
    (r'atexit\.register', 'PYTHON_ATEXIT_HOOK', 'Python 退出钩子注册'),
    
    # Node.js hooks
    (r'"postinstall"\s*:\s*"', 'NODE_POSTINSTALL', 'Node.js postinstall 脚本'),
    (r'"preinstall"\s*:\s*"', 'NODE_PREINSTALL', 'Node.js preinstall 脚本'),
    (r'"prepare"\s*:\s*"', 'NODE_PREPARE', 'Node.js prepare 脚本'),
    
    # Shell persistence
    (r'echo.*>>.*\.(?:bashrc|zshrc|profile)', 'SHELL_RC_MODIFICATION', 'Shell 配置文件修改'),
    (r'crontab\s*-[el]', 'CRON_INJECTION', 'Cron 任务注入'),
    (r'launchctl\s+(?:load|start)', 'LAUNCHD_INJECTION', 'macOS Launchd 注入'),
    (r'systemctl\s+(?:enable|start)', 'SYSTEMD_INJECTION', 'Systemd 服务注入'),
    
    # Environment manipulation
    (r'export\s+.*(?:PATH|LD_PRELOAD|PYTHONPATH)', 'ENV_MANIPULATION', '环境变量操纵'),
    (r'setx\s+', 'WINDOWS_ENV_PERSISTENCE', 'Windows 环境变量持久化'),
    
    # File system operations during install
    (r'cp\s+-r\s+~/', 'HOME_DIR_COPY', '用户目录复制'),
    (r'find\s+~.*-name', 'HOME_DIR_SCAN', '用户目录扫描'),
    (r'tar\s+czf.*~', 'HOME_DIR_ARCHIVE', '用户目录打包'),
]


class InstallHookDetector:
    """
    安装钩子检测引擎
    
    检测维度:
    1. 安装脚本分析 (setup.py, package.json)
    2. Shell 配置文件修改检测
    3. 系统服务注入检测
    4. 环境变量篡改检测
    5. 文件系统持久化检测
    """

    def __init__(self):
        self.findings: List[InstallHookFinding] = []

    def analyze_directory(self, dir_path: Path, recursive: bool = True,
                           path_filter=None) -> List[InstallHookFinding]:
        """分析目录中的安装钩子"""
        from path_filter import PathFilter as PF
        pf = path_filter or PF()
        all_findings = []
        
        files = dir_path.rglob('*') if recursive else dir_path.glob('*')
        for fp in files:
            if not fp.is_file():
                continue
            
            # 检查是否是已知的钩子文件
            if fp.name.lower() in HOOK_FILES:
                findings = self._analyze_hook_file(fp)
                all_findings.extend(findings)
            
            # 检查所有文件中的危险钩子模式
            if fp.suffix.lower() in {'.py', '.js', '.sh', '.json', '.toml', '.yaml', '.yml'}:
                if not pf.should_ignore(fp, dir_path):
                    findings = self._scan_for_hook_patterns(fp)
                    all_findings.extend(findings)
        
        self.findings.extend(all_findings)
        return all_findings

    def _analyze_hook_file(self, file_path: Path) -> List[InstallHookFinding]:
        """分析特定的安装钩子文件"""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return findings
        
        lines = content.split('\n')
        filename = file_path.name.lower()
        
        # ─── setup.py 深度分析 ─────────────────────────────────
        if filename == 'setup.py':
            findings.extend(self._analyze_setup_py(content, file_path))
        
        # ─── package.json 深度分析 ─────────────────────────────
        elif filename == 'package.json':
            findings.extend(self._analyze_package_json(content, file_path))
        
        # ─── Shell 安装脚本 ────────────────────────────────────
        elif filename.endswith(('.sh',)):
            findings.extend(self._analyze_shell_script(content, file_path))
        
        # ─── pyproject.toml ────────────────────────────────────
        elif filename == 'pyproject.toml':
            findings.extend(self._analyze_pyproject_toml(content, file_path))
        
        return findings

    def _analyze_setup_py(self, content: str, file_path: Path) -> List[InstallHookFinding]:
        """深度分析 setup.py 文件"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # cmdclass 覆盖
            if 'cmdclass' in stripped and ('install' in stripped or 'build' in stripped):
                findings.append(InstallHookFinding(
                    rule_id='HOOK_001',
                    title='setup.py cmdclass 覆盖安装命令',
                    severity='HIGH',
                    description=(
                        f'检测到 setup.py 中覆盖了标准安装命令 (cmdclass)。\n'
                        f'这可能用于在安装过程中执行任意代码。\n\n'
                        f'可疑行 ({line_num}):\n```\n{stripped}\n```'
                    ),
                    file_path=str(file_path),
                    line_number=line_num,
                    hook_type='python_cmdclass_override',
                    category='install_hook',
                    confidence=0.9,
                    remediation='审查 cmdclass 定义，确认无恶意代码执行',
                ))
            
            # 自定义 install 类
            if re.search(r'class\s+\w+\(.*install\)', stripped, re.IGNORECASE):
                findings.append(InstallHookFinding(
                    rule_id='HOOK_002',
                    title='自定义 install 类定义',
                    severity='HIGH',
                    description=(
                        f'检测到自定义的 install 类，可能在安装时执行额外操作。\n\n'
                        f'可疑行 ({line_num}):\n```\n{stripped}\n```'
                    ),
                    file_path=str(file_path),
                    line_number=line_num,
                    hook_type='custom_install_class',
                    category='install_hook',
                    confidence=0.85,
                    remediation='审查自定义 install 类的 run() 方法',
                ))
            
            # entry_points console_scripts
            if 'entry_points' in stripped and 'console_scripts' in stripped:
                findings.append(InstallHookFinding(
                    rule_id='HOOK_003',
                    title='Console Scripts 入口点定义',
                    severity='MEDIUM',
                    description=(
                        f'定义了 console_scripts 入口点，安装时会创建可执行命令。\n\n'
                        f'可疑行 ({line_num}):\n```\n{stripped}\n```'
                    ),
                    file_path=str(file_path),
                    line_number=line_num,
                    hook_type='console_script_entry',
                    category='install_hook',
                    confidence=0.7,
                    remediation='审查入口点指向的函数',
                ))
        
        return findings

    def _analyze_package_json(self, content: str, file_path: Path) -> List[InstallHookFinding]:
        """深度分析 package.json 文件"""
        findings = []
        
        import json
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings
        
        scripts = data.get('scripts', {})
        
        dangerous_hooks = ['postinstall', 'preinstall', 'prepare', 'install']
        for hook_name in dangerous_hooks:
            if hook_name in scripts:
                script_content = scripts[hook_name]
                
                # 检查脚本内容是否包含危险操作
                danger_score = 0
                danger_indicators = []
                
                if any(cmd in script_content for cmd in ['curl', 'wget', 'fetch']):
                    danger_score += 2
                    danger_indicators.append('网络下载')
                
                if any(cmd in script_content for cmd in ['bash', 'sh', 'zsh', 'cmd']):
                    danger_score += 2
                    danger_indicators.append('Shell 执行')
                
                if any(cmd in script_content for cmd in ['eval', 'exec']):
                    danger_score += 3
                    danger_indicators.append('动态执行')
                
                if any(cmd in script_content for cmd in ['.env', 'secret', 'token', 'key']):
                    danger_score += 2
                    danger_indicators.append('凭证访问')
                
                if danger_score >= 3:
                    severity = 'CRITICAL' if danger_score >= 5 else 'HIGH'
                    findings.append(InstallHookFinding(
                        rule_id='HOOK_010',
                        title=f'危险的 {hook_name} 脚本 (风险分: {danger_score})',
                        severity=severity,
                        description=(
                            f'package.json 中的 "{hook_name}" 脚本包含危险操作。\n'
                            f'危险指标: {", ".join(danger_indicators)}\n\n'
                            f'脚本内容:\n```\n{script_content}\n```'
                        ),
                        file_path=str(file_path),
                        line_number=0,
                        hook_type=f'node_{hook_name}',
                        category='install_hook',
                        confidence=0.9,
                        remediation=f'移除或审查 {hook_name} 脚本中的危险操作',
                    ))
                elif danger_score > 0:
                    findings.append(InstallHookFinding(
                        rule_id='HOOK_011',
                        title=f'{hook_name} 脚本需要注意',
                        severity='MEDIUM',
                        description=(
                            f'package.json 中的 "{hook_name}" 脚本:\n```\n{script_content}\n```'
                        ),
                        file_path=str(file_path),
                        line_number=0,
                        hook_type=f'node_{hook_name}',
                        category='install_hook',
                        confidence=0.6,
                        remediation=f'审查 {hook_name} 脚本内容',
                    ))
        
        return findings

    def _analyze_shell_script(self, content: str, file_path: Path) -> List[InstallHookFinding]:
        """分析 Shell 安装脚本"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            
            for pattern, hook_type, desc in DANGEROUS_HOOK_PATTERNS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    findings.append(InstallHookFinding(
                        rule_id='HOOK_020',
                        title=desc,
                        severity='HIGH',
                        description=(
                            f'在 {file_path.name} 中检测到危险钩子模式。\n\n'
                            f'可疑行 ({line_num}):\n```\n{stripped}\n```'
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        hook_type=hook_type,
                        category='install_hook',
                        confidence=0.85,
                        remediation='审查该操作的意图，确认是否为恶意行为',
                    ))
                    break  # One finding per line
        
        return findings

    def _analyze_pyproject_toml(self, content: str, file_path: Path) -> List[InstallHookFinding]:
        """分析 pyproject.toml 文件"""
        findings = []
        
        # 检查 build-backend
        if re.search(r'build-backend\s*=', content):
            findings.append(InstallHookFinding(
                rule_id='HOOK_030',
                title='自定义构建后端',
                severity='MEDIUM',
                description='使用了自定义的 build-backend，可能在构建时执行代码。',
                file_path=str(file_path),
                line_number=0,
                hook_type='python_build_backend',
                category='install_hook',
                confidence=0.6,
                remediation='审查 build-backend 的实现',
            ))
        
        # 检查 [tool.setuptools.cmdclass]
        if '[tool.setuptools.cmdclass]' in content:
            findings.append(InstallHookFinding(
                rule_id='HOOK_031',
                title='pyproject.toml 中的 cmdclass 配置',
                severity='HIGH',
                description='在 pyproject.toml 中配置了自定义安装命令。',
                file_path=str(file_path),
                line_number=0,
                hook_type='pyproject_cmdclass',
                category='install_hook',
                confidence=0.8,
                remediation='审查 cmdclass 配置',
            ))
        
        return findings

    def _scan_for_hook_patterns(self, file_path: Path) -> List[InstallHookFinding]:
        """扫描文件中的危险钩子模式"""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return findings
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            for pattern, hook_type, desc in DANGEROUS_HOOK_PATTERNS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    findings.append(InstallHookFinding(
                        rule_id='HOOK_040',
                        title=desc,
                        severity='MEDIUM',
                        description=(
                            f'在 {file_path.name} 中检测到潜在的危险钩子模式。\n\n'
                            f'可疑行 ({line_num}):\n```\n{stripped}\n```'
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        hook_type=hook_type,
                        category='hook_pattern',
                        confidence=0.6,
                        remediation='确认该操作是否为预期的安装行为',
                    ))
                    break
        
        return findings

    def get_summary(self) -> Dict:
        """获取安装钩子检测统计摘要"""
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        by_hook_type = {}
        
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_hook_type[f.hook_type] = by_hook_type.get(f.hook_type, 0) + 1
        
        return {
            'total_findings': len(self.findings),
            'by_severity': by_severity,
            'by_hook_type': by_hook_type,
        }
