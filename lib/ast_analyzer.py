#!/usr/bin/env python3
"""
AST 分析引擎 v1.0
AST Analysis Engine

在抽象语法树层面检测恶意代码，比正则更精准、更难绕过：
- 间接执行检测: getattr(__builtins__, ...), importlib.import_module(...)
- 数据流追踪 (Taint Analysis): 用户输入 → eval/exec
- 动态模块加载检测
- 异常控制流混淆
- AST 级别的代码变形检测
"""

import ast
from pathlib import Path
from typing import Dict, List, Set
from dataclasses import dataclass


@dataclass
class ASTFinding:
    """AST 分析发现项"""
    rule_id: str
    title: str
    severity: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    category: str
    confidence: float = 0.9
    remediation: str = "需要人工审查"


# ─── 危险内置函数 ──────────────────────────────────────────────
DANGEROUS_BUILTINS = {
    'eval', 'exec', 'compile', '__import__', 'open',
    'input', 'breakpoint',
}

# ─── 危险模块 ──────────────────────────────────────────────────
DANGEROUS_MODULES = {
    'os', 'sys', 'subprocess', 'shutil', 'ctypes',
    'socket', 'http', 'urllib', 'requests',
    'pickle', 'marshal', 'shelve',
    'importlib', 'pkgutil', 'zipimport',
    'code', 'codeop', 'runpy',
    'pty', 'popen2', 'commands',
}

# ─── 敏感路径前缀 ──────────────────────────────────────────────
SENSITIVE_PATHS = [
    '/etc/shadow', '/etc/passwd',
    '~/.ssh/', '~/.aws/', '~/.config/',
    '~/.bashrc', '~/.zshrc', '~/.profile',
]


class TaintTracker:
    """简易数据流追踪器"""

    def __init__(self):
        self.tainted_vars: Set[str] = set()

    def mark_tainted(self, var_name: str):
        self.tainted_vars.add(var_name)

    def is_tainted(self, node) -> bool:
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return True
        if isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name) and base.id in self.tainted_vars:
                return True
        return False


class ASTAnalyzer:
    """AST 分析引擎"""

    def __init__(self):
        self.findings: List[ASTFinding] = []

    def analyze_file(self, file_path: Path) -> List[ASTFinding]:
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            return []
        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError:
            return []

        visitor = _ASTVisitor(str(file_path), content)
        visitor.visit(tree)
        self.findings.extend(visitor.findings)
        return visitor.findings

    def analyze_directory(self, dir_path: Path, recursive: bool = True,
                           path_filter=None) -> List[ASTFinding]:
        from path_filter import PathFilter as PF
        pf = path_filter or PF()
        all_findings = []
        files = dir_path.rglob('*.py') if recursive else dir_path.glob('*.py')
        for fp in files:
            if fp.name.startswith('.'):
                continue
            if pf.should_ignore(fp, dir_path):
                continue
            all_findings.extend(self.analyze_file(fp))
        return all_findings


class _ASTVisitor(ast.NodeVisitor):
    """AST 遍历器 - 核心检测逻辑"""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source_lines = source.split('\n')
        self.findings: List[ASTFinding] = []
        self.imports: Dict[str, str] = {}
        self._taint_tracker = TaintTracker()

    def _get_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ''

    def _add_finding(self, rule_id, title, severity, description,
                     line_number, category, confidence=0.9,
                     remediation="需要人工审查"):
        self.findings.append(ASTFinding(
            rule_id=rule_id, title=title, severity=severity,
            description=description, file_path=self.file_path,
            line_number=line_number, code_snippet=self._get_line(line_number),
            category=category, confidence=confidence, remediation=remediation,
        ))

    def _resolve_attr_chain(self, node) -> str:
        """解析属性链: a.b.c → "a.b.c" """
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return '.'.join(reversed(parts))

    # ─── Import 收集 ────────────────────────────────────────────
    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
            if alias.name in DANGEROUS_MODULES:
                self._add_finding(
                    rule_id='AST_001',
                    title=f'导入危险模块: {alias.name}',
                    severity='MEDIUM',
                    description=f'导入了潜在危险模块 {alias.name}',
                    line_number=node.lineno,
                    category='dangerous_import',
                    confidence=0.7,
                    remediation='确认该模块的使用是否必要，限制其功能范围',
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            for alias in node.names:
                name = alias.asname or alias.name
                self.imports[name] = f'{node.module}.{alias.name}'
            if node.module in DANGEROUS_MODULES:
                dangerous_names = {a.name for a in node.names} & DANGEROUS_BUILTINS
                if dangerous_names:
                    self._add_finding(
                        rule_id='AST_002',
                        title=f'从危险模块导入危险函数: {node.module}',
                        severity='HIGH',
                        description=f'从 {node.module} 导入了 {", ".join(dangerous_names)}',
                        line_number=node.lineno,
                        category='dangerous_import',
                        confidence=0.85,
                        remediation='避免直接导入危险函数，使用安全替代方案',
                    )
        self.generic_visit(node)

    # ─── Call 检测 ──────────────────────────────────────────────
    def visit_Call(self, node):
        func = node.func

        # --- getattr(__builtins__, "eval") ---
        if isinstance(func, ast.Name) and func.id == 'getattr':
            if len(node.args) >= 2:
                arg0, arg1 = node.args[0], node.args[1]
                is_builtins = False
                if isinstance(arg0, ast.Name) and arg0.id == '__builtins__':
                    is_builtins = True
                elif isinstance(arg0, ast.Attribute) and arg0.attr == '__builtins__':
                    is_builtins = True

                if is_builtins and isinstance(arg1, ast.Constant) and isinstance(arg1.value, str):
                    method = arg1.value
                    if method in DANGEROUS_BUILTINS:
                        self._add_finding(
                            rule_id='AST_010',
                            title=f'通过 getattr 间接调用危险内置函数: {method}',
                            severity='CRITICAL',
                            description=f'使用 getattr(__builtins__, "{method}") 绕过静态检测',
                            line_number=node.lineno,
                            category='indirect_execution',
                            confidence=0.95,
                            remediation='禁止使用 getattr 访问 __builtins__ 中的危险函数',
                        )

        # --- importlib.import_module(...) ---
        if isinstance(func, ast.Attribute) and func.attr == 'import_module':
            base_name = ''
            if isinstance(func.value, ast.Name):
                base_name = func.value.id
            elif isinstance(func.value, ast.Attribute):
                base_name = func.value.attr

            if base_name == 'importlib' or self.imports.get(base_name, '').startswith('importlib'):
                if node.args and isinstance(node.args[0], ast.Constant):
                    mod = node.args[0].value
                    self._add_finding(
                        rule_id='AST_011',
                        title=f'动态模块加载: {mod}',
                        severity='HIGH',
                        description=f'使用 importlib.import_module("{mod}") 动态加载模块',
                        line_number=node.lineno,
                        category='dynamic_import',
                        confidence=0.8,
                        remediation='避免动态模块加载，使用显式 import',
                    )
                elif node.args:
                    self._add_finding(
                        rule_id='AST_012',
                        title='动态模块加载（变量名）',
                        severity='CRITICAL',
                        description='使用变量作为 import_module 参数，可能加载任意模块',
                        line_number=node.lineno,
                        category='dynamic_import',
                        confidence=0.9,
                        remediation='禁止使用变量作为模块名进行动态加载',
                    )

        # --- eval()/exec()/compile() ---
        if isinstance(func, ast.Name) and func.id in ('eval', 'exec', 'compile'):
            sev = 'CRITICAL' if func.id in ('eval', 'exec') else 'HIGH'
            self._add_finding(
                rule_id='AST_020',
                title=f'直接调用危险函数: {func.id}()',
                severity=sev,
                description=f'检测到 {func.id}() 调用，可执行任意代码',
                line_number=node.lineno,
                category='code_execution',
                confidence=0.95,
                remediation=f'避免使用 {func.id}()，使用安全的替代方案',
            )
            if node.args and self._taint_tracker.is_tainted(node.args[0]):
                self._add_finding(
                    rule_id='AST_021',
                    title=f'{func.id}() 使用了外部输入（数据流追踪）',
                    severity='CRITICAL',
                    description=f'{func.id}() 的参数来自不可信输入，存在代码注入风险',
                    line_number=node.lineno,
                    category='taint_flow',
                    confidence=0.95,
                    remediation='对输入进行严格验证和沙箱化',
                )

        # --- os.system / subprocess.* ---
        if isinstance(func, ast.Attribute):
            full_name = self._resolve_attr_chain(func)
            dangerous_calls = {
                'os.system': ('HIGH', '系统命令执行'),
                'os.popen': ('HIGH', '管道命令执行'),
                'subprocess.run': ('HIGH', '子进程执行'),
                'subprocess.call': ('HIGH', '子进程调用'),
                'subprocess.Popen': ('HIGH', '子进程创建'),
                'subprocess.check_output': ('HIGH', '子进程输出捕获'),
                'ctypes.CDLL': ('HIGH', 'C 库加载'),
                'ctypes.cdll.LoadLibrary': ('HIGH', '动态库加载'),
            }
            if full_name in dangerous_calls:
                sev, desc = dangerous_calls[full_name]
                self._add_finding(
                    rule_id='AST_030',
                    title=f'{desc}: {full_name}()',
                    severity=sev,
                    description=f'检测到 {full_name}() 调用',
                    line_number=node.lineno,
                    category='system_command',
                    confidence=0.9,
                    remediation='限制命令执行，使用白名单或沙箱',
                )
                for kw in node.keywords:
                    if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self._add_finding(
                            rule_id='AST_031',
                            title='subprocess 使用 shell=True',
                            severity='HIGH',
                            description='shell=True 允许 Shell 注入攻击',
                            line_number=node.lineno,
                            category='shell_injection',
                            confidence=0.95,
                            remediation='避免使用 shell=True，使用列表形式的命令参数',
                        )

        # --- open() 访问敏感路径 ---
        if isinstance(func, ast.Name) and func.id == 'open':
            if node.args and isinstance(node.args[0], ast.Constant):
                path = str(node.args[0].value)
                for sensitive in SENSITIVE_PATHS:
                    if sensitive.rstrip('/') in path:
                        self._add_finding(
                            rule_id='AST_040',
                            title=f'访问敏感文件: {path}',
                            severity='HIGH',
                            description=f'尝试打开敏感路径 {path}',
                            line_number=node.lineno,
                            category='sensitive_file_access',
                            confidence=0.85,
                            remediation='禁止访问敏感系统文件',
                        )
                        break

        # --- pickle.loads / marshal.loads ---
        if isinstance(func, ast.Attribute) and func.attr == 'loads':
            base = self._resolve_attr_chain(func)
            if base in ('pickle.loads', 'marshal.loads', 'shelve.open'):
                self._add_finding(
                    rule_id='AST_050',
                    title=f'不安全的反序列化: {base}()',
                    severity='CRITICAL',
                    description=f'{base}() 可执行任意代码，存在反序列化攻击风险',
                    line_number=node.lineno,
                    category='deserialization',
                    confidence=0.95,
                    remediation='使用 json 等安全格式替代 pickle/marshal',
                )

        self.generic_visit(node)

    # ─── 赋值 — taint 追踪 ──────────────────────────────────────
    def visit_Assign(self, node):
        if node.value and isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Name) and call.func.id == 'input':
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._taint_tracker.mark_tainted(target.id)
            if isinstance(call.func, ast.Attribute):
                base = self._resolve_attr_chain(call.func)
                if base in ('os.environ.get', 'os.getenv', 'sys.argv'):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self._taint_tracker.mark_tainted(target.id)
        self.generic_visit(node)

    # ─── bare except 滥用 ───────────────────────────────────────
    def visit_Try(self, node):
        for handler in node.handlers:
            if handler.type is None:
                body_str = ast.dump(node)
                suspicious = any(
                    kw in body_str.lower()
                    for kw in ['pass', 'open(', 'write(', 'send(', 'post(']
                )
                if suspicious:
                    self._add_finding(
                        rule_id='AST_060',
                        title='bare except 吞没异常并包含可疑操作',
                        severity='MEDIUM',
                        description='使用 bare except 且内部有可疑操作，可能用于隐藏恶意行为',
                        line_number=node.lineno,
                        category='exception_abuse',
                        confidence=0.7,
                        remediation='使用具体的异常类型，避免 bare except',
                    )
        self.generic_visit(node)

    # ─── Lambda 中的危险操作 ────────────────────────────────────
    def visit_Lambda(self, node):
        body_str = ast.dump(node.body)
        if any(fn in body_str for fn in ['eval', 'exec', '__import__', 'getattr']):
            self._add_finding(
                rule_id='AST_070',
                title='Lambda 中包含危险操作',
                severity='HIGH',
                description='在 lambda 表达式中使用危险函数，通常用于代码混淆',
                line_number=node.lineno,
                category='code_obfuscation',
                confidence=0.85,
                remediation='避免在 lambda 中使用危险函数',
            )
        self.generic_visit(node)

    # ─── exec 编译对象 ──────────────────────────────────────────
    def visit_Expr(self, node):
        """检测 standalone expression 中的危险调用"""
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name):
                if node.value.func.id == 'compile':
                    self._add_finding(
                        rule_id='AST_080',
                        title='动态编译代码对象',
                        severity='HIGH',
                        description='使用 compile() 动态创建代码对象',
                        line_number=node.lineno,
                        category='code_execution',
                        confidence=0.8,
                        remediation='避免动态编译代码',
                    )
        self.generic_visit(node)
