#!/usr/bin/env python3
"""
去混淆引擎 v1.0
Deobfuscation Engine

检测并还原以下混淆手法：
- Base64 / ROT13 / Hex 编码
- Unicode BiDi 覆盖攻击 (CVE-2021-42574)
- 零宽字符隐藏指令
- TR39 视觉混淆 (confusable characters)
- Zlib/Gzip 压缩 payload
- 字符串拼接混淆
"""

import re
import base64
import zlib
import codecs
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class ObfuscationFinding:
    """去混淆发现项"""
    technique: str           # 混淆技术名称
    severity: str            # CRITICAL/HIGH/MEDIUM/LOW
    description: str         # 描述
    file_path: str           # 文件路径
    line_number: int         # 行号
    original: str            # 原始混淆内容
    decoded: str             # 解码后内容
    confidence: float = 0.8  # 置信度


# ─── BiDi 危险字符 ──────────────────────────────────────────────
BIDI_DANGEROUS = {
    '\u202A',  # LEFT-TO-RIGHT EMBEDDING
    '\u202B',  # RIGHT-TO-LEFT EMBEDDING
    '\u202C',  # POP DIRECTIONAL FORMATTING
    '\u202D',  # LEFT-TO-RIGHT OVERRIDE
    '\u202E',  # RIGHT-TO-LEFT OVERRIDE (最危险)
    '\u2066',  # LEFT-TO-RIGHT ISOLATE
    '\u2067',  # RIGHT-TO-LEFT ISOLATE
    '\u2068',  # FIRST STRONG ISOLATE
    '\u2069',  # POP DIRECTIONAL ISOLATE
}

# ─── 零宽字符 ───────────────────────────────────────────────────
ZERO_WIDTH_CHARS = {
    '\u200B',  # ZERO WIDTH SPACE
    '\u200C',  # ZERO WIDTH NON-JOINER
    '\u200D',  # ZERO WIDTH JOINER
    '\uFEFF',  # ZERO WIDTH NO-BREAK SPACE (BOM)
    '\u2060',  # WORD JOINER
    '\u180E',  # MONGOLIAN VOWEL SEPARATOR
}

# ─── TR39 Confusables 映射（常见） ──────────────────────────────
CONFUSABLES = {
    'а': 'a',   # Cyrillic а → Latin a
    'е': 'e',   # Cyrillic е → Latin e
    'о': 'o',   # Cyrillic о → Latin o
    'р': 'p',   # Cyrillic р → Latin p
    'с': 'c',   # Cyrillic с → Latin c
    'х': 'x',   # Cyrillic х → Latin x
    'у': 'y',   # Cyrillic у → Latin y
    'А': 'A',
    'В': 'B',
    'Е': 'E',
    'К': 'K',
    'М': 'M',
    'Н': 'H',
    'О': 'O',
    'Р': 'P',
    'С': 'C',
    'Т': 'T',
    'Χ': 'X',
}


class Deobfuscator:
    """去混淆引擎"""

    def __init__(self):
        self.findings: List[ObfuscationFinding] = []

    def analyze_file(self, file_path: Path) -> List[ObfuscationFinding]:
        """分析单个文件的混淆情况"""
        findings = []
        
        # v3.6: 跳过 package-lock.json / yarn.lock — integrity hash 是正常包校验哈希
        # 参考 SmartChainArk skill-security-audit 误报调优经验
        filename = file_path.name.lower()
        if filename in ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'):
            return findings
        
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            return findings

        lines = content.split('\n')

        # v5.1: Pre-pass — detect and reconstruct multi-line obfuscated payloads
        findings.extend(self._check_multi_line_hex_array(content, str(file_path)))
        findings.extend(self._check_base64_bytes_literal(content, str(file_path)))
        findings.extend(self._check_string_concat_assembly(content, str(file_path)))

        for line_num, line in enumerate(lines, 1):
            findings.extend(self._check_bidi(line, str(file_path), line_num))
            findings.extend(self._check_zero_width(line, str(file_path), line_num))
            findings.extend(self._check_confusables(line, str(file_path), line_num))
            findings.extend(self._check_base64(line, str(file_path), line_num))
            findings.extend(self._check_hex_encoding(line, str(file_path), line_num))
            findings.extend(self._check_rot13(line, str(file_path), line_num))
            findings.extend(self._check_zlib_payload(line, str(file_path), line_num))
            findings.extend(self._check_string_concat(line, str(file_path), line_num))

        self.findings.extend(findings)
        return findings

    def analyze_directory(self, dir_path: Path, recursive: bool = True,
                           path_filter=None) -> List[ObfuscationFinding]:
        """分析目录"""
        from path_filter import PathFilter as PF
        pf = path_filter or PF()
        all_findings = []
        # v3.1: 扩展至 .md/.json — 恶意技能常在文档中隐藏编码 payload
        extensions = {'.py', '.js', '.ts', '.sh', '.md', '.yaml', '.yml', '.json'}

        files = dir_path.rglob('*') if recursive else dir_path.glob('*')
        for fp in files:
            if not fp.is_file():
                continue
            if fp.suffix.lower() not in extensions:
                continue
            if pf.should_ignore(fp, dir_path):
                continue
            all_findings.extend(self.analyze_file(fp))

        return all_findings

    # ─── BiDi 覆盖检测 ──────────────────────────────────────────
    def _check_bidi(self, line: str, file_path: str, line_num: int) -> List[ObfuscationFinding]:
        """检测 Unicode BiDi 覆盖攻击"""
        findings = []
        bidi_chars = [c for c in line if c in BIDI_DANGEROUS]
        if bidi_chars:
            # 显示 BiDi 字符的 Unicode 码位
            char_info = ', '.join(f'U+{ord(c):04X}' for c in bidi_chars)
            findings.append(ObfuscationFinding(
                technique='bidi_override',
                severity='CRITICAL',
                description=f'检测到 BiDi 覆盖字符 ({char_info})，可能用于隐藏恶意代码',
                file_path=file_path,
                line_number=line_num,
                original=repr(line[:200]),
                decoded=self._strip_bidi(line),
                confidence=0.95
            ))
        return findings

    def _strip_bidi(self, text: str) -> str:
        """移除 BiDi 控制字符"""
        return ''.join(c for c in text if c not in BIDI_DANGEROUS)

    # ─── 零宽字符检测 ───────────────────────────────────────────
    def _check_zero_width(self, line: str, file_path: str, line_num: int) -> List[ObfuscationFinding]:
        """检测零宽字符隐藏指令"""
        findings = []
        zw_chars = [c for c in line if c in ZERO_WIDTH_CHARS]
        if zw_chars:
            char_info = ', '.join(f'U+{ord(c):04X}' for c in zw_chars)
            findings.append(ObfuscationFinding(
                technique='zero_width_hidden',
                severity='HIGH',
                description=f'检测到零宽字符 ({char_info})，可能用于隐藏数据或指令',
                file_path=file_path,
                line_number=line_num,
                original=repr(line[:200]),
                decoded=''.join(c for c in line if c not in ZERO_WIDTH_CHARS),
                confidence=0.85
            ))
        return findings

    # ─── TR39 Confusables 检测 ──────────────────────────────────
    def _check_confusables(self, line: str, file_path: str, line_num: int) -> List[ObfuscationFinding]:
        """检测 TR39 视觉混淆字符"""
        findings = []
        confusable_chars = [(i, c) for i, c in enumerate(line) if c in CONFUSABLES]
        if confusable_chars:
            details = ', '.join(
                f"'{c}'(U+{ord(c):04X})→'{CONFUSABLES[c]}'" for _, c in confusable_chars
            )
            normalized = ''.join(CONFUSABLES.get(c, c) for c in line)
            findings.append(ObfuscationFinding(
                technique='tr39_confusables',
                severity='HIGH',
                description=f'检测到视觉混淆字符: {details}',
                file_path=file_path,
                line_number=line_num,
                original=repr(line[:200]),
                decoded=normalized,
                confidence=0.9
            ))
        return findings

    # ─── Base64 解码 ────────────────────────────────────────────
    def _check_base64(self, line: str, file_path: str, line_num: int) -> List[ObfuscationFinding]:
        """检测 Base64 编码的潜在恶意内容"""
        findings = []

        # 匹配常见的 Base64 模式
        b64_patterns = [
            # Python: base64.b64decode("...")
            r'base64\.(?:b64)?decode\s*\(\s*["\']([A-Za-z0-9+/=]{16,})["\']',
            # JS: atob("...")
            r'\batob\s*\(\s*["\']([A-Za-z0-9+/=]{16,})["\']',
            # Shell: echo "..." | base64 -d
            r'(?:echo|printf)\s+["\']([A-Za-z0-9+/=]{16,})["\']\s*\|\s*base64\s+-(?:d|D|--decode)',
            # 裸 Base64 字符串赋值
            r'(?:payload|code|cmd|script|data)\s*[=:]\s*["\']([A-Za-z0-9+/=]{32,})["\']',
        ]

        for pattern in b64_patterns:
            match = re.search(pattern, line)
            if match:
                encoded = match.group(1)
                try:
                    decoded = base64.b64decode(encoded).decode('utf-8', errors='replace')
                    # 只报告解码后有意义的结果
                    if len(decoded.strip()) > 5 and any(c.isalpha() for c in decoded):
                        # 构建详细的描述，包含解码前后对比
                        desc_lines = [
                            f'检测到 Base64 编码内容，已自动解码。',
                            f'',
                            f'📋 编码内容 (前100字符): {encoded[:100]}',
                            f'',
                            f'🔓 解码结果:',
                            f'```',
                            f'{decoded[:500]}',
                            f'```',
                        ]
                        # 如果解码结果包含危险命令，添加警告
                        danger_keywords = ['curl', 'wget', 'bash', 'sh', 'zsh', 'eval', 'exec',
                                           'python', 'ruby', 'perl', 'powershell', 'cmd.exe']
                        found_dangers = [kw for kw in danger_keywords if kw.lower() in decoded.lower()]
                        if found_dangers:
                            desc_lines.extend([
                                f'',
                                f'⚠️  解码结果包含危险命令关键词: {", ".join(found_dangers)}',
                            ])
                        
                        findings.append(ObfuscationFinding(
                            technique='base64_encoded',
                            severity='HIGH',
                            description='\n'.join(desc_lines),
                            file_path=file_path,
                            line_number=line_num,
                            original=encoded[:100],
                            decoded=decoded[:500],
                            confidence=0.8
                        ))
                except Exception:
                    pass
        return findings

    # ─── Hex 编码检测 ───────────────────────────────────────────
    def _check_hex_encoding(self, line: str, file_path: str, line_num: int) -> List[ObfuscationFinding]:
        """检测十六进制编码的 payload"""
        findings = []

        hex_patterns = [
            r'(?:\\x[0-9a-fA-F]{2}){8,}',     # \x48\x65\x6c\x6c\x6f...
            r'(?:%[0-9a-fA-F]{2}){8,}',        # %48%65%6c%6c%6f...
            r'(?:0x[0-9a-fA-F]{2},?\s*){8,}',  # 0x48, 0x65, 0x6c...
        ]

        for pattern in hex_patterns:
            match = re.search(pattern, line)
            if match:
                encoded = match.group(0)
                try:
                    # 尝试 \x 格式
                    if '\\x' in encoded:
                        decoded = encoded.encode().decode('unicode_escape')
                    elif '%' in encoded:
                        from urllib.parse import unquote
                        decoded = unquote(encoded)
                    else:
                        hex_bytes = re.findall(r'0x([0-9a-fA-F]{2})', encoded)
                        decoded = bytes(int(b, 16) for b in hex_bytes).decode('utf-8', errors='replace')

                    if len(decoded.strip()) > 5:
                        findings.append(ObfuscationFinding(
                            technique='hex_encoded',
                            severity='MEDIUM',
                            description='检测到十六进制编码内容',
                            file_path=file_path,
                            line_number=line_num,
                            original=encoded[:100],
                            decoded=decoded[:500],
                            confidence=0.7
                        ))
                except Exception:
                    pass
        return findings

    # ─── ROT13 检测 ─────────────────────────────────────────────
    def _check_rot13(self, line: str, file_path: str, line_num: int) -> List[ObfuscationFinding]:
        """检测 ROT13 编码"""
        findings = []

        rot_patterns = [
            r'codecs\.decode\s*\(\s*["\']([^"\']{10,})["\'].*rot.?13',
            r'rot13\s*\(\s*["\']([^"\']{10,})["\']',
        ]

        for pattern in rot_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                encoded = match.group(1)
                decoded = codecs.decode(encoded, 'rot_13')
                findings.append(ObfuscationFinding(
                    technique='rot13_encoded',
                    severity='MEDIUM',
                    description='检测到 ROT13 编码内容',
                    file_path=file_path,
                    line_number=line_num,
                    original=encoded[:100],
                    decoded=decoded[:500],
                    confidence=0.85
                ))
        return findings

    # ─── Zlib 压缩检测 ──────────────────────────────────────────
    def _check_zlib_payload(self, line: str, file_path: str, line_num: int) -> List[ObfuscationFinding]:
        """检测 zlib/gzip 压缩的 payload"""
        findings = []

        zlib_patterns = [
            r'zlib\.decompress\s*\(',
            r'gzip\.decompress\s*\(',
            r'import\s+zlib.*decompress',
        ]

        for pattern in zlib_patterns:
            if re.search(pattern, line):
                findings.append(ObfuscationFinding(
                    technique='zlib_compressed',
                    severity='HIGH',
                    description='检测到 zlib/gzip 解压缩操作，可能用于隐藏 payload',
                    file_path=file_path,
                    line_number=line_num,
                    original=line.strip()[:200],
                    decoded='需要运行时动态分析',
                    confidence=0.75
                ))
        return findings

    # ─── 字符串拼接混淆 ─────────────────────────────────────────
    def _check_string_concat(self, line: str, file_path: str, line_num: int) -> List[ObfuscationFinding]:
        """检测通过字符串拼接构建敏感函数名"""
        findings = []

        # 检测类似: getattr(module, "ev" + "al") 的模式
        concat_patterns = [
            # getattr(obj, "part1" + "part2")
            r'getattr\s*\([^,]+,\s*["\'][a-z]+["\']\s*\+\s*["\'][a-z]+["\']',
            # __import__("os") via concat
            r'__import__\s*\(\s*["\'][a-z]+["\']\s*\+\s*["\'][a-z]+["\']',
            # exec("part" + "part")
            r'(?:exec|eval)\s*\(\s*["\'][^"\']+["\']\s*\+',
            # chr() chain: chr(101)+chr(118)+chr(97)+chr(108)
            r'(?:chr\s*\(\s*\d+\s*\)\s*\+\s*){3,}',
        ]

        for pattern in concat_patterns:
            if re.search(pattern, line):
                findings.append(ObfuscationFinding(
                    technique='string_concat_obfuscation',
                    severity='HIGH',
                    description='检测到字符串拼接构建敏感标识符，可能用于绕过静态检测',
                    file_path=file_path,
                    line_number=line_num,
                    original=line.strip()[:200],
                    decoded='需要人工审查拼接结果',
                    confidence=0.8
                ))
        return findings

    def get_summary(self) -> Dict:
        """获取去混淆统计摘要"""
        by_technique = {}
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for f in self.findings:
            by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        return {
            'total_findings': len(self.findings),
            'by_technique': by_technique,
            'by_severity': by_severity,
        }

    # ─── v5.1: Multi-line Hex Array Reconstruction ──────────────
    def _check_multi_line_hex_array(self, content: str, file_path: str) -> List[ObfuscationFinding]:
        """检测并重组跨行的十六进制字节数组
        
        匹配模式: var = [0xNN, 0xNN, ...] （可能跨多行）
        """
        findings = []
        
        # Match Python-style hex array assignments (multi-line)
        pattern = r'(\w+)\s*=\s*\[\s*((?:0x[0-9a-fA-F]{2}\s*,?\s*)+)\]'
        
        for match in re.finditer(pattern, content, re.DOTALL):
            var_name = match.group(1)
            hex_str = match.group(2)
            
            # Extract all hex bytes
            hex_bytes = re.findall(r'0x([0-9a-fA-F]{2})', hex_str)
            if len(hex_bytes) < 8:
                continue
            
            try:
                raw = bytes(int(b, 16) for b in hex_bytes)
                # Strip null bytes (common obfuscation technique)
                decoded = raw.replace(b'\x00', b'').decode('utf-8', errors='replace')
                
                if len(decoded.strip()) > 10 and any(c.isalpha() for c in decoded):
                    danger_keywords = ['curl', 'wget', 'bash', 'sh', 'zsh', 'eval', 'exec',
                                       'python', 'ruby', 'perl', 'powershell', 'cmd.exe',
                                       'ransomware', 'malware', 'payload']
                    found_dangers = [kw for kw in danger_keywords if kw.lower() in decoded.lower()]
                    
                    desc_lines = [
                        f'检测到跨行十六进制字节数组，已重组并解码。',
                        f'',
                        f'📋 变量名: {var_name}',
                        f'📋 字节数: {len(hex_bytes)}',
                        f'',
                        f'🔓 解码结果 (去除空字节后):',
                        f'```',
                        f'{decoded[:800]}',
                        f'```',
                    ]
                    if found_dangers:
                        desc_lines.extend([
                            f'',
                            f'⚠️  解码结果包含危险关键词: {", ".join(found_dangers)}',
                        ])
                    
                    findings.append(ObfuscationFinding(
                        technique='hex_array_reconstructed',
                        severity='CRITICAL' if found_dangers else 'HIGH',
                        description='\n'.join(desc_lines),
                        file_path=file_path,
                        line_number=content[:match.start()].count('\n') + 1,
                        original=f'{var_name} = [{hex_str.strip()[:100]}...]',
                        decoded=decoded[:800],
                        confidence=0.95
                    ))
            except Exception:
                pass
        
        return findings

    # ─── v5.1: Base64 Bytes Literal Detection ───────────────────
    def _check_base64_bytes_literal(self, content: str, file_path: str) -> List[ObfuscationFinding]:
        """检测 Python bytes 字面量中的 Base64 编码内容
        
        匹配模式: var = b'Base64String...'
        """
        findings = []
        
        # Match b'...' or b"..." with base64-like content (32+ chars)
        pattern = r'(\w+)\s*=\s*b["\']([A-Za-z0-9+/=]{32,})["\']'
        
        for match in re.finditer(pattern, content):
            var_name = match.group(1)
            b64_str = match.group(2)
            
            try:
                import base64 as b64
                decoded = b64.b64decode(b64_str).decode('utf-8', errors='replace')
                
                if len(decoded.strip()) > 10 and any(c.isalpha() for c in decoded):
                    danger_keywords = ['curl', 'wget', 'bash', 'sh', 'zsh', 'eval', 'exec',
                                       'python', 'ruby', 'perl', 'powershell', 'cmd.exe',
                                       'ransomware', 'malware', 'payload']
                    found_dangers = [kw for kw in danger_keywords if kw.lower() in decoded.lower()]
                    
                    desc_lines = [
                        f'检测到 bytes 字面量中的 Base64 编码内容，已解码。',
                        f'',
                        f'📋 变量名: {var_name}',
                        f'',
                        f'🔓 解码结果:',
                        f'```',
                        f'{decoded[:800]}',
                        f'```',
                    ]
                    if found_dangers:
                        desc_lines.extend([
                            f'',
                            f'⚠️  解码结果包含危险关键词: {", ".join(found_dangers)}',
                        ])
                    
                    findings.append(ObfuscationFinding(
                        technique='base64_bytes_literal',
                        severity='CRITICAL' if found_dangers else 'HIGH',
                        description='\n'.join(desc_lines),
                        file_path=file_path,
                        line_number=content[:match.start()].count('\n') + 1,
                        original=b64_str[:100],
                        decoded=decoded[:800],
                        confidence=0.95
                    ))
            except Exception:
                pass
        
        return findings

    # ─── v5.1: String Concat Assembly ───────────────────────────
    def _check_string_concat_assembly(self, content: str, file_path: str) -> List[ObfuscationFinding]:
        """检测通过多个变量拼接构建的 Base64 字符串
        
        匹配模式: _part1_ = "xxx"; _part2_ = "yyy"; ... → 重组后解码
        """
        findings = []
        
        # Find part variables that look like base64 fragments
        part_pattern = r'(_?(?:part|chunk|seg)\w*_?)\s*=\s*["\']([A-Za-z0-9+/=]+)["\']'
        parts = {}
        for m in re.finditer(part_pattern, content):
            parts[m.group(1)] = m.group(2)
        
        if len(parts) < 3:
            return findings
        
        # Look for concatenation expressions that reference these parts
        concat_patterns = [
            r'(?:' + '|'.join(re.escape(k) for k in parts.keys()) + r'\s*\+\s*){2,}',
        ]
        
        for cp in concat_patterns:
            for m in re.finditer(cp, content):
                expr = m.group(0)
                # Extract part names from expression
                part_names = re.findall(r'(_?(?:part|chunk|seg)\w*_?)', expr)
                assembled = ''.join(parts.get(p, '') for p in part_names if p in parts)
                
                if len(assembled) < 32:
                    continue
                
                try:
                    import base64 as b64
                    decoded = b64.b64decode(assembled).decode('utf-8', errors='replace')
                    
                    if len(decoded.strip()) > 10 and any(c.isalpha() for c in decoded):
                        danger_keywords = ['curl', 'wget', 'bash', 'sh', 'zsh', 'eval', 'exec',
                                           'ransomware', 'malware', 'payload']
                        found_dangers = [kw for kw in danger_keywords if kw.lower() in decoded.lower()]
                        
                        desc_lines = [
                            f'检测到字符串拼接构建的 Base64 内容，已重组并解码。',
                            f'',
                            f'📋 拼接表达式: {expr[:200]}',
                            f'📋 重组后长度: {len(assembled)} chars',
                            f'',
                            f'🔓 解码结果:',
                            f'```',
                            f'{decoded[:800]}',
                            f'```',
                        ]
                        if found_dangers:
                            desc_lines.extend([
                                f'',
                                f'⚠️  解码结果包含危险关键词: {", ".join(found_dangers)}',
                            ])
                        
                        findings.append(ObfuscationFinding(
                            technique='string_concat_assembly',
                            severity='CRITICAL' if found_dangers else 'HIGH',
                            description='\n'.join(desc_lines),
                            file_path=file_path,
                            line_number=content[:m.start()].count('\n') + 1,
                            original=expr[:200],
                            decoded=decoded[:800],
                            confidence=0.9
                        ))
                except Exception:
                    pass
        
        return findings
