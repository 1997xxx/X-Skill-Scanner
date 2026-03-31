#!/usr/bin/env python3
"""
熵值分析引擎 v1.0 — Shannon Entropy Analysis Engine
v3.3 新增：参考 ClawGuard Auditor / SecureClaw 的熵值检测能力

通过计算文件/代码块的 Shannon 熵值，识别：
- 高熵区域 → 可能是加密/压缩/编码的 payload
- 异常熵分布 → 混淆代码的特征
- 嵌入的二进制数据 → 隐藏的恶意载荷

Shannon Entropy 范围: 0 (完全有序) ~ 8 (完全随机，二进制数据)
- 正常英文文本: ~4.0-4.5
- Python 代码: ~4.2-4.8
- Base64 编码: ~5.5-6.0
- 加密/压缩数据: >7.0
"""

import math
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from collections import Counter


@dataclass
class EntropyFinding:
    """熵值分析发现项"""
    rule_id: str
    title: str
    severity: str
    description: str
    file_path: str
    line_number: int
    entropy_score: float
    threshold: float
    category: str
    confidence: float = 0.8
    remediation: str = "需要人工审查"


# ─── 熵值阈值配置 ──────────────────────────────────────────────
# v3.6: CJK 自适应阈值 — 中文字符 Unicode 码点分布广，天然高熵
# 参考: SmartChainArk skill-security-audit 误报调优经验
ENTROPY_THRESHOLDS = {
    'CRITICAL': 7.0,   # 极高熵 — 几乎肯定是加密/压缩数据
    'HIGH': 6.0,       # 高熵 — 可能是 base64/hex 编码的 payload
    'MEDIUM': 5.5,     # 中等偏高 — 可疑编码内容
}

# CJK 字符范围（中日韩统一表意文字 + 扩展）
CJK_RANGES = [
    (0x4E00, 0x9FFF),   # CJK Unified Ideographs
    (0x3400, 0x4DBF),   # CJK Unified Ideographs Extension A
    (0x20000, 0x2A6DF), # CJK Unified Ideographs Extension B
    (0x3040, 0x309F),   # Hiragana
    (0x30A0, 0x30FF),   # Katakana
    (0xAC00, 0xD7AF),   # Hangul Syllables
]

def is_cjk_heavy(text: str, threshold: float = 0.3) -> bool:
    """
    检查文本是否包含大量 CJK 字符
    
    Args:
        text: 要检查的文本
        threshold: CJK 字符占比阈值（默认 30%）
    
    Returns:
        True 如果 CJK 字符占比超过阈值
    """
    if not text or len(text) < 10:
        return False
    
    cjk_count = 0
    for char in text:
        cp = ord(char)
        for start, end in CJK_RANGES:
            if start <= cp <= end:
                cjk_count += 1
                break
    
    return (cjk_count / len(text)) > threshold


class EntropyAnalyzer:
    """
    熵值分析引擎
    
    核心原理:
    - 逐行/逐块计算 Shannon 熵
    - 对比基准熵值（同类文件的典型熵值范围）
    - 标记显著偏离的区域
    """

    def __init__(self):
        self.findings: List[EntropyFinding] = []
        # 各类文件的基准熵值范围
        self.baseline_entropies = {
            '.py': (4.2, 4.8),      # Python 代码
            '.js': (4.3, 4.9),      # JavaScript
            '.sh': (4.0, 4.6),      # Shell 脚本
            '.md': (4.5, 5.2),      # Markdown
            '.json': (4.0, 5.0),    # JSON
            '.yaml': (4.0, 4.8),    # YAML
            '.txt': (4.0, 4.8),     # 纯文本
        }

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """
        计算字符串的 Shannon 熵
        
        H = -Σ p(x) * log2(p(x))
        
        Args:
            data: 要分析的字符串
            
        Returns:
            熵值 (0-8 bits)
        """
        if not data:
            return 0.0
        
        length = len(data)
        if length == 0:
            return 0.0
        
        freq = Counter(data)
        entropy = 0.0
        
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)

    @staticmethod
    def calculate_byte_entropy(data: bytes) -> float:
        """计算字节级别的熵值（适用于二进制数据）"""
        if not data:
            return 0.0
        
        length = len(data)
        freq = Counter(data)
        entropy = 0.0
        
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)

    def analyze_file(self, file_path: Path) -> List[EntropyFinding]:
        """分析单个文件的熵值分布"""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return findings
        
        lines = content.split('\n')
        ext = file_path.suffix.lower()
        baseline = self.baseline_entropies.get(ext, (4.0, 5.0))
        
        # v3.6: CJK 自适应阈值 — 中文天然高熵，提高阈值避免误报
        cjk_heavy = is_cjk_heavy(content)
        doc_file = ext in ('.md', '.txt')
        
        if cjk_heavy or doc_file:
            # CJK 文本或文档：提高阈值（参考 SmartChainArk 误报调优）
            effective_thresholds = {
                'CRITICAL': 7.5,   # 从 7.0 → 7.5
                'HIGH': 6.5,       # 从 6.0 → 6.5
                'MEDIUM': 6.0,     # 从 5.5 → 6.0
            }
        else:
            effective_thresholds = ENTROPY_THRESHOLDS.copy()
        
        # ─── 全局文件熵值 ───────────────────────────────────────
        global_entropy = self.calculate_entropy(content)
        if global_entropy > effective_thresholds['CRITICAL']:
            findings.append(EntropyFinding(
                rule_id='ENTROPY_001',
                title=f'文件整体熵值异常高: {global_entropy:.2f}',
                severity='CRITICAL',
                description=(
                    f'文件 "{file_path.name}" 的整体熵值为 {global_entropy:.2f}，'
                    f'远超同类文件 ({ext}) 的正常范围 {baseline[0]}-{baseline[1]}。\n'
                    f'这通常意味着文件包含大量加密、压缩或编码的数据，'
                    f'可能是隐藏的恶意 payload。'
                    + (f'\n\n⚠️ 已启用 CJK 自适应阈值（原阈值已上调）' if cjk_heavy else '')
                ),
                file_path=str(file_path),
                line_number=0,
                entropy_score=global_entropy,
                threshold=effective_thresholds['CRITICAL'],
                category='high_global_entropy',
                confidence=0.85,
                remediation='检查文件中是否包含编码/加密的 payload，特别是大段无意义字符',
            ))
        elif global_entropy > effective_thresholds['HIGH']:
            findings.append(EntropyFinding(
                rule_id='ENTROPY_002',
                title=f'文件熵值偏高: {global_entropy:.2f}',
                severity='HIGH',
                description=(
                    f'文件 "{file_path.name}" 的熵值为 {global_entropy:.2f}，'
                    f'高于正常范围 ({baseline[0]}-{baseline[1]})。\n'
                    f'可能存在编码或混淆的内容。'
                    + (f'\n\n⚠️ 已启用 CJK 自适应阈值（原阈值已上调）' if cjk_heavy else '')
                ),
                file_path=str(file_path),
                line_number=0,
                entropy_score=global_entropy,
                threshold=effective_thresholds['HIGH'],
                category='elevated_global_entropy',
                confidence=0.7,
                remediation='审查文件中的高熵区域',
            ))
        
        # ─── 逐行熵值分析 ──────────────────────────────────────
        high_entropy_lines = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if len(stripped) < 20:  # 太短的行跳过
                continue
            
            line_entropy = self.calculate_entropy(stripped)
            
            if line_entropy > effective_thresholds['CRITICAL']:
                high_entropy_lines.append((line_num, line_entropy, stripped))
            elif line_entropy > effective_thresholds['HIGH'] and len(stripped) > 50:
                high_entropy_lines.append((line_num, line_entropy, stripped))
        
        # 如果有多行高熵，报告聚合结果
        if len(high_entropy_lines) >= 3:
            avg_entropy = sum(e for _, e, _ in high_entropy_lines) / len(high_entropy_lines)
            line_nums = [ln for ln, _, _ in high_entropy_lines]
            findings.append(EntropyFinding(
                rule_id='ENTROPY_003',
                title=f'检测到多行高熵内容 ({len(high_entropy_lines)} 行)',
                severity='HIGH',
                description=(
                    f'文件中有 {len(high_entropy_lines)} 行的熵值异常高，'
                    f'平均熵值 {avg_entropy:.2f}。\n'
                    f'涉及行号: {", ".join(map(str, line_nums[:10]))}'
                    f'{"..." if len(line_nums) > 10 else ""}\n\n'
                    f'示例内容 (第 {line_nums[0]} 行):\n'
                    f'```\n{high_entropy_lines[0][2][:200]}\n```'
                ),
                file_path=str(file_path),
                line_number=line_nums[0],
                entropy_score=avg_entropy,
                threshold=effective_thresholds['HIGH'],
                category='multiple_high_entropy_lines',
                confidence=0.8,
                remediation='这些高熵行可能包含编码的 payload 或混淆代码',
            ))
        elif len(high_entropy_lines) == 1:
            ln, ent, content_sample = high_entropy_lines[0]
            findings.append(EntropyFinding(
                rule_id='ENTROPY_004',
                title=f'单行超高熵: {ent:.2f} (第 {ln} 行)',
                severity='MEDIUM',
                description=(
                    f'第 {ln} 行的熵值为 {ent:.2f}，异常高。\n'
                    f'内容预览: `{content_sample[:150]}...`'
                ),
                file_path=str(file_path),
                line_number=ln,
                entropy_score=ent,
                threshold=effective_thresholds['HIGH'],
                category='single_high_entropy_line',
                confidence=0.6,
                remediation='检查该行是否为编码数据',
            ))
        
        # ─── 长字符串常量检测 ──────────────────────────────────
        string_findings = self._detect_long_strings(content, file_path, effective_thresholds)
        findings.extend(string_findings)
        
        self.findings.extend(findings)
        return findings

    def _detect_long_strings(self, content: str, file_path: Path, 
                              effective_thresholds: Dict[str, float] = None) -> List[EntropyFinding]:
        """检测代码中的长字符串常量（可能是编码 payload）"""
        import re
        findings = []
        
        # v3.6: 跳过 package-lock.json / yarn.lock — integrity hash 是正常包校验哈希
        filename = file_path.name.lower()
        if filename in ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'):
            return findings
        
        thresholds = effective_thresholds or ENTROPY_THRESHOLDS
        min_entropy = thresholds.get('MEDIUM', 5.5)
        
        # 匹配长字符串赋值
        long_string_patterns = [
            r'(?:payload|data|code|script|cmd)\s*[=:]\s*["\']([A-Za-z0-9+/=\-_]{64,})["\']',
            r'["\']([A-Za-z0-9+/=]{64,})["\']',
        ]
        
        for pattern in long_string_patterns:
            for match in re.finditer(pattern, content):
                string_val = match.group(1) if match.lastindex else match.group(0)
                if len(string_val) >= 64:
                    entropy = self.calculate_entropy(string_val)
                    
                    if entropy > min_entropy:
                        # 计算行号
                        line_num = content[:match.start()].count('\n') + 1
                        
                        findings.append(EntropyFinding(
                            rule_id='ENTROPY_010',
                            title=f'长高熵字符串常量 (熵={entropy:.2f}, 长度={len(string_val)})',
                            severity='HIGH' if entropy > thresholds.get('HIGH', 6.0) else 'MEDIUM',
                            description=(
                                f'检测到长度为 {len(string_val)} 的高熵字符串常量，'
                                f'熵值 {entropy:.2f}。\n'
                                f'这可能是 base64 编码的 payload 或其他编码数据。\n\n'
                                f'内容预览:\n```\n{string_val[:200]}\n```'
                            ),
                            file_path=str(file_path),
                            line_number=line_num,
                            entropy_score=entropy,
                            threshold=min_entropy,
                            category='long_high_entropy_string',
                            confidence=0.75,
                            remediation='解码该字符串并审查其内容',
                        ))
        
        return findings

    def analyze_directory(self, dir_path: Path, recursive: bool = True,
                           path_filter=None) -> List[EntropyFinding]:
        """分析目录中所有文件的熵值"""
        from path_filter import PathFilter as PF
        pf = path_filter or PF()
        all_findings = []
        
        extensions = {'.py', '.js', '.ts', '.sh', '.md', '.yaml', '.yml', '.json', '.txt'}
        
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

    def get_summary(self) -> Dict:
        """获取熵值分析统计摘要"""
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        by_category = {}
        max_entropy = 0.0
        
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1
            max_entropy = max(max_entropy, f.entropy_score)
        
        return {
            'total_findings': len(self.findings),
            'by_severity': by_severity,
            'by_category': by_category,
            'max_entropy_score': max_entropy,
        }
