#!/usr/bin/env python3
"""
分析器接口 — 参考 CoPaw 的 BaseAnalyzer 设计
每个分析器实现统一的 analyze() 接口，可独立注册和扩展
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from ..models_v2 import Finding, SkillFile


class BaseAnalyzer(ABC):
    """所有安全分析器的抽象基类
    
    新检测引擎（如 LLM-based、行为数据流）可作为插件添加，
    无需修改扫描器核心逻辑。
    
    Parameters
    ----------
    name : str
        人类可读的分析器名称（用于 Finding.analyzer 字段）
    """
    
    def __init__(self, name: str) -> None:
        self.name = name
    
    @property
    def analyzer_name(self) -> str:
        return self.name
    
    @abstractmethod
    def analyze(
        self,
        skill_dir: Path,
        files: List["SkillFile"],
        *,
        skill_name: str | None = None,
    ) -> List["Finding"]:
        """分析技能包中的安全问题
        
        Parameters
        ----------
        skill_dir : Path
            技能根目录
        files : List[SkillFile]
            预发现的文件列表
        skill_name : str, optional
            技能名称
            
        Returns
        -------
        List[Finding]
            此分析器发现的列表
        """
        ...
    
    def get_name(self) -> str:
        """分析器名称"""
        return self.name


__all__ = ["BaseAnalyzer"]
