#!/usr/bin/env python3
"""
白名单管理器
Whitelist Manager
用于配置可信任的技能、域名、函数等
"""

import json
import os
from typing import Dict, List, Set, Optional
from pathlib import Path
from dataclasses import dataclass, field

from openclaw_config import get_openclaw_home


@dataclass
class WhitelistConfig:
    """白名单配置"""
    # 可信的技能列表 (Skill ID 或名称)
    trusted_skills: Set[str] = field(default_factory=set)
    
    # 可信的域名
    trusted_domains: Set[str] = field(default_factory=set)
    
    # 可信的 IP 地址
    trusted_ips: Set[str] = field(default_factory=set)
    
    # 可信的函数名 (安全函数)
    safe_functions: Set[str] = field(default_factory=set)
    
    # 可信的路径模式
    safe_paths: Set[str] = field(default_factory=set)
    
    # 豁免的规则 ID (不报告这些规则)
    exempt_rules: Set[str] = field(default_factory=set)
    
    # 放宽检查的文件路径
    skip_paths: Set[str] = field(default_factory=set)


class WhitelistManager:
    """
    白名单管理器
    
    用法:
        manager = WhitelistManager()
        manager.load_from_file("whitelist.json")
        
        # 检查是否在白名单
        if manager.is_domain_trusted("example.com"):
            print("Domain is trusted")
        
        # 豁免检查
        if manager.is_rule_exempt("CRED_001"):
            print("Rule is exempted")
    """
    
    # ✅ 预设安全函数 — 仅包含无副作用的纯计算/解析函数
    # ⚠️ 排除所有文件 I/O、动态属性操作、正则编译等可被滥用的函数
    # 参考：Bandit B3xx/B4xx 规则、Semgrep Python 安全模式
    DEFAULT_SAFE_FUNCTIONS: Set[str] = {
        # ── JSON/YAML/TOML 解析（仅内存中的序列化/反序列化）──
        "json.loads", "json.dumps",
        "yaml.safe_load", "yaml.safe_dump",
        "toml.loads", "toml.dumps",
        
        # ── 字符串操作（纯转换，无副作用）──
        "str.strip", "str.lower", "str.upper", "str.replace",
        "str.split", "str.join", "str.find",
        "str.startswith", "str.endswith",
        "str.format", "str.encode", "str.decode",
        
        # ── 日志输出（仅打印，不执行）──
        "print",
        "logging.info", "logging.debug", "logging.warning",
        "logging.error", "logging.critical",
        
        # ── 类型检查（只读 introspection）──
        "isinstance", "type", "hasattr",
        
        # ── 基础数据结构构造 ──
        "list", "dict", "set", "tuple",
        "len", "range",
        "sorted", "enumerate", "zip",
        
        # ── 数学/数值 ──
        "int", "float", "str", "bool",
        "abs", "max", "min", "sum",
        "round",
        
        # ── 时间查询（只读，不含 sleep）──
        "time.time",
        "datetime.now", "datetime.utcnow",
        "datetime.fromtimestamp", "datetime.strftime",
    }
    
    # ⚠️ 路径白名单：默认空白（零信任）
    # 用户有需求自行通过 whitelist.json 或 API 添加
    DEFAULT_SAFE_PATHS: Set[str] = set()
    
    def __init__(self):
        self.config = WhitelistConfig()
        self._load_defaults()
    
    def _load_defaults(self):
        """加载默认安全函数和路径"""
        self.config.safe_functions.update(self.DEFAULT_SAFE_FUNCTIONS)
        self.config.safe_paths.update(self.DEFAULT_SAFE_PATHS)
    
    def load_from_file(self, filepath: str) -> bool:
        """
        从文件加载白名单配置
        
        Args:
            filepath: 配置文件路径
        
        Returns:
            是否加载成功
        """
        if not os.path.exists(filepath):
            return False
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 解析配置
            if "trusted_skills" in data:
                self.config.trusted_skills.update(data["trusted_skills"])
            
            if "trusted_domains" in data:
                self.config.trusted_domains.update(data["trusted_domains"])
            
            if "trusted_ips" in data:
                self.config.trusted_ips.update(data["trusted_ips"])
            
            if "safe_functions" in data:
                self.config.safe_functions.update(data["safe_functions"])
            
            if "safe_paths" in data:
                self.config.safe_paths.update(data["safe_paths"])
            
            if "exempt_rules" in data:
                self.config.exempt_rules.update(data["exempt_rules"])
            
            if "skip_paths" in data:
                self.config.skip_paths.update(data["skip_paths"])
            
            return True
        
        except Exception as e:
            print(f"Failed to load whitelist: {e}")
            return False
    
    def save_to_file(self, filepath: str) -> bool:
        """
        保存白名单配置到文件
        
        Args:
            filepath: 配置文件路径
        
        Returns:
            是否保存成功
        """
        try:
            data = {
                "trusted_skills": list(self.config.trusted_skills),
                "trusted_domains": list(self.config.trusted_domains),
                "trusted_ips": list(self.config.trusted_ips),
                "safe_functions": list(self.config.safe_functions),
                "safe_paths": list(self.config.safe_paths),
                "exempt_rules": list(self.config.exempt_rules),
                "skip_paths": list(self.config.skip_paths),
            }
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return True
        
        except Exception as e:
            print(f"Failed to save whitelist: {e}")
            return False
    
    def is_domain_trusted(self, domain: str) -> bool:
        """检查域名是否可信"""
        domain = domain.lower()
        
        # 精确匹配
        if domain in self.config.trusted_domains:
            return True
        
        # 域名后缀匹配 (e.g., "github.com" matches "raw.githubusercontent.com")
        for trusted in self.config.trusted_domains:
            if domain.endswith(f".{trusted}") or domain == trusted:
                return True
        
        return False
    
    def is_ip_trusted(self, ip: str) -> bool:
        """检查 IP 是否可信"""
        return ip in self.config.trusted_ips
    
    def is_function_safe(self, func_name: str) -> bool:
        """检查函数是否在安全列表中"""
        # 处理模块.函数格式
        if "." in func_name:
            module_func = func_name
            func_only = func_name.split(".")[-1]
            return module_func in self.config.safe_functions or func_only in self.config.safe_functions
        
        return func_name in self.config.safe_functions
    
    def is_path_safe(self, path: str) -> bool:
        """检查路径是否安全"""
        import fnmatch
        
        for safe_pattern in self.config.safe_paths:
            if fnmatch.fnmatch(path, safe_pattern):
                return True
        
        return False
    
    def is_rule_exempt(self, rule_id: str) -> bool:
        """检查规则是否被豁免"""
        return rule_id in self.config.exempt_rules
    
    def should_skip_path(self, path: str) -> bool:
        """检查路径是否应该跳过检查"""
        import fnmatch
        
        for skip_pattern in self.config.skip_paths:
            if fnmatch.fnmatch(path, skip_pattern):
                return True
        
        return False
    
    def is_whitelisted(self, target) -> dict:
        """
        检查目标是否在白名单中
        
        Args:
            target: Path 对象或字符串路径
        
        Returns:
            dict: {'is_whitelisted': bool, 'reason': str}
        """
        from pathlib import Path
        
        # 转换为 Path 对象
        if isinstance(target, str):
            target = Path(target)
        
        target_str = str(target)
        target_name = target.name if hasattr(target, 'name') else ''
        target_str_normalized = target_str.replace('~', str(get_openclaw_home()))
        
        # 1. 检查技能名称是否在可信技能列表中
        if target_name in self.config.trusted_skills:
            return {'is_whitelisted': True, 'reason': f'Trusted skill: {target_name}'}
        
        # 2. 检查路径是否应该跳过
        if self.should_skip_path(target_str):
            return {'is_whitelisted': True, 'reason': f'Skip path pattern: {target_str}'}
        
        # 3. 检查路径模式匹配（需显式配置 safe_paths）
        for safe_path in self.config.safe_paths:
            safe_path_expanded = safe_path.replace('~', str(get_openclaw_home()))
            if target_str_normalized.startswith(safe_path_expanded):
                return {'is_whitelisted': True, 'reason': f'Safe path pattern: {safe_path}'}
        
        # ⚠️ 默认：不在白名单中，必须扫描
        return {'is_whitelisted': False, 'reason': 'Not in whitelist (zero-trust default)'}
        
        return {'is_whitelisted': False, 'reason': 'Not in whitelist'}
    
    def add_trusted_domain(self, domain: str):
        """添加可信域名"""
        self.config.trusted_domains.add(domain.lower())
    
    def add_trusted_skill(self, skill_id: str):
        """添加可信技能"""
        self.config.trusted_skills.add(skill_id)
    
    def add_exempt_rule(self, rule_id: str):
        """添加豁免规则"""
        self.config.exempt_rules.add(rule_id)
    
    def get_summary(self) -> Dict:
        """获取白名单摘要"""
        return {
            "trusted_skills_count": len(self.config.trusted_skills),
            "trusted_domains_count": len(self.config.trusted_domains),
            "trusted_ips_count": len(self.config.trusted_ips),
            "safe_functions_count": len(self.config.safe_functions),
            "safe_paths_count": len(self.config.safe_paths),
            "exempt_rules_count": len(self.config.exempt_rules),
            "skip_paths_count": len(self.config.skip_paths),
        }


# 导出
__all__ = ['WhitelistManager', 'WhitelistConfig']