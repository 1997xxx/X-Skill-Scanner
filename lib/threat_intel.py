#!/usr/bin/env python3
"""
威胁情报引擎 v3.1 - 基于 ClawHavoc/Snyk ToxicSkills/SkillJect 分析
加载和匹配威胁情报数据，支持技能名称、域名、IP、代码模式匹配
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class ThreatIntelligence:
    """威胁情报匹配引擎"""
    
    def __init__(self, data_path: Optional[str] = None):
        if data_path is None:
            data_path = Path(__file__).parent / 'threat_intel.json'
        self.data_path = Path(data_path)
        self.intel_data = self._load_intel()
    
    def _load_intel(self) -> Dict:
        """加载威胁情报数据"""
        if not self.data_path.exists():
            return self._empty_intel()
        
        with open(self.data_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _empty_intel(self) -> Dict:
        """返回空情报数据结构"""
        return {
            'version': '3.1.0',
            'updated': datetime.now().strftime('%Y-%m-%d'),
            'sources': ['Local Database'],
            'known_malicious_names': [],
            'typosquat_patterns': [],
            'attack_patterns': {},
            'ioc_domains': [],
            'malicious_authors': []
        }
    
    def check_skill_name(self, name: str) -> Tuple[bool, Optional[str], str]:
        """
        检查技能名称是否在已知恶意列表中
        
        Returns:
            (is_malicious, matched_name, risk_category)
        """
        name_lower = name.lower()
        
        # 精确匹配 - 已知恶意技能名
        known_malicious = self.intel_data.get('known_malicious_names', [])
        for malicious_name in known_malicious:
            if malicious_name.lower() == name_lower:
                return True, malicious_name, 'KNOWN_MALICIOUS'
        
        # Typosquat 模糊匹配 - 基于 ClawHavoc/Snyk 报告的模式
        typosquat_patterns = self.intel_data.get('typosquat_patterns', [])
        for pattern in typosquat_patterns:
            pattern_lower = pattern.lower()
            # 前缀匹配或包含匹配
            if name_lower.startswith(pattern_lower + '-') or \
               name_lower.startswith(pattern_lower) or \
               pattern_lower.startswith(name_lower) or \
               name_lower.replace('-', '') == pattern_lower.replace('-', ''):
                return True, pattern, 'TYPOSQUAT'
        
        return False, None, ''
    
    def check_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        检查域名/IP 是否在 IOC 列表中
        
        Returns:
            (is_blacklisted, matched_ioc)
        """
        domain_lower = domain.lower()
        for ioc in self.intel_data.get('ioc_domains', []):
            if ioc.lower() in domain_lower:
                return True, ioc
        return False, None
    
    def check_author(self, author: str) -> Tuple[bool, Optional[str]]:
        """
        检查作者是否在已知恶意作者列表中
        
        Returns:
            (is_malicious, matched_author)
        """
        author_lower = author.lower()
        for mal_author in self.intel_data.get('malicious_authors', []):
            if mal_author.lower() == author_lower:
                return True, mal_author
        return False, None
    
    def get_attack_patterns(self) -> Dict:
        """获取所有攻击模式"""
        return self.intel_data.get('attack_patterns', {})
    
    def check_code_patterns(self, code: str) -> List[Dict]:
        """
        检查代码是否匹配已知攻击模式
        
        Returns:
            匹配的攻击模式列表
        """
        matches = []
        patterns = self.get_attack_patterns()
        
        for pattern_id, pattern_info in patterns.items():
            indicators = pattern_info.get('indicators', [])
            severity = pattern_info.get('severity', 'HIGH')
            
            for indicator in indicators:
                try:
                    if re.search(re.escape(indicator), code, re.IGNORECASE):
                        matches.append({
                            'pattern_id': pattern_id,
                            'description': pattern_info.get('description', ''),
                            'indicator': indicator,
                            'severity': severity
                        })
                        break  # One match per pattern is enough
                except re.error:
                    continue
        
        return matches
    
    def get_statistics(self) -> Dict:
        """获取情报统计信息"""
        stats = self.intel_data.get('statistics', {})
        return {
            'total_known_malicious': len(self.intel_data.get('known_malicious_names', [])),
            'typosquat_variants': len(self.intel_data.get('typosquat_patterns', [])),
            'attack_patterns': len(self.get_attack_patterns()),
            'ioc_domains': len(self.intel_data.get('ioc_domains', [])),
            'malicious_authors': len(self.intel_data.get('malicious_authors', [])),
            **stats
        }
    
    def get_version(self) -> str:
        """获取情报库版本"""
        return self.intel_data.get('version', 'unknown')
    
    def get_updated(self) -> str:
        """获取最后更新时间"""
        return self.intel_data.get('updated', 'unknown')
    
    def get_sources(self) -> List[str]:
        """获取情报来源"""
        return self.intel_data.get('sources', [])