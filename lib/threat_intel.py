#!/usr/bin/env python3
"""
威胁情报引擎
加载和匹配威胁情报数据
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class ThreatIntelligence:
    """威胁情报匹配引擎"""
    
    def __init__(self, data_path: Optional[str] = None):
        if data_path is None:
            data_path = Path(__file__).parent.parent / 'data' / 'threat_intel.json'
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
            'version': '1.0.0',
            'updated': datetime.now().strftime('%Y-%m-%d'),
            'malicious_patterns': [],
            'malicious_skill_names': [],
            'malicious_domains': [],
            'malicious_ips': []
        }
    
    def check_skill_name(self, name: str) -> Tuple[bool, Optional[str]]:
        """
        检查技能名称是否在黑名单中
        
        Returns:
            (is_malicious, matched_name)
        """
        name_lower = name.lower()
        for malicious_name in self.intel_data.get('malicious_skill_names', []):
            if malicious_name.lower() == name_lower:
                return True, malicious_name
        return False, None
    
    def check_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        检查域名是否在黑名单中
        
        Returns:
            (is_blacklisted, matched_domain)
        """
        domain_lower = domain.lower()
        for malicious_domain in self.intel_data.get('malicious_domains', []):
            if malicious_domain.lower() in domain_lower:
                return True, malicious_domain
        return False, None
    
    def check_ip(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        检查 IP 是否在黑名单中
        
        Returns:
            (is_blacklisted, matched_ip)
        """
        for malicious_ip in self.intel_data.get('malicious_ips', []):
            if ip.startswith(malicious_ip.split('.')[:3]):
                return True, malicious_ip
        return False, None
    
    def check_code_pattern(self, code: str) -> List[Dict]:
        """
        检查代码是否匹配恶意模式
        
        Returns:
            匹配的模式列表
        """
        import re
        matches = []
        
        for pattern in self.intel_data.get('malicious_patterns', []):
            try:
                if re.search(pattern['pattern'], code, re.IGNORECASE):
                    matches.append({
                        'id': pattern['id'],
                        'name': pattern['name'],
                        'severity': pattern['severity']
                    })
            except re.error:
                continue
        
        return matches
    
    def get_statistics(self) -> Dict:
        """获取情报统计信息"""
        return self.intel_data.get('statistics', {
            'total_malicious': len(self.intel_data.get('malicious_skill_names', [])),
            'malicious_domains': len(self.intel_data.get('malicious_domains', [])),
            'malicious_ips': len(self.intel_data.get('malicious_ips', [])),
            'ttp_patterns': len(self.intel_data.get('malicious_patterns', []))
        })
    
    def get_version(self) -> str:
        """获取情报库版本"""
        return self.intel_data.get('version', 'unknown')
    
    def get_updated(self) -> str:
        """获取最后更新时间"""
        return self.intel_data.get('updated', 'unknown')
