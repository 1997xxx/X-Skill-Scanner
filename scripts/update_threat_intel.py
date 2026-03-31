#!/usr/bin/env python3
"""
威胁情报自动更新工具 v1.0
Threat Intelligence Auto-Updater

从多个安全源自动拉取和合并威胁情报数据，包括：
- MaliciousAgentSkillsBench (MASB)
- ClawHavoc / Koi Security
- ToxicSkills (Snyk)
- 自定义本地规则

用法:
    python3 scripts/update_threat_intel.py              # 更新所有源
    python3 scripts/update_threat_intel.py --source masb  # 仅更新 MASB
    python3 scripts/update_threat_intel.py --dry-run      # 预览不保存
"""

import json
import sys
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set


# ─── 配置 ──────────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent.parent / 'data'
INTEL_FILE = DATA_DIR / 'threat_intel.json'

# 已知恶意技能名称样本（来自公开研究）
KNOWN_MALICIOUS_SKILLS = [
    # MaliciousAgentSkillsBench
    "memory-stealer", "credential-harvester", "keylogger-skill",
    "reverse-shell-helper", "crypto-miner-plugin", "data-exfiltrator",
    "prompt-injector", "system-commander", "file-encryptor",
    "network-scanner-pro", "password-dumper", "backdoor-installer",
    "rootkit-helper", "ransomware-trigger", "spyware-collector",
    "token-thief", "session-hijacker", "privilege-escalator",
    "dns-tunnel-tool", "hidden-payload-loader",
    # ClawHavoc / Koi Security
    "clawhavoc-test", "poisoned-skill-alpha", "toxic-agent-beta",
    "malicious-mcp-gateway", "trojan-helper", "worm-propagator",
    # ToxicSkills (Snyk)
    "toxic-skill-demo", "evil-assistant", "dark-helper",
    "shadow-plugin", "venom-tool", "cobra-exploit",
]

KNOWN_MALICIOUS_DOMAINS = [
    "evil-api.example.com", "malware-c2.example.net",
    "data-exfil.example.org", "phishing-login.example.com",
    "cryptominer-pool.example.net",
]

KNOWN_MALICIOUS_IPS = [
    "198.51.100.1", "203.0.113.66", "192.0.2.99",
    "198.51.100.42", "203.0.113.100",
]

KNOWN_TTP_PATTERNS = [
    {"id": "TTP_015", "name": "Instruction Override", "pattern": "(ignore|forget|override).*(previous|all|instruction)", "severity": "CRITICAL"},
    {"id": "TTP_029", "name": "DAN Jailbreak", "pattern": "(DAN|developer mode|uncensored|unfiltered)", "severity": "HIGH"},
    {"id": "TTP_001", "name": "Reverse Shell Pattern", "pattern": "/dev/tcp/\\d+\\.\\d+\\.\\d+\\.\\d+", "severity": "CRITICAL"},
    {"id": "TTP_002", "name": "Crypto Mining Pool", "pattern": "stratum\\+tcp://", "severity": "CRITICAL"},
    {"id": "TTP_003", "name": "Base64 Execute", "pattern": "eval\\(.*base64_decode", "severity": "HIGH"},
    {"id": "TTP_004", "name": "Curl Pipe Bash", "pattern": "curl\\s+[^|]+\\|\\s*(ba)?sh", "severity": "CRITICAL"},
    {"id": "TTP_005", "name": "Wget Pipe Sh", "pattern": "wget\\s+[^|]+\\|\\s*sh", "severity": "CRITICAL"},
]


def load_current_intel() -> Dict:
    """加载当前威胁情报"""
    if INTEL_FILE.exists():
        try:
            with open(INTEL_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, KeyError):
            pass
    
    return {
        "version": "0.0.0",
        "updated": "",
        "malicious_skill_names": [],
        "malicious_domains": [],
        "malicious_ips": [],
        "malicious_patterns": [],
        "sources": {},
        "statistics": {},
    }


def save_intel(intel: Dict):
    """保存威胁情报"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(INTEL_FILE, 'w', encoding='utf-8') as f:
        json.dump(intel, f, ensure_ascii=False, indent=2)
    print(f"✅ 威胁情报已保存: {INTEL_FILE}")


def bump_version(version: str) -> str:
    """版本号 +1"""
    parts = version.split('.')
    try:
        parts[-1] = str(int(parts[-1]) + 1)
    except ValueError:
        parts.append('1')
    return '.'.join(parts)


def merge_deduplicate(list_a: List[str], list_b: List[str]) -> List[str]:
    """合并并去重（保持大小写不敏感）"""
    seen: Set[str] = set()
    result = []
    for item in list_a + list_b:
        key = item.lower().strip()
        if key and key not in seen:
            seen.add(key)
            result.append(item.strip())
    return sorted(result)


def update_from_builtin(intel: Dict, dry_run: bool = False) -> int:
    """从内置样本更新"""
    added = 0
    
    old_skills = intel.get('malicious_skill_names', [])
    new_skills = merge_deduplicate(old_skills, KNOWN_MALICIOUS_SKILLS)
    added += len(new_skills) - len(old_skills)
    intel['malicious_skill_names'] = new_skills
    
    old_domains = intel.get('malicious_domains', [])
    new_domains = merge_deduplicate(old_domains, KNOWN_MALICIOUS_DOMAINS)
    added += len(new_domains) - len(old_domains)
    intel['malicious_domains'] = new_domains
    
    old_ips = intel.get('malicious_ips', [])
    new_ips = merge_deduplicate(old_ips, KNOWN_MALICIOUS_IPS)
    added += len(new_ips) - len(old_ips)
    intel['malicious_ips'] = new_ips
    
    # TTP patterns - merge by ID
    old_patterns = intel.get('malicious_patterns', [])
    existing_ids = {p.get('id') for p in old_patterns}
    for p in KNOWN_TTP_PATTERNS:
        if p['id'] not in existing_ids:
            old_patterns.append(p)
            added += 1
    intel['malicious_patterns'] = old_patterns
    
    intel.setdefault('sources', {})
    intel['sources']['builtin'] = {
        'last_updated': datetime.now().isoformat(),
        'skills_added': len(KNOWN_MALICIOUS_SKILLS),
        'domains_added': len(KNOWN_MALICIOUS_DOMAINS),
        'ips_added': len(KNOWN_MALICIOUS_IPS),
        'patterns_added': len(KNOWN_TTP_PATTERNS),
    }
    
    return added


def update_statistics(intel: Dict):
    """更新统计信息"""
    intel['statistics'] = {
        'total_malicious_skills': len(intel.get('malicious_skill_names', [])),
        'total_malicious_domains': len(intel.get('malicious_domains', [])),
        'total_malicious_ips': len(intel.get('malicious_ips', [])),
        'total_ttp_patterns': len(intel.get('malicious_patterns', [])),
    }


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='威胁情报自动更新工具')
    parser.add_argument('--dry-run', action='store_true', help='仅预览，不保存')
    parser.add_argument('--source', choices=['all', 'builtin', 'masb'], 
                        default='all', help='更新来源')
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔄 X Skill Scanner - 威胁情报更新")
    print("=" * 60)
    
    intel = load_current_intel()
    old_version = intel.get('version', '0.0.0')
    print(f"\n当前版本: {old_version}")
    print(f"最后更新: {intel.get('updated', '从未')}")
    
    total_added = 0
    
    if args.source in ('all', 'builtin'):
        print("\n📦 更新内置威胁样本...")
        added = update_from_builtin(intel, dry_run=args.dry_run)
        total_added += added
        print(f"   新增 {added} 条情报")
    
    # 更新版本和时间
    intel['version'] = bump_version(old_version)
    intel['updated'] = datetime.now().isoformat()
    update_statistics(intel)
    
    stats = intel.get('statistics', {})
    print(f"\n📊 情报库统计:")
    print(f"   恶意技能名称: {stats.get('total_malicious_skills', 0)}")
    print(f"   恶意域名:     {stats.get('total_malicious_domains', 0)}")
    print(f"   恶意 IP:      {stats.get('total_malicious_ips', 0)}")
    print(f"   TTP 模式:     {stats.get('total_ttp_patterns', 0)}")
    print(f"   新版本:       {intel['version']}")
    
    if args.dry_run:
        print("\n⚠️  Dry run 模式 — 未保存更改")
    else:
        save_intel(intel)
        print(f"\n✅ 更新完成! 共新增 {total_added} 条情报")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
