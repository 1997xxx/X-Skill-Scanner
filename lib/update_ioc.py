#!/usr/bin/env python3
"""
IOC 情报自动更新工具 — 纯本地模式

从公开威胁情报 Feed 拉取最新恶意域名/IP/URL，
合并到 threat_intel.json 的 ioc_domains 列表中。

⚠️ 本脚本需要联网执行，但 x-skill-scanner 扫描器本身完全离线。
   建议通过 cron 或手动定期运行此脚本更新本地情报库。

使用方式:
    # 更新所有源（默认）
    python3 lib/update_ioc.py

    # 仅更新特定源
    python3 lib/update_ioc.py --source urlhaus

    # 预览不写入
    python3 lib/update_ioc.py --dry-run

    # 查看当前情报统计
    python3 lib/update_ioc.py --stats
"""

import json
import re
import sys
import csv
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple
from io import StringIO
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


# ─── 威胁情报 Feed 源 ──────────────────────────────────────

FEED_SOURCES = [
    {
        'id': 'urlhaus',
        'name': 'URLhaus (abuse.ch)',
        'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
        'format': 'csv',
        'description': '恶意 URL 和域名，每小时更新',
        'extract_field': 'url',  # CSV 列名
        'extract_domain_only': True,  # 只取域名，不要路径
    },
    {
        'id': 'c2intel',
        'name': 'C2IntelFeeds',
        'url': 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv',
        'format': 'csv',
        'description': 'C2 服务器 IP 地址（30天）',
        'extract_field': 'IP',
    },
    {
        'id': 'threatfox_ioc',
        'name': 'ThreatFox IOC',
        'url': 'https://threatfox-api.abuse.ch/api/v1/',
        'format': 'json',
        'description': 'Abuse.ch 综合威胁指标',
        'method': 'POST',
        'body': '{"query": "get_iocs", "days": 7}',
    },
    {
        'id': 'blocklist_de',
        'name': 'Blocklist.de',
        'url': 'https://lists.blocklist.de/lists/all.txt',
        'format': 'text',
        'description': '已知攻击源 IP 列表',
    },
    {
        'id': 'emerging_threats',
        'name': 'Emerging Threats DNS',
        'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'format': 'text',
        'description': '失陷主机 IP 列表',
    },
    # ─── v5.1 新增：无需 API key 的免费源（来自 awesome-threat-intelligence）───
    {
        'id': 'phishtank',
        'name': 'PhishTank',
        'url': 'https://data.phishtank.com/data/online-valid.csv.gz',
        'format': 'csv_gz',
        'description': '活跃钓鱼网站 URL（社区驱动）',
        'extract_field': 'url',
        'extract_domain_only': True,
        'optional': True,
    },
    {
        'id': 'spamhaus_drop',
        'name': 'Spamhaus DROP',
        'url': 'https://www.spamhaus.org/drop/drop.txt',
        'format': 'cidr_text',
        'description': '僵尸网络/C2 控制服务器 IP 段',
    },
    {
        'id': 'firehol_level1',
        'name': 'Firehol Level 1',
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
        'format': 'cidr_text',
        'description': '多源聚合恶意 IP 列表（150+ 数据源）',
    },
    {
        'id': 'binary_defense',
        'name': 'Binary Defense Banlist',
        'url': 'https://www.binarydefense.com/banlist.txt',
        'format': 'text',
        'description': 'Binary Defense 威胁情报 IP 黑名单',
    },
    {
        'id': 'cins_army',
        'name': 'CI Army List',
        'url': 'http://cinsscore.com/list/ci-badguys.txt',
        'format': 'text',
        'description': 'CINS Score 子集，专注其他列表未覆盖的恶意 IP',
    },
    {
        'id': 'bambenek_cc',
        'name': 'Bambenek C&C Tracker',
        'url': 'https://files.bambenekconsulting.com/bambenek/c2-ipmasterlist.txt',
        'format': 'text',
        'description': '活跃 C&C 服务器 IP 跟踪',
        'optional': True,
    },
    {
        'id': 'digitalside',
        'name': 'DigitalSide Threat-Intel',
        'url': 'https://osint.digitalside.it/Threat-Intel/lists/ip-list.txt',
        'format': 'text',
        'description': '基于恶意软件分析的 IP/域名 IOC',
    },
    {
        'id': 'ipsum',
        'name': 'IPsum (stamparm)',
        'url': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        'format': 'ipsum',  # 特殊格式：IP + 出现次数
        'description': '聚合 30+ 公开恶意 IP 列表的威胁情报源',
        'ipsum_min_count': 5,  # 只取被 ≥5 个源确认的高置信度 IP
    },
    {
        'id': 'dshield_block',
        'name': 'DShield Block List',
        'url': 'https://isc.sans.edu/block.txt',
        'format': 'text',
        'description': 'SANS/DShield 攻击源 IP 黑名单',
    },
    {
        'id': 'fastintercept',
        'name': 'FastIntercept IP List',
        'url': 'https://intercept.sh/threatlists/ip.txt',
        'format': 'text',
        'description': '基于全球蜜网的 IP 信誉列表',
        'optional': True,
    },
    {
        'id': 'rescure',
        'name': 'REScure Threat Intel',
        'url': 'https://rescure.fruxlabs.com/rescure.txt',
        'format': 'text',
        'description': 'Fruxlabs 独立威胁情报项目（每 6 小时更新）',
        'optional': True,
    },
]


def fetch_url(url: str, method: str = 'GET', body: str = None) -> str:
    """安全地获取 URL 内容"""
    headers = {
        'User-Agent': 'x-skill-scanner-ioc-updater/5.1 (local threat intel update)',
    }
    
    try:
        req = Request(url, headers=headers, method=method)
        if body and method == 'POST':
            req.add_header('Content-Type', 'application/json')
            data = urlopen(req, timeout=30, data=body.encode())
        else:
            data = urlopen(req, timeout=30)
        
        content = data.read().decode('utf-8', errors='ignore')
        return content
    except (URLError, HTTPError, TimeoutError) as e:
        print(f"   ⚠️  获取失败 [{url[:60]}...]: {e}")
        return ""


# ─── 常见文件扩展名（排除这些，避免把文件名当域名） ──────
FILE_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.msi', '.scr', '.com',
    '.zip', '.rar', '.tar', '.gz', '.bz2', '.xz', '.7z',
    '.txt', '.log', '.csv', '.json', '.xml', '.yaml', '.yml',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.py', '.js', '.ts', '.rb', '.php', '.java', '.c', '.cpp', '.h',
    '.html', '.css', '.sh', '.bash', '.zsh', '.fish',
    '.apk', '.ipa', '.deb', '.rpm', '.pkg', '.dmg',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.flac', '.wav',
    '.xpi', '.crx', '.jar', '.whl', '.wheel', '.egg',
    '.vdw', '.dat', '.tmp', '.bak', '.swp', '.cache', '.bin', '.so',
}


def is_valid_ioc(ioc: str) -> bool:
    """验证是否为有效的 IOC（域名或 IP）"""
    if not ioc or len(ioc) < 4:
        return False
    
    lower_ioc = ioc.lower()
    
    # ── 先检查是否是 IP 地址 ───────────────────────────
    ip_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    ip_match = re.match(ip_pattern, ioc)
    if ip_match:
        # 验证每个段 <= 255
        return all(0 <= int(g) <= 255 for g in ip_match.groups())
    
    # ── 不是 IP，当作域名处理 ──────────────────────────
    
    # 跳过文件扩展名
    for ext in FILE_EXTENSIONS:
        if lower_ioc.endswith(ext):
            return False
    
    # 域名至少要有两段（example.com）
    parts = ioc.split('.')
    if len(parts) < 2:
        return False
    
    # TLD 必须是 2-6 个纯字母
    tld = parts[-1].lower()
    if not tld.isalpha() or len(tld) < 2 or len(tld) > 6:
        return False
    
    # 域名的每一段必须包含至少一个字母（排除纯数字段如 "1.exe" 的变体）
    for part in parts[:-1]:  # 不检查 TLD
        if not any(c.isalpha() for c in part):
            # 纯数字段可能是子域名（123pan.cn），允许
            pass
    
    # 跳过 localhost 和内网地址（以防万一）
    skip_patterns = [
        r'^localhost',
        r'\.(local|test|example|invalid)$',
    ]
    for pattern in skip_patterns:
        if re.search(pattern, ioc, re.I):
            return False
    
    # 基本域名格式检查
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,6}$'
    return bool(re.match(domain_pattern, ioc))


def extract_iocs_from_text(content: str) -> Set[str]:
    """从纯文本中提取 IP 和域名"""
    iocs = set()
    
    # IP 地址
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    for match in re.finditer(ip_pattern, content):
        ip = match.group(1)
        if is_valid_ioc(ip):
            iocs.add(ip)
    
    # 域名（排除常见合法 CDN 和服务）
    domain_pattern = r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b'
    for match in re.finditer(domain_pattern, content):
        domain = match.group(1).lower()
        if is_valid_ioc(domain):
            iocs.add(domain)
    
    return iocs


def extract_iocs_from_csv(content: str, field_name: str = None, domain_only: bool = False) -> Set[str]:
    """从 CSV 中提取 IOC"""
    iocs = set()
    
    try:
        reader = csv.DictReader(StringIO(content))
        rows = list(reader)
        
        if not rows:
            return extract_iocs_from_text(content)
        
        # 自动检测字段名
        field_lower = {k.lower().lstrip('#').strip(): k for k in rows[0].keys()}
        
        if field_name:
            fn_lower = field_name.lower()
            target_field = next((v for k, v in field_lower.items() if fn_lower == k), None)
        else:
            target_field = None
        
        if not target_field:
            for candidate in ['ip', 'host', 'domain', 'url', 'ioc']:
                if candidate in field_lower:
                    target_field = field_lower[candidate]
                    break
        
        if not target_field:
            return extract_iocs_from_text(content)
        
        for row in rows:
            value = row.get(target_field, '').strip()
            if not value:
                continue
            
            # 如果是 URL，提取域名/IP
            if value.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(value)
                hostname = parsed.hostname
                if hostname and is_valid_ioc(hostname):
                    iocs.add(hostname.lower())
                continue
            
            # domain_only 模式下，不处理非 URL 值
            if domain_only:
                continue
            
            if is_valid_ioc(value):
                iocs.add(value.lower())
                
    except Exception as e:
        print(f"   ⚠️  CSV 解析失败: {e}")
        return extract_iocs_from_text(content)
    
    return iocs


def fetch_source(source: Dict) -> Tuple[str, Set[str]]:
    """获取单个数据源的 IOC"""
    print(f"\n📡 获取: {source['name']}")
    print(f"   URL: {source['url'][:80]}...")
    
    method = source.get('method', 'GET')
    body = source.get('body')
    content = fetch_url(source['url'], method, body)
    
    if not content:
        return source['id'], set()
    
    fmt = source['format']
    iocs = parse_content(content, fmt, source)
    
    print(f"   ✅ 提取到 {len(iocs)} 个 IOC")
    return source['id'], iocs


def parse_content(content: str, fmt: str, source: Dict) -> Set[str]:
    """解析不同格式的内容"""
    # ─── gzip 压缩 CSV（PhishTank） ───────────────────
    if fmt == 'csv_gz':
        import gzip
        try:
            raw = content.encode('latin-1')  # 恢复原始字节
            decompressed = gzip.decompress(raw).decode('utf-8', errors='ignore')
            return extract_iocs_from_csv(
                decompressed,
                field_name=source.get('extract_field'),
                domain_only=source.get('extract_domain_only', False)
            )
        except Exception as e:
            print(f"   ⚠️  gzip 解压失败: {e}")
            return extract_iocs_from_text(content)
    
    # ─── CIDR 格式（Spamhaus DROP / Firehol） ───────────────────
    if fmt == 'cidr_text':
        import ipaddress
        iocs = set()
        
        # 保留/私有地址段 — 这些不是恶意指标
        reserved_networks = [
            ipaddress.ip_network('0.0.0.0/8'),
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('100.64.0.0/10'),  # CGNAT
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),  # Link-local
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('224.0.0.0/4'),  # Multicast
            ipaddress.ip_network('240.0.0.0/4'),  # Reserved
        ]
        
        def is_reserved_cidr(cidr_str: str) -> bool:
            try:
                net = ipaddress.ip_network(cidr_str, strict=False)
                return any(net.overlaps(reserved) for reserved in reserved_networks)
            except ValueError:
                return True
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith(';') or line.startswith('#'):
                continue
            # CIDR: 1.2.3.0/24 → 提取完整 CIDR
            cidr_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d+)?', line)
            if cidr_match:
                full_cidr = cidr_match.group(0)
                if not is_reserved_cidr(full_cidr):
                    iocs.add(full_cidr)
        return iocs
    
    # ─── 标准格式 ─────────────────────────────────────
    if fmt == 'csv':
        return extract_iocs_from_csv(
            content, 
            field_name=source.get('extract_field'),
            domain_only=source.get('extract_domain_only', False)
        )
    elif fmt == 'json':
        try:
            data = json.loads(content)
            iocs = set()
            if isinstance(data, dict) and 'data' in data:
                for item in data['data']:
                    if 'ioc' in item:
                        ioc = item['ioc']
                        if ioc.startswith(('http://', 'https://')):
                            from urllib.parse import urlparse
                            parsed = urlparse(ioc)
                            ioc = parsed.hostname or ''
                        if is_valid_ioc(ioc):
                            iocs.add(ioc.lower())
            else:
                iocs = extract_iocs_from_text(json.dumps(data))
        except json.JSONDecodeError:
            iocs = extract_iocs_from_text(content)
        return iocs
    # ─── IPsum（IP + 出现次数） ──────────────────────
    if fmt == 'ipsum':
        iocs = set()
        min_count = source.get('ipsum_min_count', 5)
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                try:
                    count = int(parts[1])
                except ValueError:
                    count = 1
                if count >= min_count and is_valid_ioc(ip):
                    iocs.add(ip)
        return iocs
    
    else:  # text
        return extract_iocs_from_text(content)


def load_existing_ioc(intel_path: Path) -> Dict:
    """加载现有威胁情报"""
    if not intel_path.exists():
        return {
            'version': '5.1.0',
            'updated': datetime.now().strftime('%Y-%m-%d'),
            'sources': ['Local Database'],
            'known_malicious_names': [],
            'typosquat_patterns': [],
            'attack_patterns': {},
            'ioc_domains': [],
            'malicious_authors': []
        }
    
    with open(intel_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description='更新本地 IOC 威胁情报')
    parser.add_argument('--source', type=str, help='仅更新指定源 (urlhaus, c2intel, etc.)')
    parser.add_argument('--dry-run', action='store_true', help='预览模式，不写入文件')
    parser.add_argument('--stats', action='store_true', help='显示当前情报统计')
    args = parser.parse_args()
    
    lib_dir = Path(__file__).parent
    intel_path = lib_dir / 'threat_intel.json'
    
    # 统计模式
    if args.stats:
        data = load_existing_ioc(intel_path)
        print("📊 当前威胁情报统计")
        print(f"   版本: {data.get('version')}")
        print(f"   更新时间: {data.get('updated')}")
        print(f"   来源: {', '.join(data.get('sources', []))}")
        print(f"   恶意技能名: {len(data.get('known_malicious_names', []))} 条")
        print(f"   IOC 域名/IP: {len(data.get('ioc_domains', []))} 条")
        
        iocs = data.get('ioc_domains', [])
        ips = [i for i in iocs if re.match(r'^\d+\.\d+\.\d+\.\d+$', i)]
        domains = [i for i in iocs if not re.match(r'^\d+\.\d+\.\d+\.\d+$', i)]
        print(f"     ├─ IP 地址: {len(ips)} 条")
        print(f"     └─ 域名: {len(domains)} 条")
        print(f"   CIDR 网段: {len(data.get('cidr_ranges', []))} 个（Spamhaus DROP + Firehol）")
        return
    
    # 加载现有数据
    data = load_existing_ioc(intel_path)
    existing_iocs = set(i.lower() for i in data.get('ioc_domains', []))
    existing_cidrs = set(data.get('cidr_ranges', []))
    print(f"📂 现有 IOC: {len(existing_iocs)} 条 | CIDR 网段: {len(existing_cidrs)} 个")
    
    # 筛选要更新的源
    sources = FEED_SOURCES
    if args.source:
        sources = [s for s in sources if s['id'] == args.source]
        if not sources:
            print(f"❌ 未知源: {args.source}")
            print(f"可用源: {', '.join(s['id'] for s in FEED_SOURCES)}")
            sys.exit(1)
    
    # 获取所有源 — 分离 IOC 和 CIDR
    all_new_iocs: Set[str] = set()
    all_new_cidrs: Set[str] = set()
    updated_sources = []
    
    for source in sources:
        src_id, iocs = fetch_source(source)
        
        # 可选源 403 时静默跳过
        if not iocs and source.get('optional'):
            continue
        
        if iocs:
            # CIDR 格式的数据存入独立字段
            if source.get('format') == 'cidr_text':
                all_new_cidrs.update(iocs)
            else:
                all_new_iocs.update(iocs)
            updated_sources.append(source['name'])
    
    if not all_new_iocs and not all_new_cidrs:
        print("\n⚠️  未获取到新 IOC，可能是网络问题或源不可用")
        return
    
    # 合并
    new_iocs = all_new_iocs - existing_iocs
    merged_iocs = existing_iocs | all_new_iocs
    new_cidrs = all_new_cidrs - existing_cidrs
    merged_cidrs = existing_cidrs | all_new_cidrs
    
    print(f"\n📊 合并结果:")
    print(f"   IOC 新增: {len(new_iocs)} 条 | 已有: {len(existing_iocs) - len(new_iocs)} 条（跳过）| 总计: {len(merged_iocs)} 条")
    print(f"   CIDR 新增: {len(new_cidrs)} 个 | 已有: {len(existing_cidrs) - len(new_cidrs)} 个（跳过）| 总计: {len(merged_cidrs)} 个")
    
    if new_iocs:
        print(f"\n🆕 新增 IOC 示例（前 10 条）:")
        for ioc in sorted(new_iocs)[:10]:
            print(f"   + {ioc}")
        if len(new_iocs) > 10:
            print(f"   ... 还有 {len(new_iocs) - 10} 条")
    
    if new_cidrs:
        print(f"\n🆕 新增 CIDR 网段示例（前 10 个）:")
        for cidr in sorted(new_cidrs)[:10]:
            print(f"   + {cidr}")
        if len(new_cidrs) > 10:
            print(f"   ... 还有 {len(new_cidrs) - 10} 个")
    
    # 写入
    if args.dry_run:
        print("\n🔍 预览模式，未写入文件")
        return
    
    data['ioc_domains'] = sorted(list(merged_iocs))
    data['cidr_ranges'] = sorted(list(merged_cidrs))
    data['updated'] = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    # 更新来源列表
    current_sources = set(data.get('sources', []))
    for name in updated_sources:
        current_sources.add(f"{name} (auto-updated)")
    data['sources'] = sorted(list(current_sources))
    data['version'] = '5.1.0'
    
    with open(intel_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ 情报已更新: {intel_path}")
    print(f"   总 IOC 数: {len(merged_iocs)} 条")


if __name__ == '__main__':
    main()
