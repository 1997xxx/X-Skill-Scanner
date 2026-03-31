#!/usr/bin/env python3
"""
威胁情报更新脚本 v3.1
从多个来源获取最新恶意技能情报并更新本地数据库

Sources:
- Koi.ai ClawHavoc Report (341 malicious skills)
- Snyk ToxicSkills Campaign Analysis  
- PiedPiper0709/openclaw-malicious-skills
- GitHub Issue IOC Lists
- SkillJect Attack Pattern Analysis
"""

import json
import csv
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict


def parse_csv_intel(csv_path):
    """解析 CSV 格式的情报数据"""
    skills = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            skills.append({
                'name': row.get('skill_name', '').strip(),
                'source': row.get('source', '').strip(),
                'author': row.get('author', '').strip(),
                'risk_category': row.get('risk_category', '').strip(),
                'severity': row.get('severity', '').strip(),
                'confidence': int(row.get('confidence', 0)),
            })
    return skills


def build_intelligence_database():
    """构建完整的威胁情报数据库"""
    
    # Known malicious skill names from multiple sources
    known_malicious = {
        # ClawHub Typosquats (伪装官方 ClawHub)
        'clawhub', 'clawhub1', 'clawhubb', 'clawhubcli', 'clawhud', 'clawwhub', 'cllawhub',
        'clawhub-6yr3b', 'clawhub-c9y4p', 'clawhub-d4kxr', 'clawhub-f3qcn', 'clawhub-gpcrq',
        'clawhub-gstca', 'clawhub-hh1fd', 'clawhub-hh2km', 'clawhub-hylhq', 'clawhub-i7oci',
        'clawhub-i9zhz', 'clawhub-ja7eh', 'clawhub-krmvq', 'clawhub-oihpl', 'clawhub-olgys',
        'clawhub-osasg', 'clawhub-rkvny', 'clawhub-sxtsn', 'clawhub-tlxx5', 'clawhub-uoeym',
        'clawhub-wixce', 'clawhub-wotp2', 'clawdhub1',
        
        # Auto-Updaters (伪装更新器)
        'auto-updater', 'auto-updater-161ks', 'auto-updater-2yq87', 'auto-updater-3rk1s',
        'auto-updater-5buwl', 'auto-updater-5fhqm', 'auto-updater-8xwp6', 'auto-updater-deza8',
        'auto-updater-dzuba', 'auto-updater-e89da', 'auto-updater-eclpb', 'auto-updater-gw6f5',
        'auto-updater-hfmct', 'auto-updater-jkiuq', 'auto-updater-lth9t', 'auto-updater-m0fsa',
        'auto-updater-mclql', 'auto-updater-mkukz', 'auto-updater-mn5ri', 'auto-updater-nlt3m',
        'auto-updater-ocn18', 'auto-updater-p5rmt', 'auto-updater-qdyme', 'auto-updater-se38e',
        'auto-updater-sxdg2', 'auto-updater-xcgnm', 'auto-updater-xsunp', 'update', 'updater',
        
        # Polymarket Impersonators (伪装交易工具)
        'poly', 'polym', 'polymarket', 'polymarkets', 'polytrading',
        'polymarket-25nwy', 'polymarket-33efn', 'polymarket-4rrsh', 'polymarket-5dylt',
        'polymarket-6ehca', 'polymarket-7ceau', 'polymarket-all-in-one', 'polymarket-bpnyq',
        'polymarket-cexex', 'polymarket-dfknh', 'polymarket-esfbk', 'polymarket-fpwui',
        'polymarket-gxyrz', 'polymarket-hoedg', 'polymarket-ik168', 'polymarket-jezc4',
        'polymarket-juui0', 'polymarket-lzgm8', 'polymarket-mjjsc', 'polymarket-phqtc',
        'polymarket-qjypn', 'polymarket-qpi7w', 'polymarket-qxjyy', 'polymarket-s7x4d',
        'polymarket-traiding-bot', 'polymarket-vj5zb', 'polymarket-vx875', 'polymarket-wapbk',
        'polymarket-y0c8k', 'polymarket-z7lwp',
        
        # Wallet Trackers (伪装钱包追踪器)
        'wallet-tracker-0ghsk', 'wallet-tracker-0waih', 'wallet-tracker-8orkd',
        'wallet-tracker-af1i6', 'wallet-tracker-al7er', 'wallet-tracker-auqlh',
        'wallet-tracker-bf3bs', 'wallet-tracker-bqahy', 'wallet-tracker-bs5ur',
        'wallet-tracker-bxb0a', 'wallet-tracker-fntdr', 'wallet-tracker-gel8n',
        'wallet-tracker-hhjpv', 'wallet-tracker-ijyto', 'wallet-tracker-l7dst',
        'wallet-tracker-mgwpt', 'wallet-tracker-oozrx', 'wallet-tracker-pbckx',
        'wallet-tracker-qoa9k', 'wallet-tracker-rcoux', 'wallet-tracker-s5hx9',
        'wallet-tracker-udqiq', 'wallet-tracker-ue8hv', 'wallet-tracker-x76ik',
        'wallet-tracker-zih4w',
        
        # Phantom Wallet Clones (伪装 Phantom 钱包)
        'phantom', 'phantom-0jcvy', 'phantom-0snsv', 'phantom-3uttg', 'phantom-64juz',
        'phantom-afnuz', 'phantom-ahdwb', 'phantom-bdacv', 'phantom-fdjtg', 'phantom-fsvib',
        'phantom-ftbrg', 'phantom-fvizs', 'phantom-ggjrq', 'phantom-hpwmb', 'phantom-iebcc',
        'phantom-jwik3', 'phantom-kxcuj', 'phantom-lpnfp', 'phantom-lxnyf', 'phantom-mdr3q',
        'phantom-nrqdw', 'phantom-pcue3', 'phantom-pvber', 'phantom-q8ark', 'phantom-qs450',
        'phantom-syjqj', 'phantom-vpnfy', 'phantom-vwlfb', 'phantom-xivjh', 'phantom-ygmjc',
        
        # Google Workspace Fakes (伪装 Google 集成)
        'google-workspace', 'google-workspace-2z5dp', 'google-workspace-7ylf0',
        'google-workspace-8zdgy', 'google-workspace-auqud', 'google-workspace-devfw',
        'google-workspace-gbvyc', 'google-workspace-izypr', 'google-workspace-m2hcx',
        'google-workspace-ndlt1', 'google-workspace-ozgdc', 'google-workspace-t9lkr',
        'google-workspace-tqhmn', 'google-workspace-womvg', 'google-workspace-wwxem',
        'google-workspace-yj9ug', 'google-workspace-ytrqj', 'google-workspace-zg8ad',
        'google-qx4',
        
        # YouTube Summarize Clones (伪装 YouTube 摘要)
        'youtube-summarize', 'youtube-summarize-11y0i', 'youtube-summarize-35o20',
        'youtube-summarize-3luwa', 'youtube-summarize-5oixh', 'youtube-summarize-7vnwu',
        'youtube-summarize-8edua', 'youtube-summarize-beqh9', 'youtube-summarize-ebw5x',
        'youtube-summarize-gctcr', 'youtube-summarize-genms', 'youtube-summarize-hr5oh',
        'youtube-summarize-iagv2', 'youtube-summarize-ib7el', 'youtube-summarize-ietsw',
        'youtube-summarize-k67rk', 'youtube-summarize-kodxd', 'youtube-summarize-l4hjv',
        'youtube-summarize-l8nmj', 'youtube-summarize-lh9rq',
        
        # Yahoo Finance Fakes (伪装金融行情)
        'yahoo-finance', 'yahoo-finance-1h2ji', 'yahoo-finance-2s8cv', 'yahoo-finance-55ykj',
        'yahoo-finance-5fhu3', 'yahoo-finance-6icpt', 'yahoo-finance-7txap', 'yahoo-finance-bzrvt',
        'yahoo-finance-cv8ev', 'yahoo-finance-eqosk', 'yahoo-finance-ijybk', 'yahoo-finance-jdlqs',
        'yahoo-finance-jzgua', 'yahoo-finance-kmhxs', 'yahoo-finance-m16op', 'yahoo-finance-mb9wu',
        'yahoo-finance-mz1nt', 'yahoo-finance-om4g4', 'yahoo-finance-saosh', 'yahoo-finance-tqxkb',
        'yahoo-finance-uelhr', 'yahoo-finance-w3wo2', 'yahoo-finance-wcr6j', 'yahoo-finance-y7mbx',
        'yahoo-finance-ztbyq',
        
        # X/Twitter Trends Fakes (伪装社交趋势分析)
        'x-trends', 'x-trends-0heof', 'x-trends-9y6gc', 'x-trends-axy84', 'x-trends-bjcps',
        'x-trends-cpif3', 'x-trends-dijrb', 'x-trends-el5qn', 'x-trends-hloqe', 'x-trends-kujtp',
        'x-trends-ky4xt', 'x-trends-kzcxt', 'x-trends-mtzmi', 'x-trends-ngw4s', 'x-trends-nvdfx',
        'x-trends-orwhp', 'x-trends-ovdpf', 'x-trends-p7ivk', 'x-trends-qfpkj', 'x-trends-qhz9c',
        'x-trends-qpaoo', 'x-trends-qylxo', 'x-trends-rjmtk', 'x-trends-rwskq', 'x-trends-wbc5p',
        'x-trends-ypqjp',
        
        # Solana Wallet Trackers (伪装 Solana 钱包跟踪)
        'solana-wallet-tracker', 'solana-wallet-tracker-0bbn7', 'solana-wallet-tracker-1nqgh',
        'solana-wallet-tracker-2ae1q', 'solana-wallet-tracker-3bkif', 'solana-wallet-tracker-3itwx',
        'solana-wallet-tracker-4dc9g', 'solana-wallet-tracker-4utfp', 'solana-wallet-tracker-52k37',
        'solana-wallet-tracker-5jlwm', 'solana-wallet-tracker-6a9zc', 'solana-wallet-tracker-6rn7o',
        'solana-wallet-tracker-7mi7t', 'solana-wallet-tracker-8gc1n', 'solana-wallet-tracker-8lxw9',
        'solana-wallet-tracker-8m7no', 'solana-wallet-tracker-acx63', 'solana-wallet-tracker-ej5ot',
        'solana-wallet-tracker-fqpsi', 'solana-wallet-tracker-fshmi', 'solana-wallet-tracker-gw9xj',
        'solana-wallet-tracker-hqrui', 'solana-wallet-tracker-jc8up', 'solana-wallet-tracker-jz1xh',
        'solana-wallet-tracker-k8nnu', 'solana-wallet-tracker-kclqk', 'solana-wallet-tracker-llrxm',
        'solana-wallet-tracker-p4qef', 'solana-wallet-tracker-qgrkz', 'solana-wallet-tracker-ro6ez',
        'solana-wallet-tracker-ssnw9', 'solana-wallet-tracker-tb5vg', 'solana-wallet-tracker-v4hsw',
        
        # Ethereum Gas Trackers (伪装加密行情)
        'ethereum-gas-tracker', 'ethereum-gas-tracker-abxf0', 'ethereum-gas-tracker-esupl',
        'ethereum-gas-tracker-fygz0', 'ethereum-gas-tracker-gon2c', 'ethereum-gas-tracker-hx8j0',
        'ethereum-gas-tracker-k51pi', 'ethereum-gas-tracker-leifg', 'ethereum-gas-tracker-lm4cv',
        'ethereum-gas-tracker-mnsfw', 'ethereum-gas-tracker-nmcq5', 'ethereum-gas-tracker-pz0kz',
        'ethereum-gas-tracker-qxorv', 'ethereum-gas-tracker-rmiu4', 'ethereum-gas-tracker-t8oaj',
        
        # Insider Wallets Finders (伪装钱包画像)
        'insider-wallets-finder', 'insider-wallets-finder-1a7pi', 'insider-wallets-finder-2fz1g',
        'insider-wallets-finder-57h4t', 'insider-wallets-finder-9dlka', 'insider-wallets-finder-art4q',
        'insider-wallets-finder-btj6c', 'insider-wallets-finder-cv1d9', 'insider-wallets-finder-djiq0',
        'insider-wallets-finder-firui', 'insider-wallets-finder-h5syo', 'insider-wallets-finder-hbmjm',
        'insider-wallets-finder-im29o', 'insider-wallets-finder-jacit', 'insider-wallets-finder-kq9nv',
        'insider-wallets-finder-mk3w3', 'insider-wallets-finder-ngv64', 'insider-wallets-finder-nq6a9',
        'insider-wallets-finder-q9qng', 'insider-wallets-finder-qjkug', 'insider-wallets-finder-r6wya',
        'insider-wallets-finder-tivyf', 'insider-wallets-finder-zah8d', 'insider-wallets-finder-zzs2p',
        
        # Lost Bitcoin Scams (伪装找回比特币)
        'lost-bitcoin', 'lost-bitcoin-10li1', 'lost-bitcoin-dbrgt', 'lost-bitcoin-eabml',
        
        # AuthTool Campaign (凭据窃取)
        'base-agent', 'bybit-agent', 'polymarket-traiding-bot',
        
        # Hidden Backdoors (隐藏后门)
        'better-polymarket', 'polymarket-all-in-one',
        
        # Credential Exfiltration (数据外传)
        'rankaj',
        
        # Other known malicious
        'bird-js', 'deepresearch', 'amir',
        
        # Snyk identified threats
        'coding-agent-1gx', 'whatsapp-mgv', 'moltbook-lm8', 'moltbookagent', 'publish-dist',
    }
    
    # Typosquat patterns for fuzzy matching
    typosquat_patterns = {
        'clawhub', 'clawdhub', 'clawwhub', 'cllawhub', 'clawhud', 'clawhubcli', 'clawhubb', 'clawhub1',
        'auto-updater', 'update', 'updater',
        'polymarket', 'poly', 'polym', 'polymarkets', 'polytrading',
        'phantom', 'wallet-tracker', 'solana-wallet-tracker',
        'ethereum-gas-tracker', 'insider-wallets-finder',
        'lost-bitcoin', 'youtube-summarize', 'yahoo-finance', 'x-trends',
        'google-workspace', 'google',
    }
    
    # Known malicious authors from threat reports
    malicious_authors = [
        'zaycv',           # ClawHavoc campaign author
        'aztr0nutzs',      # Snyk threat actor
        'pepe276',         # Moltbook campaign
        'moonshine-100rze', # Moltbook variant
    ]
    
    # IOC domains and IPs from multiple reports
    ioc_domains = [
        '91.92.242.30',    # Known C2 server (ClawHavoc)
        'glot.io',         # Payload