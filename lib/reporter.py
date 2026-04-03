#!/usr/bin/env python3
"""Report Generator v3.2 - Dedup + Responsive Layout"""
import json, re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from constants import HTML_CSS_BASE
from collections import defaultdict

try:
    from i18n import I18n
except ImportError:
    try:
        from .i18n import I18n
    except ImportError:
        I18n = None


class ReportGenerator:
    def __init__(self, output_format='html', i18n=None):
        self.output_format = output_format
        self.i18n = i18n or (I18n() if I18n else None)

    def generate(self, scan_result, output_path=None):
        fmt = self.output_format
        if fmt == 'json': report = self._gen_json(scan_result)
        elif fmt == 'html': report = self._gen_html(scan_result)
        elif fmt == 'md': report = self._gen_md(scan_result)
        else: report = self._gen_text(scan_result)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
        return report

    @staticmethod
    def _dedup(findings):
        if not findings:
            return []
        groups = defaultdict(list)
        for f in findings:
            d = isinstance(f, dict)
            rid = f.get('rule_id', f.get('title', '')) if d else getattr(f, 'rule_id', '') or getattr(f, 'title', '')
            sev = f.get('severity', '?') if d else getattr(f, 'severity', '?')
            groups[(rid, sev)].append(f)
        merged = []
        for key, grp in groups.items():
            if len(grp) == 1:
                merged.append(grp[0])
                continue
            first = grp[0]
            d = isinstance(first, dict)
            locs = []
            for g in grp:
                fp = g.get('file_path','') if d else getattr(g,'file_path','')
                ln = g.get('line_number') or g.get('line',0) if d else getattr(g,'line_number',None) or getattr(g,'line',0)
                locs.append(f'{fp}:{ln}' if ln else fp)
            ulocs = list(dict.fromkeys(locs))
            cnt = len(ulocs)
            if d:
                desc = re.sub(r':\d+', '', first.get('description',''))
                if cnt > 1:
                    ls = ', '.join(ulocs[:5]) + (f' etc {cnt} locations' if cnt > 5 else '')
                    desc += f'\n\nFound {cnt} times: {ls}'
                merged.append({**first, 'description': desc,
                    'file_path': ulocs[0].split(':')[0] if ':' in ulocs[0] else ulocs[0],
                    'line_number': None, '_merged_count': cnt})
            else:
                desc = re.sub(r':\d+', '', getattr(first,'description',''))
                if cnt > 1:
                    ls = ', '.join(ulocs[:5]) + (f' etc {cnt} locations' if cnt > 5 else '')
                    desc += f'\n\nFound {cnt} times: {ls}'
                merged.append({'severity':getattr(first,'severity','?'),'title':getattr(first,'title',''),
                    'description':desc,'file_path':ulocs[0].split(':')[0] if ':' in ulocs[0] else ulocs[0],
                    'line_number':None,'remediation':getattr(first,'remediation',''),
                    'source':getattr(first,'source',''),'rule_id':getattr(first,'rule_id',''),
                    '_merged_count':cnt})
        return merged

    def _gen_text(self, r):
        """生成增强版文本报告 — 包含攻击手法分析"""
        lines = []
        
        # ─── 头部 ──────────────────────────────────────────────
        lines.append('=' * 70)
        lines.append('🛡️  SKILL SECURITY SCAN REPORT / 技能安全扫描报告')
        lines.append('=' * 70)
        lines.append(f"目标 / Target : {r.get('target','?')}")
        lines.append(f"时间 / Time   : {r.get('scan_time','?')}")
        lines.append(f"文件 / Files  : {r.get('total_files',0)}")
        lines.append(f"版本 / Version: {r.get('scanner_version','3.4.0')}")
        lines.append('-' * 70)
        
        # ─── 风险评级 ──────────────────────────────────────────
        rl = r.get('risk_level','?')
        rs = r.get('risk_score',0)
        vt = r.get('verdict','?')
        fbs = r.get('findings_by_severity', {})
        
        risk_emoji = {'EXTREME': '⛔', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'SAFE': '✅'}
        emoji = risk_emoji.get(rl, '❓')
        lines.append(f"{emoji} 风险等级 / RISK LEVEL : {rl}")
        lines.append(f"📊 风险评分 / RISK SCORE : {rs}/100")
        lines.append(f"🏁 结论     / VERDICT    : {vt}")
        lines.append('-' * 70)
        
        # ─── 按严重等级统计 ────────────────────────────────────
        severity_labels = [
            ('CRITICAL', '🔴 严重'),
            ('HIGH',     '🟠 高危'),
            ('MEDIUM',   '🟡 中危'),
            ('LOW',      '🟢 低危'),
            ('INFO',     'ℹ️  信息'),
        ]
        for sev_key, sev_label in severity_labels:
            count = fbs.get(sev_key, 0)
            if count > 0:
                lines.append(f"  {sev_label}: {count}")
        lines.append('-' * 70)
        
        # ─── 按来源引擎统计 ────────────────────────────────────
        source_map = r.get('findings_by_source', {})
        if source_map:
            source_labels = {
                'threat_intel': '🛡️ 威胁情报',
                'deobfuscation': '🧹 去混淆检测',
                'static_analysis': '🔍 静态分析',
                'ast_analysis': '🌳 AST 分析',
                'dependency_check': '📦 依赖检查',
                'prompt_injection_test': '💉 提示词注入',
                'baseline_check': '📋 基线比对',
                'semantic_audit': '🧠 语义审计',
                'entropy_analysis': '📊 熵值分析',
                'install_hook_detection': '🔧 安装钩子检测',
                'network_profiling': '🌐 网络行为画像',
            }
            lines.append('')
            lines.append('各引擎检出 / Findings by Engine:')
            for src, cnt in sorted(source_map.items(), key=lambda x: -x[1]):
                label = source_labels.get(src, src)
                lines.append(f"  {label}: {cnt}")
            lines.append('-' * 70)
        
        # ─── 攻击手法分析 (新增) ───────────────────────────────
        attack_analysis = self._analyze_attack_patterns(r)
        if attack_analysis:
            lines.append('')
            lines.append('⚠️  检测到的攻击手法 / DETECTED ATTACK PATTERNS')
            lines.append('=' * 70)
            
            # 总体描述
            lines.append('')
            lines.append('该技能包含以下恶意行为模式：')
            lines.append('')
            
            for i, item in enumerate(attack_analysis, 1):
                lines.append(f"【{i}】{item['title']}")
                lines.append(f"    类型 / Type    : {item['type']}")
                lines.append(f"    严重度 / Severity: {item['severity']}")
                lines.append(f"    描述 / Desc    : {item['description']}")
                if item.get('evidence'):
                    lines.append(f"    证据 / Evidence:")
                    for ev_line in item['evidence'].split('\n'):
                        lines.append(f"      {ev_line}")
                if item.get('impact'):
                    lines.append(f"    影响 / Impact  : {item['impact']}")
                lines.append(f"    建议 / Fix     : {item['remediation']}")
                lines.append('')
            
            lines.append('-' * 70)
        
        # ─── 各层检测结果 ──────────────────────────────────────
        lines.append('')
        lines.append('📊 各层检测结果 / LAYER-BY-LAYER RESULTS')
        lines.append('=' * 70)
        
        layer_labels = {
            'deobfuscation': ('🧹 去混淆', 'Deobfuscation'),
            'static_analysis': ('🔍 静态分析', 'Static Analysis'),
            'ast_analysis': ('🌳 AST 分析', 'AST Analysis'),
            'semantic_audit': ('🧠 语义审计', 'Semantic Audit'),
            'entropy_analysis': ('📊 熵值分析', 'Entropy Analysis'),
            'install_hook_detection': ('🔧 安装钩子', 'Install Hooks'),
            'network_profiling': ('🌐 网络画像', 'Network Profiling'),
            'threat_intel': ('🛡️ 威胁情报', 'Threat Intel'),
            'credential_theft_detection': ('🔐 凭证窃取检测', 'Credential Theft'),
            'correlation_engine': ('🔗 关联分析', 'Correlation Engine'),
            'dependency_check': ('📦 依赖检查', 'Dependencies'),
            'prompt_injection_test': ('💉 注入探针', 'Injection Test'),
            'baseline_check': ('📋 基线比对', 'Baseline Check'),
        }
        
        layer_order = ['deobfuscation', 'static_analysis', 'ast_analysis', 
                       'semantic_audit', 'entropy_analysis', 
                       'install_hook_detection', 'network_profiling',
                       'threat_intel', 'credential_theft_detection', 
                       'correlation_engine']
        
        for src_key in layer_order:
            label_cn, label_en = layer_labels.get(src_key, (src_key, src_key))
            cnt = source_map.get(src_key, 0) if source_map else 0
            if cnt > 0:
                status = f'⚠️  {cnt} 个问题'
            else:
                status = '✅ 正常'
            lines.append(f"  {label_cn}: {status}")
        
        lines.append('-' * 70)
        
        # ─── 详细发现列表 ──────────────────────────────────────
        deduped = self._dedup(r.get('findings', []))
        so = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sf = sorted(deduped, key=lambda f: so.get(
            f.get('severity', 'INFO') if isinstance(f, dict) else getattr(f, 'severity', 'INFO'), 5))
        
        if sf:
            lines.append('')
            lines.append(f'📋 详细发现 / DETAILED FINDINGS ({len(sf)} unique)')
            lines.append('-' * 70)
            
            for i, f in enumerate(sf, 1):
                d = isinstance(f, dict)
                sev = f.get('severity', '?') if d else getattr(f, 'severity', '?')
                ttl = f.get('title', '?') if d else getattr(f, 'title', '?')
                fp = f.get('file_path', '') if d else getattr(f, 'file_path', '')
                ln = f.get('line_number') or f.get('line', 0) if d else getattr(f, 'line_number', None) or getattr(f, 'line', 0)
                desc = f.get('description', '') if d else getattr(f, 'description', '')
                rem = f.get('remediation', '') if d else getattr(f, 'remediation', '')
                src = f.get('source', '') if d else getattr(f, 'source', '')
                mc = f.get('_merged_count', 1) if d else getattr(f, '_merged_count', 1)
                
                loc = f'{fp}:{ln}' if ln else fp
                badge = f' (x{mc})' if mc > 1 else ''
                cs = f.get('code_snippet', '') if d else getattr(f, 'code_snippet', '')
                
                lines.append(f'')
                lines.append(f'  #{i}. [{sev}] {ttl}{badge}')
                lines.append(f'      位置 / Location: {loc}')
                lines.append(f'      来源 / Source  : {src}')
                
                # 格式化描述（保留结构化格式，去除 markdown 代码块）
                clean_desc = re.sub(r'```\n?(.*?)\n?```', r'[CODE BLOCK: \1]', desc, flags=re.DOTALL)
                # 将换行符转换为缩进换行，保持可读性
                formatted_lines = []
                for dline in clean_desc.split('\n'):
                    dline = dline.strip()
                    if dline:
                        if len(dline) > 180:
                            dline = dline[:180] + '...'
                        formatted_lines.append(f'      {dline}')
                
                if formatted_lines:
                    lines.append('      描述 / Desc:')
                    lines.extend(formatted_lines)
                
                # 代码片段
                if cs:
                    lines.append('      代码 / Code:')
                    for cline in cs.strip().split('\n'):
                        lines.append(f'      │ {cline}')
                
                lines.append(f'      修复 / Fix     : {rem}')
        
        # ─── 综合总结 ──────────────────────────────────────────
        lines.append('')
        lines.append('=' * 70)
        
        # 扫描完成状态
        if 'DO NOT INSTALL' in vt or rl in ('EXTREME', 'HIGH'):
            lines.append(f"⛔ 扫描完成 — 禁止安装")
        elif 'CAUTION' in vt or rl == 'MEDIUM':
            lines.append(f"⚠️  扫描完成 — 建议审查后安装")
        else:
            lines.append(f"✅ 扫描完成 — 可安全安装")
        lines.append('')
        
        # 指标表格
        total_findings = r.get('total_findings', 0)
        crit_count = fbs.get('CRITICAL', 0)
        high_count = fbs.get('HIGH', 0)
        med_count = fbs.get('MEDIUM', 0)
        low_count = fbs.get('LOW', 0)
        
        lines.append(f"{'指标':<15} {'结果'}")
        lines.append('-' * 40)
        lines.append(f"{'风险等级':<15} {emoji} {rl}")
        lines.append(f"{'风险分数':<15} {rs}/100")
        lines.append(f"{'安全问题':<15} {total_findings} 个（{crit_count} CRITICAL + {high_count} HIGH + {med_count} MEDIUM + {low_count} LOW）")
        lines.append(f"{'结论':<15} {vt}")
        lines.append('')
        lines.append('=' * 70)
        
        return '\n'.join(lines)

    def _analyze_attack_patterns(self, r: Dict) -> List[Dict]:
        """
        基于扫描结果自动分析攻击手法
        
        参考 ClawGuard Auditor 的攻击链重构能力，将离散的发现项
        整合为结构化的攻击手法分析报告。
        """
        findings = r.get('findings', [])
        if not findings:
            return []
        
        attacks = []
        content_raw = ''  # 收集原始内容用于分析
        
        for f in findings:
            if not isinstance(f, dict):
                continue
            desc = f.get('description', '') or ''
            title = f.get('title', '') or ''
            src = f.get('source', '')
            cat = f.get('category', '')
            sev = f.get('severity', '')
            content_raw += f"{title} | {desc}\n"
        
        # ─── 模式 1: 远程代码执行链 ────────────────────────────
        rce_indicators = [
            ('curl', 'bash', 'pipe'), ('wget', 'sh', 'pipe'),
            ('base64', 'decode', 'exec'), ('eval', 'exec', 'direct'),
            ('91.92.242', '', 'ip_literal'), ('glot.io', '', 'staging_domain'),
            ('rentry.co', '', 'staging_domain'),
        ]
        
        rce_matches = []
        for kw1, kw2, rce_type in rce_indicators:
            if kw1.lower() in content_raw.lower() and (not kw2 or kw2.lower() in content_raw.lower()):
                rce_matches.append(rce_type)
        
        if len(rce_matches) >= 2:
            # 提取证据行
            evidence_lines = []
            for f in findings:
                if not isinstance(f, dict):
                    continue
                desc = f.get('description', '')
                if any(kw in desc.lower() for kw in ['curl', 'wget', 'base64', 'bash', '91.92.242']):
                    fp = f.get('file_path', '')
                    ln = f.get('line_number', 0)
                    evidence_lines.append(f"[{fp}:{ln}] {f.get('title', '')}")
            
            attacks.append({
                'title': '远程代码执行 (Remote Code Execution)',
                'type': 'RCE Chain',
                'severity': 'CRITICAL',
                'description': (
                    f'检测到完整的远程代码执行攻击链。'
                    f'攻击者通过编码/管道技术从外部服务器下载并执行恶意代码。'
                    f'匹配模式: {", ".join(set(rce_matches))}'
                ),
                'evidence': '\n'.join(evidence_lines[:5]) if evidence_lines else 'N/A',
                'impact': '攻击者可在受害者机器上执行任意命令，完全控制系统',
                'remediation': '禁止安装此技能，阻断与可疑域名的所有通信',
            })
        
        # ─── 模式 2: 凭证窃取 ──────────────────────────────────
        cred_keywords = ['password', 'credential', '.env', 'token', 'secret', 'api_key', 'login']
        cred_matches = sum(1 for kw in cred_keywords if kw.lower() in content_raw.lower())
        
        if cred_matches >= 2:
            evidence_lines = []
            for f in findings:
                if not isinstance(f, dict):
                    continue
                desc = f.get('description', '')
                if any(kw in desc.lower() for kw in cred_keywords):
                    evidence_lines.append(f"[{f.get('file_path', '')}:{f.get('line_number', 0)}] {f.get('title', '')}")
            
            attacks.append({
                'title': '凭证窃取 (Credential Harvesting)',
                'type': 'Data Theft',
                'severity': 'CRITICAL',
                'description': (
                    f'检测到凭证收集行为。技能要求或尝试获取用户的敏感认证信息，'
                    f'包括密码、API 密钥、Token 等。'
                ),
                'evidence': '\n'.join(evidence_lines[:5]) if evidence_lines else 'N/A',
                'impact': '用户凭证可能被发送到攻击者控制的服务器',
                'remediation': '不要在此技能中输入任何真实凭证，使用临时/测试账号',
            })
        
        # ─── 模式 3: 社会工程学 ────────────────────────────────
        se_keywords = ['download', 'extract', 'password:', 'run this', 'critical', 
                       'before using', 'will not work', 'apple', 'cdn', 'update']
        se_matches = sum(1 for kw in se_keywords if kw.lower() in content_raw.lower())
        
        if se_matches >= 3:
            attacks.append({
                'title': '社会工程学 (Social Engineering)',
                'type': 'Psychological Manipulation',
                'severity': 'HIGH',
                'description': (
                    f'检测到社会工程学手法。技能使用紧迫性话术、权威伪装（如伪造 Apple CDN）、'
                    f'或强制性指令诱导用户执行危险操作。'
                ),
                'evidence': f'匹配关键词: {", ".join(kw for kw in se_keywords if kw.lower() in content_raw.lower())}',
                'impact': '用户可能被诱导执行恶意命令或下载木马程序',
                'remediation': '仔细审查所有要求用户手动执行的命令，不要盲目复制粘贴',
            })
        
        # ─── 模式 4: 数据外传 ──────────────────────────────────
        exfil_keywords = ['exfil', 'send', 'upload', 'post', 'transmit', 'external', 'requests.post']
        exfil_matches = sum(1 for kw in exfil_keywords if kw.lower() in content_raw.lower())
        
        if exfil_matches >= 2:
            attacks.append({
                'title': '数据外传 (Data Exfiltration)',
                'type': 'Data Leakage',
                'severity': 'CRITICAL',
                'description': (
                    f'检测到向外部服务器传输数据的行为。'
                    f'技能可能将用户数据、系统信息或凭证发送到攻击者控制的端点。'
                ),
                'evidence': f'匹配模式: {", ".join(kw for kw in exfil_keywords if kw.lower() in content_raw.lower())}',
                'impact': '敏感数据可能被泄露到外部服务器',
                'remediation': '审查所有网络请求的目标地址和传输内容',
            })
        
        # ─── 模式 5: 持久化/后门 ───────────────────────────────
        persist_keywords = ['crontab', 'bashrc', 'zshrc', 'profile', 'launchctl', 
                           'systemctl', 'persistence', 'backdoor', 'reverse shell']
        persist_matches = sum(1 for kw in persist_keywords if kw.lower() in content_raw.lower())
        
        if persist_matches >= 1:
            attacks.append({
                'title': '持久化/后门 (Persistence / Backdoor)',
                'type': 'System Persistence',
                'severity': 'CRITICAL',
                'description': (
                    f'检测到系统持久化或后门行为。'
                    f'技能尝试在系统中建立持久访问机制，确保即使重启后仍能继续执行恶意操作。'
                ),
                'evidence': f'匹配模式: {", ".join(kw for kw in persist_keywords if kw.lower() in content_raw.lower())}',
                'impact': '系统可能被长期控制，难以彻底清除',
                'remediation': '立即隔离受影响的系统，检查所有启动项和定时任务',
            })
        
        # ─── 模式 6: 恶意作者/已知威胁 ─────────────────────────
        threat_findings = [f for f in findings if isinstance(f, dict) and f.get('source') == 'threat_intel']
        if threat_findings:
            ti_titles = [f.get('title', '') for f in threat_findings]
            attacks.append({
                'title': '已知威胁情报匹配 (Threat Intelligence Match)',
                'type': 'Known Threat',
                'severity': 'CRITICAL',
                'description': (
                    f'技能或作者匹配已知威胁情报数据库。'
                    f'这表明该技能属于已确认的恶意软件家族或攻击活动。'
                ),
                'evidence': '\n'.join(ti_titles[:5]),
                'impact': '此技能已被安全社区确认为恶意软件',
                'remediation': '立即删除，报告给安全团队和相关平台',
            })
        
        return attacks

    def _gen_json(self, r):
        return json.dumps(r, indent=2, ensure_ascii=False)

    def _esc(self, text):
        return (str(text).replace('&','&amp;').replace('<','&lt;')
                .replace('>','&gt;').replace('"','&quot;'))

    def _render_desc(self, desc):
        if not desc or desc == 'N/A':
            return ''
        safe = self._esc(desc)
        parts = []
        last = 0
        for m in re.finditer(r'```\n?(.*?)\n?```', safe, re.DOTALL):
            before = safe[last:m.start()]
            if before.strip():
                parts.append(f'<div class="ds">{before.strip()}</div>')
            parts.append(f'<pre class="cb"><code>{m.group(1).strip()}</code></pre>')
            last = m.end()
        rem = safe[last:]
        if rem.strip():
            parts.append(f'<div class="ds">{rem.strip()}</div>')
        return ''.join(parts)

    def _gen_html(self, r):
        rl = r.get('risk_level','UNKNOWN')
        rc = rl.lower()
        rs = r.get('risk_score',0)
        fbs = r.get('findings_by_severity',{})
        parts = []
        for s,lbl,clr in [('CRITICAL','严重 Critical','#dc3545'),('HIGH','高危 High','#fd7e14'),
                          ('MEDIUM','中危 Medium','#ffc107'),('LOW','低危 Low','#28a745')]:
            c = fbs.get(s,0)
            if c:
                parts.append(f'<b style="color:{clr}">{c} {lbl} ({s})</b>')
        summary = f'共发现 <b>{r.get("total_findings",0)}</b> 个安全问题 / Total <b>{r.get("total_findings",0)}</b> issues found.'
        if parts:
            summary += ' 其中 / Including: '+'、'.join(parts)+'.'
        vt = r.get('verdict','')
        if 'DO NOT INSTALL' in vt:
            summary += ' 禁止安装此技能 / Do not install.'
        elif 'CAUTION' in vt:
            summary += ' 建议审查后安装 / Review before installing.'
        else:
            summary += ' 可安全安装 / Safe to install.'

        deduped = self._dedup(r.get('findings',[]))
        so = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
        sf = sorted(deduped, key=lambda f: so.get(
            f.get('severity','INFO') if isinstance(f,dict) else getattr(f,'severity','INFO'),5))

        sl = {'threat_intel':'🛡️ 威胁情报 / Threat Intel','static_analysis':'🔍 静态分析 / Static Analysis',
              'deobfuscation':'🧹 去混淆 / Deobfuscation','ast_analysis':'🌳 AST 分析 / AST Analysis',
              'dependency_check':'📦 依赖检查 / Dependencies','baseline_check':'📋 基线比对 / Baseline',
              'prompt_injection_test':'💉 注入探针 / Injection Test','semantic_audit':'🧠 语义审计 / Semantic Audit',
              'install_hook_detection':'🔧 安装钩子 / Install Hooks','network_profiling':'🌐 网络画像 / Network Profiling'}

        source_map = r.get('findings_by_source', {})

        # Build rows grouped by source with section anchors for jump links
        src_findings = defaultdict(list)
        for f in sf:
            d = isinstance(f, dict)
            src = f.get('source','') if d else getattr(f,'source','')
            src_findings[src].append(f)

        rows = ''
        for src_key, findings in src_findings.items():
            slabel = sl.get(src_key, src_key)
            rows += '<tr class="src-hdr" id="sec-'+src_key+'"><td colspan="4">'+slabel+'</td></tr>\n'
            for f in findings:
                d = isinstance(f, dict)
                sev = f.get('severity','?') if d else getattr(f,'severity','?')
                ttl = f.get('title','?') if d else getattr(f,'title','?')
                desc = f.get('description','') if d else getattr(f,'description','')
                fp = f.get('file_path','') if d else getattr(f,'file_path','')
                ln = f.get('line_number') or f.get('line',0) if d else getattr(f,'line_number',None) or getattr(f,'line',0)
                rem = f.get('remediation','') if d else getattr(f,'remediation','')
                mc = f.get('_merged_count',1) if d else getattr(f,'_merged_count',1)
                loc = f'{fp}:{ln}' if ln else fp
                badge = f' <span class="mbadge">x{mc}</span>' if mc > 1 else ''
                cs = f.get('code_snippet','') if d else getattr(f,'code_snippet','')
                hdesc = self._render_desc(desc)
                cblock = ''
                if cs:
                    cblock = '<pre class="cb"><code>'+self._esc(cs.strip())+'</code></pre>'
                rows += '<tr><td class="cs"><span class="s-'+sev.lower()+'">'+sev+'</span></td>'
                rows += '<td class="ci"><b>'+self._esc(ttl)+'</b>'+badge+hdesc+cblock+'</td>'
                rows += '<td class="cl"><code>'+self._esc(loc)+'</code><br><small>'+slabel+'</small></td>'
                rows += '<td class="cr">'+self._esc(rem)+'</td></tr>\n'

        vc = 'safe' if 'SAFE' in vt else ('caution' if 'CAUTION' in vt else 'danger')
        bc = 'ext' if rc == 'extreme' else rc

        css = HTML_CSS_BASE.strip()

        sev_rows = ''
        for s, c in fbs.items():
            sev_rows += '<tr><td>'+s+'</td><td>'+str(c)+'</td></tr>'

        html = '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>\n'
        html += '<meta charset="UTF-8">\n'
        html += '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        html += '<title>Skill Security Report</title>\n'
        html += '<style>\n' + css + '\n</style>\n'
        html += '</head>\n<body>\n<a id="top"></a>\n<div class="ctn">\n'
        html += '<h1>&#x1F50D; 技能安全扫描报告<br><small style="font-size:14px;color:#666">Skill Security Scan Report</small></h1>\n'
        html += '<div class="meta">\n'
        html += '<p><strong>目标 / Target:</strong> '+self._esc(r.get('target','?'))+'</p>\n'
        html += '<p><strong>扫描时间 / Scan Time:</strong> '+str(r.get('scan_time','?'))+'</p>\n'
        html += '</div>\n'
        html += '<div class="sts">\n'
        html += '<div class="st"><div class="sv">'+str(r.get('total_files',0))+'</div>'
        html += '<div class="sl">审查文件 / Files</div></div>\n'
        html += '<div class="st"><div class="sv">'+str(len(sf))+'</div>'
        html += '<div class="sl">唯一发现 / Unique</div></div>\n'
        html += '<div class="st"><div class="sv">'+str(r.get('total_findings',0))+'</div>'
        html += '<div class="sl">问题总数 / Total</div></div>\n'
        html += '<div class="st"><div class="sv">'+str(r.get('risk_score',0))+'</div>'
        html += '<div class="sl">风险评分 / Score</div></div>\n'
        html += '</div>\n'
        html += '<div class="bg b'+bc+'">'+rl+'</div>\n'
        html += '<div class="vd v'+vc+'">'+self._esc(vt)+'</div>\n'

        # ─── Summary 综合总结区块 ──────────────────────────────
        crit_count = fbs.get('CRITICAL',0)
        high_count = fbs.get('HIGH',0)
        med_count = fbs.get('MEDIUM',0)
        low_count = fbs.get('LOW',0)
        total_findings = r.get('total_findings',0)
        
        if 'DO NOT INSTALL' in vt or rl in ('EXTREME','HIGH'):
            summary_header = '&#x26D4; 扫描完成 — 禁止安装 / Scan Complete — DO NOT INSTALL'
            summary_bg = '#f8d7da'
            summary_color = '#721c24'
        elif 'CAUTION' in vt or rl == 'MEDIUM':
            summary_header = '&#x26A0;&#xFE0F; 扫描完成 — 建议审查后安装 / Scan Complete — Review Before Installing'
            summary_bg = '#fff3cd'
            summary_color = '#856404'
        else:
            summary_header = '&#x2705; 扫描完成 — 可安全安装 / Scan Complete — Safe to Install'
            summary_bg = '#d4edda'
            summary_color = '#155724'
        
        html += '<div class="sumbox" style="background:'+summary_bg+';color:'+summary_color+';padding:20px;border-radius:8px;margin-top:20px">\n'
        html += '<h3 style="margin:0 0 16px;color:'+summary_color+'">'+summary_header+'</h3>\n'
        html += '<div class="sumrow"><span class="sumlbl">风险等级 / Risk Level</span><span>'+rl+'</span></div>\n'
        html += '<div class="sumrow"><span class="sumlbl">风险分数 / Risk Score</span><span>'+str(rs)+'/100</span></div>\n'
        html += '<div class="sumrow"><span class="sumlbl">安全问题 / Security Issues</span><span>'+str(total_findings)+' 个（'+str(crit_count)+' CRITICAL + '+str(high_count)+' HIGH + '+str(med_count)+' MEDIUM + '+str(low_count)+' LOW）</span></div>\n'
        html += '<div class="sumrow"><span class="sumlbl">结论 / Verdict</span><span>'+self._esc(vt)+'</span></div>\n'
        html += '</div>\n'
        
        # ─── Decoded Malicious Payloads (for HIGH/EXTREME risks) ──────────────
        if rl in ('EXTREME', 'HIGH'):
            raw_payloads = []
            for f in r.get('findings', []):
                dc = f.get('decoded_content') or ''
                # Collect decoded content from deobfuscation findings
                if dc.strip() and f.get('source') == 'deobfuscation':
                    raw_payloads.append({
                        'content': dc[:800],
                        'file': f.get('file_path', ''),
                        'line': f.get('line_number', 0),
                        'technique': f.get('rule_id', ''),
                    })
            
            # v5.1: Deduplicate — keep only complete payloads, drop fragments
            # A fragment is either too short (<30 chars) or is a substring of another payload
            decoded_payloads = []
            seen_contents = set()
            for dp in raw_payloads:
                c = dp['content'].strip()
                # Skip very short fragments
                if len(c) < 30:
                    continue
                # Skip if this content is already covered by a longer payload we've seen
                if any(c in existing for existing in seen_contents):
                    continue
                # Skip if a longer version of this content will come later — 
                # instead, replace any existing shorter versions that are substrings of this one
                seen_contents = {s for s in seen_contents if s not in c}
                seen_contents.add(c)
                decoded_payloads.append(dp)
            
            if decoded_payloads:
                html += '<h2 style="color:#dc3545;margin-top:24px">&#x1F6A8; 解码后的恶意载荷 / Decoded Malicious Payloads</h2>\n'
                html += '<div style="background:#fff3cd;border-left:4px solid #dc3545;padding:16px;border-radius:6px">\n'
                html += '<p style="margin:0 0 12px;color:#856404;font-weight:600">&#x26A0;&#xFE0F; 以下是扫描器从混淆代码中还原出的真实内容 — 这是判断技能是否恶意的最关键证据。</p>\n'
                for i, dp in enumerate(decoded_payloads, 1):
                    html += f'<div style="margin-bottom:12px">\n'
                    html += f'<strong>载荷 #{i}</strong> — {self._esc(dp["file"])}:{dp["line"]} [{self._esc(dp["technique"])}]\n'
                    html += f'<pre style="background:#1a1a2e;color:#e9456e;padding:12px;border-radius:4px;overflow-x:auto;margin:6px 0;font-size:13px">{self._esc(dp["content"])}</pre>\n'
                    html += f'</div>\n'
                html += '</div>\n'
        
        # ─── 各层检测结果 ──────────────────────────────────────
        layer_labels = {
            'deobfuscation': ('&#x1F9F9; 去混淆','Deobfuscation'),
            'static_analysis': ('&#x1F50E; 静态分析','Static Analysis'),
            'ast_analysis': ('&#x1F333; AST 分析','AST Analysis'),
            'semantic_audit': ('&#x1F9E0; 语义审计','Semantic Audit'),
            'entropy_analysis': ('&#x1F4CA; 熵值分析','Entropy Analysis'),
            'install_hook_detection': ('&#x1F527; 安装钩子','Install Hooks'),
            'network_profiling': ('&#x1F310; 网络画像','Network Profiling'),
            'threat_intel': ('&#x1F6E1;&#xFE0F; 威胁情报','Threat Intel'),
            'credential_theft_detection': ('&#x1F510; 凭证窃取检测','Credential Theft'),
            'correlation_engine': ('&#x1F517; 关联分析','Correlation Engine'),
        }
        
        layer_order = ['deobfuscation','static_analysis','ast_analysis','semantic_audit',
                       'entropy_analysis','install_hook_detection','network_profiling',
                       'threat_intel','credential_theft_detection','correlation_engine']
        
        html += '<h2>&#x1F4CA; 各层检测结果 / Layer-by-Layer Results</h2>\n'
        html += '<table>\n<tr><th>防御层 / Layer</th><th>结果 / Result</th></tr>\n'
        for src_key in layer_order:
            label_cn, label_en = layer_labels.get(src_key, (src_key, src_key))
            cnt = source_map.get(src_key, 0) if source_map else 0
            if cnt > 0:
                status = '&#x26A0;&#xFE0F; '+str(cnt)+' 个问题 / '+str(cnt)+' issues'
                row_color = '#dc3545'
                href = '#sec-'+src_key
                cls = 'layer-row clickable'
            else:
                status = '&#x2705; 正常 / Clean'
                row_color = '#28a745'
                href = ''
                cls = 'layer-row'
            if href:
                html += '<tr class="'+cls+'"><td>'+label_cn+'</td><td style="color:'+row_color+';font-weight:600"><a href="'+href+'" style="color:'+row_color+';text-decoration:none;font-weight:600">'+status+'</a></td></tr>\n'
            else:
                html += '<tr class="'+cls+'"><td>'+label_cn+'</td><td style="color:'+row_color+';font-weight:600">'+status+'</td></tr>\n'
        html += '</table>\n'

        # ─── 按严重等级统计 ────────────────────────────────────
        html += '<h2>按严重等级统计 / Findings by Severity</h2>\n'
        html += '<table>\n<tr><th>等级 / Severity</th><th>数量 / Count</th></tr>\n'
        html += sev_rows + '\n</table>\n'

        # ─── 攻击手法分析 (v3.3+) ─────────────────────────────
        aa = self._analyze_attack_patterns(r)
        if aa:
            html += '<h2>&#x26A0;&#xFE0F; 攻击手法分析 / Attack Pattern Analysis</h2>\n'
            for item in aa:
                sev_color = {'CRITICAL':'#dc3545','HIGH':'#fd7e14','MEDIUM':'#ffc107'}.get(item.get('severity','#6c757d'))
                html += '<div style="background:#fff;border-left:4px solid '+sev_color+';padding:16px;margin:12px 0;border-radius:0 8px 8px 0;box-shadow:0 1px 4px rgba(0,0,0,.06)">\n'
                html += '<h3 style="margin:0 0 8px;color:'+sev_color+'">'+self._esc(item['title'])+'</h3>\n'
                html += '<p style="margin:4px 0;font-size:13px"><b>Type:</b> '+self._esc(item['type'])+' | <b>Severity:</b> <span style="color:'+sev_color+';font-weight:700">'+item['severity']+'</span></p>\n'
                html += '<p style="margin:4px 0;font-size:14px">'+self._esc(item['description'])+'</p>\n'
                if item.get('evidence'):
                    html += '<pre style="background:#f8f9fa;padding:8px;border-radius:4px;font-size:12px;overflow-x:auto;margin:8px 0">'+self._esc(item['evidence'])+'</pre>\n'
                if item.get('impact'):
                    html += '<p style="margin:4px 0;font-size:13px;color:#dc3545"><b>&#x1F4A5; Impact:</b> '+self._esc(item['impact'])+'</p>\n'
                html += '<p style="margin:4px 0;font-size:13px;color:#28a745"><b>&#x1F527; Fix:</b> '+self._esc(item['remediation'])+'</p>\n'
                html += '</div>\n'

        # ─── 详细发现 ──────────────────────────────────────────
        html += '<h2>详细发现 / Detailed Findings ('+str(len(sf))+' unique)</h2>\n'
        html += '<table>\n'
        html += '<tr><th>等级 / Severity</th><th>问题描述 / Issue</th>'
        html += '<th>位置来源 / Location</th><th>修复 / Fix</th></tr>\n'
        html += rows
        html += '</table>\n'
        html += '<a id="bottom"></a>\n'

        # ─── 浮动导航按钮 ──────────────────────────────────────
        html += '<div class="nav-float">\n'
        html += '<a href="#top" class="nav-btn" title="回到顶部 / Back to Top">&#x2B06;&#xFE0F;</a>\n'
        html += '<a href="#bottom" class="nav-btn" title="跳到底部 / Jump to Bottom">&#x2B07;&#xFE0F;</a>\n'
        html += '</div>\n'

        html += '</div>\n</body>\n</html>'
        return html

    def _gen_md(self, r):
        lines = ['# &#x1F50D; 技能安全扫描报告<br><small style="font-size:14px;color:#666">Skill Security Scan Report</small>','',
                 '**Target:** '+str(r.get('target','?')),
                 '**Date:** '+str(r.get('scan_time','?')),
                 '**Files:** '+str(r.get('total_files',0)),'',
                 '## Risk',
                 '- Level: **'+str(r.get('risk_level','?'))+'**',
                 '- Score: '+str(r.get('risk_score',0))+'/100',
                 '- Verdict: '+str(r.get('verdict','?')),'']
        for s,c in r.get('findings_by_severity',{}).items():
            e = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}.get(s,'⚪')
            lines.append(f'- {e} **{s}:** {c}')

        # ─── 综合总结 ──────────────────────────────────────────
        rl = r.get('risk_level','?')
        rs = r.get('risk_score',0)
        vt = r.get('verdict','?')
        fbs = r.get('findings_by_severity',{})
        total_findings = r.get('total_findings',0)
        crit_count = fbs.get('CRITICAL',0)
        high_count = fbs.get('HIGH',0)
        med_count = fbs.get('MEDIUM',0)
        low_count = fbs.get('LOW',0)
        
        lines.extend(['','## 📊 扫描总结 / Scan Summary',''])
        
        if 'DO NOT INSTALL' in vt or rl in ('EXTREME','HIGH'):
            lines.append('⛔ **扫描完成 — 禁止安装 / DO NOT INSTALL**')
        elif 'CAUTION' in vt or rl == 'MEDIUM':
            lines.append('⚠️  **扫描完成 — 建议审查后安装 / Review Before Installing**')
        else:
            lines.append('✅ **扫描完成 — 可安全安装 / Safe to Install**')
        lines.append('')
        
        lines.append('| 指标 / Metric | 结果 / Result |')
        lines.append('|--------------|---------------|')
        lines.append(f'| 风险等级 / Risk Level | {rl} |')
        lines.append(f'| 风险分数 / Risk Score | {rs}/100 |')
        lines.append(f'| 安全问题 / Security Issues | {total_findings} 个（{crit_count} CRITICAL + {high_count} HIGH + {med_count} MEDIUM + {low_count} LOW） |')
        lines.append(f'| 结论 / Verdict | {vt} |')
        lines.append('')
        
        # ─── Decoded Malicious Payloads (for HIGH/EXTREME risks) ──────────────
        if rl in ('EXTREME', 'HIGH'):
            raw_payloads = []
            for f in r.get('findings', []):
                dc = f.get('decoded_content') or ''
                if dc.strip() and f.get('source') == 'deobfuscation':
                    raw_payloads.append({
                        'content': dc[:800],
                        'file': f.get('file_path', ''),
                        'line': f.get('line_number', 0),
                        'technique': f.get('rule_id', ''),
                    })
            
            # v5.1: Deduplicate — keep only complete payloads, drop fragments
            decoded_payloads = []
            seen_contents = set()
            for dp in raw_payloads:
                c = dp['content'].strip()
                if len(c) < 30:
                    continue
                if any(c in existing for existing in seen_contents):
                    continue
                seen_contents = {s for s in seen_contents if s not in c}
                seen_contents.add(c)
                decoded_payloads.append(dp)
            
            if decoded_payloads:
                lines.append('### 🚨 解码后的恶意载荷 / Decoded Malicious Payloads')
                lines.append('')
                lines.append('> ⚠️ 以下是扫描器从混淆代码中还原出的真实内容 — 这是判断技能是否恶意的最关键证据。')
                lines.append('')
                for i, dp in enumerate(decoded_payloads, 1):
                    file_short = dp['file'].split('/')[-2:] if '/' in dp['file'] else [dp['file']]
                    lines.append(f'**载荷 #{i}** — `{"/".join(file_short)}`:{dp["line"]} [{dp["technique"]}]')
                    lines.append('```')
                    lines.append(dp['content'])
                    lines.append('```')
                    lines.append('')
        
        # ─── 各层检测结果 ──────────────────────────────────────
        layer_labels = {
            'deobfuscation': '🧹 去混淆 / Deobfuscation',
            'static_analysis': '🔍 静态分析 / Static Analysis',
            'ast_analysis': '🌳 AST 分析 / AST Analysis',
            'semantic_audit': '🧠 语义审计 / Semantic Audit',
            'entropy_analysis': '📊 熵值分析 / Entropy Analysis',
            'install_hook_detection': '🔧 安装钩子 / Install Hooks',
            'network_profiling': '🌐 网络画像 / Network Profiling',
            'threat_intel': '🛡️ 威胁情报 / Threat Intel',
            'credential_theft_detection': '🔐 凭证窃取检测 / Credential Theft',
            'correlation_engine': '🔗 关联分析 / Correlation Engine',
        }
        
        layer_order = ['deobfuscation','static_analysis','ast_analysis','semantic_audit',
                       'entropy_analysis','install_hook_detection','network_profiling',
                       'threat_intel','credential_theft_detection','correlation_engine']
        
        source_map = r.get('findings_by_source',{})
        lines.append('### 各层检测结果 / Layer-by-Layer Results')
        lines.append('')
        lines.append('| 防御层 / Layer | 结果 / Result |')
        lines.append('|---------------|---------------|')
        for src_key in layer_order:
            label = layer_labels.get(src_key, src_key)
            cnt = source_map.get(src_key, 0) if source_map else 0
            if cnt > 0:
                status = f'⚠️ {cnt} 个问题 / {cnt} issues'
            else:
                status = '✅ 正常 / Clean'
            lines.append(f'| {label} | {status} |')
        lines.append('')

        # ─── 按严重等级统计 ────────────────────────────────────
        lines.extend(['','## 按严重等级统计 / Findings by Severity',''])
        for s,c in r.get('findings_by_severity',{}).items():
            e = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}.get(s,'⚪')
            lines.append(f'- {e} **{s}:** {c}')
        lines.append('')

        # ─── 攻击手法分析 (v3.3+) ─────────────────────────────
        aa = self._analyze_attack_patterns(r)
        if aa:
            lines.extend(['','## ⚠️ 攻击手法分析 / Attack Pattern Analysis',''])
            for item in aa:
                lines.append(f"### {item['title']}")
                lines.append(f"- **Type:** {item['type']} | **Severity:** {item['severity']}")
                lines.append(f"- **Description:** {item['description']}")
                if item.get('evidence'):
                    lines.append(f"- **Evidence:**\n```\n{item['evidence']}\n```")
                if item.get('impact'):
                    lines.append(f"- **💥 Impact:** {item['impact']}")
                lines.append(f"- **🔧 Fix:** {item['remediation']}")
                lines.append('')

        # ─── 详细发现 ──────────────────────────────────────────
        lines.extend(['','## Findings',''])
        deduped = self._dedup(r.get('findings',[]))
        for i,f in enumerate(deduped,1):
            d = isinstance(f, dict)
            sev = f.get('severity','?') if d else getattr(f,'severity','?')
            ttl = f.get('title','?') if d else getattr(f,'title','?')
            fp = f.get('file_path','') if d else getattr(f,'file_path','')
            ln = f.get('line_number') or f.get('line',0) if d else getattr(f,'line_number',None) or getattr(f,'line',0)
            desc = f.get('description','') if d else getattr(f,'description','')
            rem = f.get('remediation','') if d else getattr(f,'remediation','')
            mc = f.get('_merged_count',1) if d else getattr(f,'_merged_count',1)
            badge = f' (x{mc} occurrences)' if mc > 1 else ''
            cs = f.get('code_snippet','') if d else getattr(f,'code_snippet','')
            lines.append(f'### {i}. [{sev}] {ttl}{badge}')
            loc = f'{fp}:{ln}' if ln else fp
            lines.append(f'- **File:** `{loc}`')
            lines.append(f'- **Description:** {desc}')
            if cs:
                lines.append(f'- **Code Snippet:**\n```\n{cs.strip()}\n```')
            lines.append(f'- **修复 / Fix:** {rem}')
            lines.append('')
        
        return '\n'.join(lines)
