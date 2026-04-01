# 🔍 X Skill Scanner

**Enterprise-grade AI Agent Skill Security Scanner** — Twelve-layer defense pipeline protecting your AI agents from malicious skill poisoning.

**企业级 AI Agent 技能安全扫描器** — 十二层深度防御，保护你的 AI Agent 免受恶意技能投毒。

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-v5.1.0-blue.svg)](CHANGELOG.md)

---

## 🚨 Why This Tool Matters / 为什么需要这个工具

ClawHub has been infiltrated by **472+ malicious skills** (per SlowMist Security monitoring), including top-downloaded popular skills. Attack vectors include:

ClawHub 已被 **472+ 恶意 Skills** 渗透（慢雾安全监测），包括下载量最高的热门技能。攻击手法包括：

- Base64-encoded backdoors + remote code execution / Base64 编码后门 + 远程代码执行
- osascript fake password dialogs on macOS (Nova Stealer) / osascript 伪造 macOS 系统密码弹窗（Nova Stealer）
- SSH/AWS credential theft + webhook exfiltration / SSH/AWS 密钥窃取 + webhook 外传
- Browser cookie/localStorage data theft / 浏览器 Cookie/LocalStorage 数据窃取

> ⚠️ Every installed skill is a trust relationship — and that trust deserves scrutiny.
>
> 每个安装的技能都是一份信任——这份信任值得被审视。

---

## 🆕 v5.0 New Features / v5.0 新特性

### 🧠 Profile-Driven Adaptive Scanning / 画像驱动自适应扫描
Scans skills in three modes based on trust profile:
根据信任画像自动选择扫描模式：
- **Quick** (trust ≥70): Only threat intel + static analysis + credential check — ~3s
- **Standard** (trust 40-69): Full 12-layer scan + LLM review for MEDIUM+ findings
- **Full** (trust <40 or red flags): All engines + LLM reviews every finding

### 🤖 Batch LLM Review / LLM 批量审查
Groups findings by file for single LLM call instead of one-per-finding. Reduces API calls by **70%+**.
按文件分组发现，一次 LLM 调用审查多条，API 调用减少 **70%+**。

### 🔗 Cross-Layer Correlation / 跨层关联分析
Detects multi-stage attack chains across detection layers:
识别跨引擎的多阶段攻击链：
- C2 Infiltration Chain (obfuscation + network + persistence)
- Credential Harvest Chain (credential theft + data exfiltration)
- Supply Chain Attack (malicious dependency + install hook)
- Rug-Pull Pattern (baseline change + semantic risk)
- Social Engineering Chain (prompt injection + exploitation)
- Reverse Shell Chain (reverse shell + network + obfuscation)

### 📈 Risk Score Upgrade / 风险评分升级
- CORRELATION category weight = 35 (highest priority)
- Cross-layer stacking bonus for multi-engine hits on same file
- Context-aware modifiers (install hook ×1.5, network ×1.2, credentials ×1.3)

---

## 🛡️ Twelve-Layer Defense Pipeline / 十二层防御管线

| Layer | Engine | Capability |
|-------|--------|------------|
| 0 | 🎯 Skill Profiler | Trust score · scan strategy recommendation · risk fingerprint |
| 1 | 🔍 Threat Intel | 380+ malicious skill names · IOC domains/IPs · attack patterns |
| 2 | 🧹 Deobfuscation | Base64/Hex/BiDi/zero-width/TR39/Zlib/string concatenation |
| 3 | 🔎 Static Analysis | 194+ rules · credentials/injection/supply chain/time bombs |
| 4 | 🌳 AST Deep Analysis | Taint tracking · indirect execution · dynamic imports |
| 5 | 📦 Dependency Check | requirements.txt / package.json CVE matching |
| 6 | 💉 Prompt Injection | 25+ probes · system override · role hijacking · DAN/Jailbreak |
| 7 | 📋 Baseline Tracking | SHA-256 fingerprint · rug-pull detection |
| 8 | 🧠 Semantic Audit | LLM intent analysis (optional, for high-risk files) |
| 9 | 📊 Entropy Analysis | Shannon entropy · CJK adaptive thresholds · encoded payloads |
| 10 | 🔧 Install Hooks | postinstall · setup.py · shell RC · cron injection |
| 11 | 🌐 Network Profiler | endpoint extraction · IP direct connect · covert channels · C2 |
| 12 | 🔐 Credential Theft | osascript phishing · SSH/AWS keys · browser cookies · Keychain |
| 🔗 | Cross-Layer Correlation | Multi-engine attack chain detection · correlation scoring |

---

## 🚀 Quick Start / 快速开始

```bash
# Clone the repository
git clone https://github.com/1997xxx/X-Skill-Scanner.git
cd X-Skill-Scanner

# Install dependencies
pip install -r requirements.txt

# Scan a single skill
./scan -t ./my-skill/

# Quick mode (skip LLM semantic audit)
./scan -t ./my-skill/ --no-semantic

# Disable FP filter (for debugging)
./scan -t ./my-skill/ --no-fp-filter

# HTML report
./scan -t ./my-skill/ --format html -o report.html

# SARIF output (for GitHub Security Tab)
./scan -t ./my-skill/ --format sarif -o results.sarif
```

### Configuration / 配置

Set environment variables for LLM-powered features:
```bash
export OPENAI_BASE_URL="https://your-provider.com/v1/chat/completions"
export OPENAI_API_KEY="your-api-key"
export OPENAI_MODEL="gpt-4o-mini"
```

Or configure in `~/.openclaw/openclaw.json` — the scanner auto-discovers providers.

### CLI Options / 命令行选项

```
-t TARGET          Target skill directory or file
--no-semantic      Skip LLM semantic audit
--no-llm-review    Skip LLM secondary review
--no-fp-filter     Skip false positive pre-filter
--format FORMAT    Output format: text (default), html, json, md, sarif
-o OUTPUT          Output file path
--whitelist FILE   Custom whitelist JSON
--threat-intel FILE Custom threat intel JSON
--path-filter PATTERN  Path exclusion regex
```

---

## 📊 Risk Levels / 风险等级

| Level | Score | Action |
|-------|-------|--------|
| 🟢 SAFE | 0–4 | ✅ No significant issues |
| 🟢 LOW | 5–19 | ✅ Safe to install |
| 🟡 MEDIUM | 20–49 | ⚠️ Review before installing |
| 🔴 HIGH | 50–79 | ❌ Do not install without approval |
| ⛔ EXTREME | 80–100 | ❌ Block immediately |

---

## 🏗️ Architecture / 架构概览

```
Skill Input
    │
    ▼
┌─ Whitelist Check ──────────────────────────────┐
│                                                  │
│  ┌─ Skill Profiler ──→ scan_strategy ────────┐  │
│  │  quick / standard / full                   │  │
│  ▼                                            │  │
│  ┌─ Threat Intel ──→ malicious names/IOC     │  │
│  ├─ Deobfuscation ──→ Base64/Hex/BiDi        │  │
│  ├─ Static Analysis ──→ 194+ rules           │  │ ← controlled by
│  ├─ AST Analysis ──→ taint tracking           │  │   scan_strategy
│  ├─ Dependency Check ──→ CVE matching         │  │
│  ├─ Prompt Injection ──→ 25+ probes           │  │
│  ├─ Baseline Tracking ──→ SHA-256 diff        │  │
│  ├─ Semantic Audit ──→ LLM intent             │  │
│  ├─ Entropy Analysis ──→ anomaly detection    │  │
│  ├─ Install Hooks ──→ postinstall/setup.py    │  │
│  ├─ Network Profiler ──→ C2/exfil detection   │  │
│  └─ Credential Theft ──→ osascript/SSH/AWS    │  │
│                                                  │
│  ┌─ Cross-Layer Correlation ──→ attack chains  │  │
│  └─ FP Pre-Filter ──→ auto-filter known FPs   │  │
│                                                  │
│  ┌─ LLM Batch Review ──→ TP/FP/HUMAN_REVIEW   │  │
│  └─ Risk Scorer ──→ final score + verdict     │  │
│                                                  │
└──────────────────────────────────────────────────┘
    │
    ▼
Report (text / HTML / JSON / SARIF)
```

---

## 🤝 Acknowledgments / 致谢

This project's threat intelligence and detection capabilities reference research from:

本项目的威胁情报和检测能力参考了以下安全团队的研究成果：

- [Koi.ai](https://koi.ai) — ClawHavoc Report (341 malicious skills)
- [Snyk](https://snyk.io) — ToxicSkills Campaign Analysis
- [SmartChainArk](https://github.com/smartchainark/skill-security-audit) — 13 detectors + false positive tuning
- [SlowMist Security](https://slowmist.com) — ClawHub poisoning analysis
- [Tencent Keen Lab](https://ke.tencent.com) — OpenClaw Skills risk analysis
- [MurphySec](https://murphysec.com) — AI Agent Security Report

---

## 📄 License / 许可证

MIT License

---

**X Skill Scanner Team** — Your AI skill security guardian 🛡️

*Version: v5.1.0 | Updated: 2026-04-01*
