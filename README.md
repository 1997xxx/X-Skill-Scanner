# 🔍 X Skill Scanner

**Enterprise-grade AI Agent Skill Security Scanner** — Twelve-layer defense pipeline protecting your AI agents from malicious skill poisoning.

**企业级 AI Agent 技能安全扫描器** — 十二层深度防御，保护你的 AI Agent 免受恶意技能投毒。

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-v5.2.0-blue.svg)](CHANGELOG.md)

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

| Layer | Engine / 引擎 | Capability / 能力 |
|-------|--------|------------|
| 0 | 🎯 Skill Profiler / 技能画像 | Trust score · scan strategy · risk fingerprint<br>信任评分 · 扫描策略推荐 · 风险指纹 |
| 1 | 🔍 Threat Intel / 威胁情报 | 380+ malicious skill names · IOC domains/IPs · attack patterns<br>380+ 恶意技能名 · IOC 域名/IP · 攻击模式 |
| 2 | 🧹 Deobfuscation / 去混淆 | Base64/Hex/BiDi/zero-width/TR39/Zlib/string concatenation<br>Base64/十六进制/双向字符/零宽字符/TR39/Zlib/字符串拼接 |
| 3 | 🔎 Static Analysis / 静态分析 | 194+ rules · credentials/injection/supply chain/time bombs<br>194+ 规则 · 凭据/注入/供应链/逻辑炸弹检测 |
| 4 | 🌳 AST Deep Analysis / AST 深度分析 | Taint tracking · indirect execution · dynamic imports<br>污点追踪 · 间接执行 · 动态导入 |
| 5 | 📦 Dependency Check / 依赖检查 | requirements.txt / package.json CVE matching<br>CVE 漏洞匹配（Python/Node.js） |
| 6 | 💉 Prompt Injection / 提示注入 | 25+ probes · system override · role hijacking · DAN/Jailbreak<br>25+ 探针 · 系统覆盖 · 角色劫持 · DAN/越狱检测 |
| 7 | 📋 Baseline Tracking / 基线追踪 | SHA-256 fingerprint · rug-pull detection<br>SHA-256 指纹 · 撤资跑路检测 |
| 8 | 🧠 Semantic Audit / 语义审计 | LLM intent analysis (optional, for high-risk files)<br>LLM 意图分析（可选，针对高风险文件） |
| 9 | 📊 Entropy Analysis / 熵值分析 | Shannon entropy · CJK adaptive thresholds · encoded payloads<br>香农熵 · 中日韩自适应阈值 · 编码载荷检测 |
| 10 | 🔧 Install Hooks / 安装钩子 | postinstall · setup.py · shell RC · cron injection<br>postinstall · setup.py · Shell 启动项 · Cron 注入 |
| 11 | 🌐 Network Profiler / 网络画像 | Endpoint extraction · IP direct connect · covert channels · C2<br>端点提取 · IP 直连 · 隐蔽通道 · C2 通信检测 |
| 12 | 🔐 Credential Theft / 凭据窃取 | osascript phishing · SSH/AWS keys · browser cookies · Keychain<br>osascript 钓鱼 · SSH/AWS 密钥 · 浏览器 Cookie · 钥匙串 |
| 🔗 | Cross-Layer Correlation / 跨层关联 | Multi-engine attack chain detection · correlation scoring<br>多引擎攻击链检测 · 关联评分 |

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

为 LLM 驱动的功能设置环境变量：
```bash
export OPENAI_BASE_URL="https://your-provider.com/v1/chat/completions"
export OPENAI_API_KEY="your-api-key"
export OPENAI_MODEL="gpt-4o-mini"
```

或在 `~/.openclaw/openclaw.json` 中配置 — 扫描器会自动发现 Provider。

### CLI Options / 命令行选项

```
-t TARGET             目标技能目录或文件 / Target skill directory or file
--no-semantic         跳过 LLM 语义审计 / Skip LLM semantic audit
--no-llm-review       跳过 LLM 二次审查 / Skip LLM secondary review
--no-fp-filter        跳过误报预过滤器 / Skip false positive pre-filter
--format FORMAT       输出格式：text(默认)/html/json/md/sarif / Output format
-o OUTPUT             输出文件路径 / Output file path
--whitelist FILE      自定义白名单 JSON / Custom whitelist JSON
--threat-intel FILE   自定义威胁情报 JSON / Custom threat intel JSON
--path-filter PATTERN 路径排除正则 / Path exclusion regex
--install             扫描后询问是否安装 / Prompt to install after scan
--no-prompt           跳过安装询问（CI/自动化）/ Skip install prompt (CI/automation)
--install-to PATH     指定安装目录 / Specify install directory
```

---

## 📊 Risk Levels / 风险等级

| Level | Score | Action / 处理方式 |
|-------|-------|--------|
| 🟢 SAFE | 0–4 | ✅ 无显著问题 / No significant issues |
| 🟢 LOW | 5–19 | ✅ 可安全安装 / Safe to install |
| 🟡 MEDIUM | 20–49 | ⚠️ 建议人工审查后决定 / Review before installing |
| 🔴 HIGH | 50–79 | ❌ 未经批准禁止安装 / Do not install without approval |
| ⛔ EXTREME | 80–100 | ❌ 立即阻断 / Block immediately |

---

## 🏗️ Architecture / 架构概览

```
Skill Input / 技能输入
    │
    ▼
┌─ Whitelist Check / 白名单检查 ───────────────────┐
│                                                  │
│  ┌─ Skill Profiler / 技能画像 → scan_strategy ─┐ │
│  │  quick(快速) / standard(标准) / full(全面)   │ │
│  ▼                                            │  │
│  ┌─ Threat Intel / 威胁情报 → names/IOC       │  │
│  ├─ Deobfuscation / 去混淆 → Base64/Hex/BiDi  │  │
│  ├─ Static Analysis / 静态分析 → 194+ rules   │  │ ← controlled by
│  ├─ AST Analysis / AST 分析 → taint tracking   │  │   scan_strategy
│  ├─ Dependency Check / 依赖检查 → CVE matching │  │
│  ├─ Prompt Injection / 提示注入 → 25+ probes   │  │
│  ├─ Baseline Tracking / 基线追踪 → SHA-256     │  │
│  ├─ Semantic Audit / 语义审计 → LLM intent     │  │
│  ├─ Entropy Analysis / 熵值分析 → anomaly      │  │
│  ├─ Install Hooks / 安装钩子 → postinstall     │  │
│  ├─ Network Profiler / 网络画像 → C2/exfil     │  │
│  └─ Credential Theft / 凭据窃取 → osascript    │  │
│                                                  │
│  ┌─ Cross-Layer Correlation / 跨层关联 → chains │ │
│  └─ FP Pre-Filter / 误报预过滤 → auto-filter   │  │
│                                                  │
│  ┌─ LLM Batch Review / LLM 批量审查            │  │
│  └─ Risk Scorer / 风险评分 → score + verdict   │  │
│                                                  │
└──────────────────────────────────────────────────┘
    │
    ▼
Report / 报告 (text / HTML / JSON / SARIF)
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

*Version: v5.2.0 | Updated: 2026-04-01*
