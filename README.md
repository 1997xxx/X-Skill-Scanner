# 🔍 X Skill Scanner

**Enterprise-grade AI Agent Skill Security Scanner** — Twelve-layer defense pipeline protecting your AI agents from malicious skill poisoning.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-v5.2.0-blue.svg)](CHANGELOG.md)
[![GitHub Stars](https://img.shields.io/github/stars/1997xxx/X-Skill-Scanner?style=social)](https://github.com/1997xxx/X-Skill-Scanner)

📖 [中文文档 →](README_CH.md)

---

## 🚨 Why This Tool Matters

ClawHub has been infiltrated by **472+ malicious skills** (per SlowMist Security monitoring), including top-downloaded popular skills. Every installed skill is a trust relationship — and that trust deserves scrutiny.

### Real Attack Examples

| Attack Vector | Example | Impact |
|--------------|---------|--------|
| Base64-encoded backdoor + RCE | `weather-query` disguised as weather tool, actually downloads ransomware | File system encryption |
| osascript fake password dialog | Nova Stealer steals macOS Keychain credentials | Account compromise |
| SSH/AWS credential exfiltration | Stolen credentials sent via Discord Webhook | Cloud resource takeover |
| Browser cookie theft | Session tokens read from localStorage / Keychain | Session hijacking |

---

## ✨ Core Features

### 1️⃣ Twelve-Layer Deep Defense

X Skill Scanner is not a simple regex-matching tool. It builds **12 independent detection engines**, covering the full attack surface from surface-level signatures to deep intent analysis:

- **Surface Detection** — Threat intelligence matching (380+ known malicious skill names, IOC domains/IPs), whitelist validation
- **Code Analysis** — 194+ static rules, AST taint tracking, dependency CVE checks, deobfuscation engine
- **Behavioral Profiling** — Network endpoint extraction, install hook detection, credential theft pattern recognition
- **Semantic Understanding** — LLM-driven intent analysis, identifying hidden threats invisible to the naked eye
- **Correlation Analysis** — Cross-engine attack chain detection, discovering multi-stage combined attacks

**Zero configuration required.** The scanner auto-discovers your OpenClaw LLM Provider configuration — no environment variables needed.

### 2️⃣ Intelligent Deobfuscation

Malicious skills most commonly use obfuscation. The scanner includes **5 deobfuscation engines** that penetrate any number of encoding layers:

| Technique | Description | Example |
|-----------|-------------|---------|
| Base64 Decoding | Auto-detects and decodes `base64.b64decode()`, `b'...'` literals | `Y3VybCAtcy...` → `curl -s ...` |
| Hex Array Reconstruction | Collects cross-line `[0x63, 0x75, 0x72, ...]` byte arrays, strips null bytes | `curl\x00 -s\x00` → `curl -s` |
| String Concat Assembly | Identifies `_part1_ + _part2_ + ...` patterns, reassembles and decodes | Fragmented Base64 → full command |
| BiDi Character Detection | Detects Unicode bidirectional override characters (CVE-2021-42574) | Visually deceptive filenames |
| Zero-Width Character Detection | Detects invisible character injection | Hidden watermarks / identifiers |

**Reports display decoded malicious payloads directly** — no manual reverse engineering needed.

### 3️⃣ Profile-Driven Adaptive Scanning

Not every skill needs a full scan. The scanner first performs a **trust profile assessment** and automatically selects the scanning strategy:

```
Trust Score ≥ 70  → Quick Mode (3 layers)     ~3 seconds
Trust Score 40-69 → Standard Mode (12 layers)  ~15 seconds
Trust Score < 40  → Full Mode (12 layers + LLM per-finding review)  ~60 seconds
```

Profile dimensions: author credibility, skill type, file structure合理性, red flag markers, etc.

### 4️⃣ Batch LLM Review — 70%+ Fewer API Calls

Traditional approaches call the LLM separately for each finding, creating massive API overhead. The scanner uses a **file-grouped batch review** strategy:

- All findings in the same file merged into one LLM call
- Complete code context included for better judgment accuracy
- Auto-filters false positives (security tool self-references, documentation, test data)
- Cross-provider alias resolution, auto-adapts to your OpenClaw default model

### 5️⃣ Cross-Layer Correlation — Detect Multi-Stage Attack Chains

A single engine's finding may be isolated, but combined signals across multiple engines reveal real threats. The scanner identifies **6 attack chain patterns**:

| Attack Chain | Composed Engines | Typical Scenario |
|-------------|-----------------|------------------|
| C2 Infiltration | Obfuscation + Network + Persistence | Obfuscated download → establish C2 → persist |
| Credential Harvest | Credential Theft + Data Exfiltration | Read SSH keys → webhook exfil |
| Supply Chain Attack | Malicious Dependency + Install Hook | Malicious package → postinstall execution |
| Rug-Pull Pattern | Baseline Change + Semantic Risk | Normal skill update implants malicious code |
| Social Engineering | Prompt Injection + Exploitation | Bypass system instructions → dangerous operations |
| Reverse Shell Chain | Reverse Shell + Network + Obfuscation | Obfuscated reverse shell connection |

### 6️⃣ Multi-Format Reports — Fit Your Workflow

| Format | Use Case |
|--------|----------|
| **Text** | Quick terminal viewing |
| **HTML** | Interactive report with highlighted decoded malicious payload section |
| **JSON** | Machine-readable, CI/CD integration |
| **Markdown** | GitHub Issues / PR comments |
| **SARIF** | Native GitHub Security Tab integration |

---

## 🛡️ Twelve-Layer Defense Pipeline

| Layer | Engine | Capability |
|-------|--------|------------|
| 0 | 🎯 Skill Profiler | Trust score · scan strategy · risk fingerprint |
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
| 11 | 🌐 Network Profiler | Endpoint extraction · IP direct connect · covert channels · C2 |
| 12 | 🔐 Credential Theft | osascript phishing · SSH/AWS keys · browser cookies · Keychain |
| 🔗 | Cross-Layer Correlation | Multi-engine attack chain detection · correlation scoring |

---

## 🚀 Quick Start

### As an OpenClaw Skill (Recommended)

```bash
# Clone into your skills directory
git clone https://github.com/1997xxx/X-Skill-Scanner.git \
  ~/.openclaw/skills/x-skill-scanner

# Restart OpenClaw — the skill auto-registers
openclaw gateway restart

# Now just say: "scan this skill" or "audit skill security"
# The scanner auto-triggers before any skill installation
```

### Standalone CLI

```bash
# Scan a local skill
python3 lib/scanner.py -t ./my-skill/

# Scan a remote skill URL
python3 lib/scanner.py --url https://github.com/user/skill-repo

# Quick mode (skip LLM semantic audit)
python3 lib/scanner.py -t ./my-skill/ --no-semantic

# HTML report with decoded payload highlights
python3 lib/scanner.py -t ./my-skill/ --format html -o report.html

# SARIF output (for GitHub Security Tab integration)
python3 lib/scanner.py -t ./my-skill/ --format sarif -o results.sarif
```

### Configuration

**Zero-config mode:** The scanner auto-discovers LLM Provider from `~/.openclaw/openclaw.json`. No manual setup needed.

For custom providers:
```bash
export OPENAI_BASE_URL="https://your-provider.com/v1/chat/completions"
export OPENAI_API_KEY="your-api-key"
export OPENAI_MODEL="gpt-4o-mini"
```

### CLI Options

```
-t TARGET             Target skill directory or file
--url URL             Remote skill URL (auto-clones & scans)
--no-semantic         Skip LLM semantic audit
--no-llm-review       Skip LLM secondary review
--no-fp-filter        Skip false positive pre-filter
--format FORMAT       Output format: text(default)/html/json/md/sarif
-o OUTPUT             Output file path
--whitelist FILE      Custom whitelist JSON
--threat-intel FILE   Custom threat intel JSON
--path-filter PATTERN Path exclusion regex
--install             Prompt to install after scan
--no-prompt           Skip install prompt (CI/automation)
--install-to PATH     Specify install directory
```

---

## 📊 Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| 🟢 SAFE | 0–4 | ✅ No significant issues |
| 🟢 LOW | 5–19 | ✅ Safe to install |
| 🟡 MEDIUM | 20–49 | ⚠️ Review before installing |
| 🔴 HIGH | 50–79 | ❌ Do not install without approval |
| ⛔ EXTREME | 80–100 | ❌ Block immediately |

---

## 🏗️ Architecture

```
Skill Input (local dir / GitHub URL / zip)
    │
    ▼
┌─ Pre-flight Legality Check ──────────────────────────────────┐
│  Validates SKILL.md structure, blocks non-skill inputs       │
├─ Whitelist Check ────────────────────────────────────────────┤
│  Known-safe skills skip full scan                            │
├─ Skill Profiling ────────────────────────────────────────────┤
│  Trust score → scan_strategy (quick / standard / full)       │
├─ 12-Layer Detection Pipeline ────────────────────────────────┤
│                                                              │
│  Threat Intel → Deobfuscation → Static Analysis → AST       │
│  Dependencies → Prompt Injection → Baseline → Semantic      │
│  Entropy → Install Hooks → Network → Credential Theft       │
│                                                              │
├─ Cross-Layer Correlation ────────────────────────────────────┤
│  Detects 6 attack chain patterns across engines              │
├─ FP Pre-Filter ──────────────────────────────────────────────┤
│  Auto-filters security tool self-references, docs, tests     │
├─ LLM Batch Review ───────────────────────────────────────────┤
│  Groups findings by file → single LLM call per file          │
├─ Risk Scoring ───────────────────────────────────────────────┤
│  Cross-layer stacking + correlation bonuses + verdict        │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
Report: text / HTML (with decoded payloads) / JSON / Markdown / SARIF
```

---

## 🆕 Changelog Highlights

### v5.2.0 (2026-04-02)
- 🚨 **Decoded Malicious Payloads** — Reports now prominently display fully reconstructed malicious commands at the top
- 🔓 **Multi-layer Deobfuscation** — Hex array reconstruction, Base64 bytes literal detection, string concat assembly
- 🎯 **Provider Alias Resolution** — Auto-resolves model names across providers (fixes LLM timeout issues)
- 🧹 **Fragment Dedup** — Only complete payloads shown; fragments automatically filtered

### v5.1.0 (2026-04-01)
- Ethics & Compliance Framework (six principles)
- Project hygiene cleanup + version synchronization

### v5.0.0 (2026-03-31)
- Profile-driven adaptive scanning (quick/standard/full modes)
- Batch LLM review (70%+ API call reduction)
- Cross-layer correlation engine (6 attack chain patterns)
- Risk scoring upgrade with context-aware modifiers

---

## 🤝 Acknowledgments

This project's threat intelligence and detection capabilities reference research from:

- [Koi.ai](https://koi.ai) — ClawHavoc Report (341 malicious skills)
- [Snyk](https://snyk.io) — ToxicSkills Campaign Analysis
- [SmartChainArk](https://github.com/smartchainark/skill-security-audit) — 13 detectors + false positive tuning
- [SlowMist Security](https://slowmist.com) — ClawHub poisoning analysis
- [Tencent Keen Lab](https://ke.tencent.com) — OpenClaw Skills risk analysis
- [MurphySec](https://murphysec.com) — AI Agent Security Report

---

## 📄 License

MIT License

---

**X Skill Scanner Team** — Your AI skill security guardian 🛡️

*Version: v5.2.0 | Updated: 2026-04-02*
