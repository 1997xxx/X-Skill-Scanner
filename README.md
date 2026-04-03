# 🔍 X Skill Scanner

**Enterprise-grade AI Agent Skill Security Scanner** — Twelve-layer defense pipeline protecting your AI agents from malicious skill poisoning.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-v6.0.0-blue.svg)](CHANGELOG.md)
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
- **Semantic Understanding** — Multi-agent intent analysis via OpenClaw sessions_spawn, identifying hidden threats invisible to the naked eye
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
Trust Score < 40  → Full Mode (12 layers + SubAgent review)  ~60 seconds
```

Profile dimensions: author credibility, skill type, file structure合理性, red flag markers, etc.

### 4️⃣ SubAgent-Based Review — Cross-Platform, Zero API Config

The scanner uses OpenClaw's multi-agent communication (`sessions_spawn`) for intelligent false positive filtering:

- **No external API dependencies** — works on Windows/macOS/Linux without idealab/OpenAI configuration
- **Push-based notifications** — zero polling cost, real-time results
- **Automatic heuristic fallback** — when SubAgent unavailable, rule-based classification takes over
- **Negative example detection** — recognizes "don't do X" documentation patterns vs actual malicious instructions
- **Batch processing** — groups findings by file for efficient review

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
| 7 | 📋 Baseline Tracking | SHA-256 fingerprint · rug-pull detection · change audit |
| 8 | 🧠 Semantic Audit | Multi-agent intent analysis (optional, for high-risk files) |
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
--no-llm-review       Skip SubAgent secondary review
--no-fp-filter        Skip false positive pre-filter
--format FORMAT       Output format: text(default)/html/json/md/sarif
-o OUTPUT             Output file path
--whitelist FILE      Custom whitelist JSON
--baseline-only       Check baseline changes only
--update-baseline     Update baseline after scan
--profile-only        Output skill profile only
--json                JSON output shortcut
```

---

## 📊 Sample Output

```
🔍 X Skill Scanner v6.0.0
Scanning: ./my-skill/

🎯 Step 0/7: Skill Profiling...
Skill: my-skill | Author: trusted-dev | Type: OpenClaw Skill | Files: 12
Trust Score: 85/100 | Strategy: quick | Red Flags: 0

🔍 Step 1/7: Threat Intelligence...
✅ No threat intel matches

🔎 Step 3/7: Static Analysis...
Found 2 issues:
  ⚠️ [MEDIUM] Hardcoded secret detected (config.py:15)
  ℹ️ [LOW] Non-standard port usage (network.py:42)

🤖 Step 6.0: SubAgent Review...
   Review: 2 findings → 1 FP | 0 TP | 1 HUMAN_REVIEW

============================================================
Risk Level: LOW (8/100)
Verdict: ✅ SAFE TO INSTALL
============================================================
```

---

## 🏗️ Architecture

### Module Structure

```
lib/
├── scanner.py                 # Main orchestrator (12-layer pipeline)
├── subagent_reviewer.py       # v6.0: Multi-agent review engine
├── models.py                  # Unified data models (Finding, Severity, etc.)
├── models_v2.py               # Compatibility shim → models.py
│
├── analyzers/                 # Detection engines
│   ├── pattern_analyzer.py    # Rule-based pattern matching
│   └── ...
│
├── threat_intel.py            # IOC matching (skill names, domains, IPs)
├── static_analyzer.py         # 194+ static security rules
├── ast_analyzer.py            # AST-based taint tracking
├── deobfuscator.py            # Multi-engine deobfuscation
├── dependency_checker.py      # CVE database matching
├── prompt_injection_probes.py # 25+ injection test probes
├── semantic_auditor.py        # LLM-driven intent analysis
├── entropy_analyzer.py        # Shannon entropy analysis
├── install_hook_detector.py   # Postinstall/setup.py detection
├── network_profiler.py        # Network behavior profiling
├── credential_theft_detector.py # Credential access patterns
├── social_engineering_detector.py # Social engineering patterns
├── correlation_engine.py      # Cross-layer attack chain detection
│
├── fp_filter.py               # False positive pre-filter
├── pre_flight_check.py        # Legitimacy validation
├── skill_profiler.py          # Trust score calculation
├── risk_scorer.py             # Risk score computation
├── reporter.py                # Multi-format report generation
├── baseline.py                # SHA-256 baseline tracking
├── whitelist.py               # Trusted domain/rule exemptions
├── rule_loader.py             # YAML rule loading
├── llm_provider.py            # Shared LLM provider discovery
├── path_filter.py             # Path exclusion patterns
├── self_check.py              # Module health check
└── update_ioc.py              # IOC database updater
```

### Design Principles

| Principle | Implementation | Benefit |
|-----------|---------------|---------|
| Push > Poll | Auto announcement delivery | Zero polling cost |
| Isolation > Sharing | Independent sessions, working dirs | No conflicts |
| Declarative > Imperative | Tool calls, LLM-friendly | Easy orchestration |
| Async > Sync | Background execution | High concurrency |
| Snapshot > Reference | Attachment copying | Independent lifecycles |

---

## 🔄 Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

### Recent Releases

| Version | Date | Highlights |
|---------|------|-----------|
| **v6.0.0** | 2026-04-03 | SubAgent review, unified models, cross-platform |
| v5.5.0 | 2026-04-02 | Architecture upgrade, adaptive scanning |
| v5.2.0 | 2026-04-02 | Enhanced deobfuscation |
| v5.1.0 | 2026-04-01 | Baseline tracking, correlation analysis |
| v5.0.0 | 2026-03-31 | Initial release |

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone and install dependencies
git clone https://github.com/1997xxx/X-Skill-Scanner.git
cd X-Skill-Scanner
pip install PyYAML

# Run tests
python3 -m pytest tests/

# Run self-check
python3 lib/self_check.py
```

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [SlowMist Security](https://slowmist.com) for malicious skill monitoring data
- [OpenClaw](https://github.com/openclaw/openclaw) for the multi-agent communication framework
- All contributors who reported vulnerabilities and suggested improvements

---

*Version: v6.0.0 | Updated: 2026-04-03*
