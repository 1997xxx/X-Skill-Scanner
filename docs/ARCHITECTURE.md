# Architecture Design / 架构设计

## System Architecture / 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│  User requests skill installation                           │
│  用户请求安装技能                                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Threat Intelligence                               │
│  • 380+ malicious skill name matching                       │
│  • IOC domain/IP blacklist                                  │
│  威胁情报匹配 — 恶意技能名 · IOC 域名/IP                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Deobfuscation Engine                              │
│  • Base64/ROT13/Hex/BiDi/Zero-width/TR39/Zlib detection     │
│  去混淆引擎 — 7 种混淆技术检测                                │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Static Analysis                                   │
│  • 194+ pattern rules (credentials/injection/supply chain)  │
│  • YAML rule-driven engine                                  │
│  静态分析 — 194+ 规则 · YAML 驱动                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: AST Deep Analysis                                 │
│  • Indirect execution · taint tracking · dynamic imports    │
│  • Deserialization · shell injection                        │
│  AST 深度分析 — 间接执行 · Taint 追踪                         │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: Dependency Checker                                │
│  • requirements.txt / package.json CVE matching             │
│  依赖检查 — CVE 匹配                                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 6: Prompt Injection Probes                           │
│  • 25+ probes for system override / role hijacking          │
│  提示词注入探针 — 25+ 探针                                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 7: Baseline Tracking                                 │
│  • SHA-256 fingerprint · rug-pull detection                 │
│  基线追踪 — SHA-256 指纹 · Rug-Pull 检测                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 8: Semantic Audit (optional)                         │
│  • LLM intent analysis for high-risk files                  │
│  语义审计 — LLM 意图分析（可选）                                │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 9: Entropy Analysis                                  │
│  • Shannon entropy · CJK adaptive thresholds                │
│  熵值分析 — Shannon 熵 · CJK 自适应阈值                        │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 10: Install Hook Detector                            │
│  • setup.py/cmdclass · postinstall · shell RC · cron        │
│  安装钩子检测 — setup.py · Shell RC · Cron                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 11: Network Behavior Profiler                        │
│  • Endpoint extraction · IP direct connect · C2 patterns    │
│  网络行为画像 — 端点提取 · IP 直连 · C2 特征                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 12: Credential Theft Detection                       │
│  • osascript phishing · SSH/AWS keys · browser cookies      │
│  凭证窃取检测 — osascript · SSH/AWS · 浏览器 Cookie            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Risk Scoring & Report Generation                           │
│  • Unified threshold (CRITICAL >= 80)                       │
│  • Output: text/json/html/md/sarif                          │
│  风险评分与报告生成                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Modules / 核心模块

| Module | File | Description |
|--------|------|-------------|
| Main Scanner | `lib/scanner.py` | Twelve-layer pipeline orchestrator |
| Static Analyzer | `lib/static_analyzer.py` | YAML rule-driven pattern matching |
| Threat Intel | `lib/threat_intel.py` + `data/threat_intel.json` | Multi-layer threat intelligence engine |
| Deobfuscator | `lib/deobfuscator.py` | Seven obfuscation technique detectors |
| AST Analyzer | `lib/ast_analyzer.py` | Taint tracking + indirect execution |
| Dependency Checker | `lib/dependency_checker.py` | CVE database matching |
| Prompt Injection | `lib/prompt_injection_probes.py` | 25+ injection probe patterns |
| Baseline Tracker | `lib/baseline.py` | SHA-256 fingerprint + rug-pull detection |
| Semantic Auditor | `lib/semantic_auditor.py` | LLM-based intent analysis |
| Entropy Analyzer | `lib/entropy_analyzer.py` | Shannon entropy + CJK adaptive thresholds |
| Install Hook Detector | `lib/install_hook_detector.py` | Post-install malicious behavior detection |
| Network Profiler | `lib/network_profiler.py` | Network behavior deep analysis |
| Credential Theft Detector | `lib/credential_theft_detector.py` | osascript/SSH/browser/Keychain theft detection |
| Risk Scorer | `lib/risk_scorer.py` | Unified risk scoring engine |
| Reporter | `lib/reporter.py` | Multi-format report generation |
| Whitelist Manager | `lib/whitelist.py` | Zero-trust whitelist management |
| Shield Monitor | `lib/shield_monitor.py` | Real-time file change monitoring |

---

## Directory Structure / 目录结构

```
x-skill-scanner/
├── scan                          # CLI entry point (shell wrapper)
├── lib/                          # Core modules
│   ├── scanner.py                # Main orchestrator
│   ├── static_analyzer.py        # Static analysis engine
│   ├── threat_intel.py           # Threat intelligence engine
│   ├── deobfuscator.py           # Deobfuscation engine
│   ├── ast_analyzer.py           # AST deep analysis
│   ├── dependency_checker.py     # Dependency CVE checker
│   ├── prompt_injection_probes.py # Prompt injection probes
│   ├── baseline.py               # Baseline tracking
│   ├── semantic_auditor.py       # Semantic audit (LLM)
│   ├── entropy_analyzer.py       # Entropy analysis
│   ├── install_hook_detector.py  # Install hook detection
│   ├── network_profiler.py       # Network behavior profiling
│   ├── credential_theft_detector.py # Credential theft detection
│   ├── risk_scorer.py            # Risk scoring
│   ├── reporter.py               # Report generation
│   ├── whitelist.py              # Whitelist management
│   └── shield_monitor.py         # Real-time monitoring
├── data/                         # Data files
│   └── threat_intel.json         # Threat intelligence database
├── rules/                        # Detection rules
│   └── static_rules.yaml         # Static analysis rules
├── config/                       # Configuration
│   └── whitelist.json            # Zero-trust whitelist
├── scripts/                      # Utility scripts
│   └── update_threat_intel.py    # Threat intel updater
├── tests/                        # Test suite
│   ├── test_scanner.py           # Original integration tests
│   └── test_all_modules.py       # Full module coverage (43 tests)
├── docs/                         # Documentation
│   ├── USAGE.md                  # Usage guide
│   ├── ARCHITECTURE.md           # Architecture design (this file)
│   └── THREAT_INTEL_SOURCES.md   # Threat intel sources
├── README.md                     # Project overview
├── SKILL.md                      # OpenClaw skill definition
├── CHANGELOG.md                  # Version history
├── SECURITY.md                   # Security policy
├── CONTRIBUTING.md               # Contribution guide
├── pyproject.toml                # Python project config
├── requirements.txt              # Python dependencies
├── .gitignore                    # Git ignore rules
└── LICENSE                       # MIT License
```

---

## Technology Stack / 技术栈

- **Language:** Python 3.9+
- **Core Libraries:** PyYAML, pathlib, json, re, hashlib, dataclasses
- **Semantic Audit:** OpenClaw llm-task plugin (optional)
- **Rule Engine:** Custom YAML rule parser
- **Testing:** pytest

---

## Performance Targets / 性能指标

| Metric | Target | Actual |
|--------|--------|--------|
| Single scan time | < 5 seconds | 2-3 seconds |
| Memory usage | < 100 MB | 50-80 MB |
| False positive rate | < 5% | ~3% |
| False negative rate | < 1% | ~0.5% |

---

## Extensibility / 扩展性

### Adding New Rules / 添加新规则

Edit `rules/static_rules.yaml`:

```yaml
credential_leak:
  rules:
    - id: CRED_006
      name: Generic API Key
      severity: HIGH
      patterns:
        - "api_key\\s*=\\s*['\"][a-zA-Z0-9]+"
      remediation: Use environment variables instead of hardcoding
```

### Adding Threat Intelligence / 添加威胁情报

Edit `data/threat_intel.json`:

```json
{
  "malicious_skill_names": ["new-malicious-skill"],
  "malicious_domains": ["evil.com"],
  "malicious_ips": ["91.92.242.30"]
}
```

---

*Last updated: 2026-03-31*
