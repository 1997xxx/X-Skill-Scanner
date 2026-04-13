# Changelog

All notable changes to X-Skill-Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [7.1.0] - 2026-04-13

### 🎯 Platform Detection & AGENT.md Hook

#### Core Changes
- **Preserved:** 12-layer defense pipeline (core scanning capability)
- **New:** Platform detection (Step 0: OpenClaw/Claude Code/Cursor/Windsurf/QClaw)
- **New:** AGENT.md hook injection mechanism (replaces standalone hook script)
- **New:** LLM semantic audit via Skill Prompt (no Python LLM API calls)
- **Updated:** scan_skill.sh with platform auto-detection

#### Platform Detection Logic
1. Check ~/.openclaw directory → OpenClaw
2. Check environment variables (CLAUDE_CODE, CURSOR, WINDSURF, QCLAW)
3. Check config files (~/.cursor/settings.json, ~/.windsurf/config.json, ~/.qclaw/config.json)
4. Default → unknown

#### Files Changed
- `SKILL.md`: Added 12-layer defense pipeline table, platform detection flow
- `postInstall`: Inject AGENT.md rules instead of creating standalone hook
- `scripts/scan_skill.sh`: Added detect_platform() function
- `references/installation-flows.md`: Updated AGENT.md injection instructions

---

## [7.0.0] - 2026-04-13

### 🚀 Pure Skill Architecture

#### Core Changes
- Pure Skill architecture - standardized scanning workflow
- Secondary semantic audit prompt templated
- Pre-install automatic trigger mechanism (pre_install hook)
- Cross-platform compatibility (OpenClaw/Claude Code/Cursor/Windsurf/QClaw)
- Standardized tool definitions (Tools)
- Report templated

---

## [6.1.0] - 2026-04-10

### 🚀 Performance Optimization

#### Lazy Loading System
- **New:** `lib/engine_loader.py` — Lazy loading engine manager
- **New:** `lib/scanner_lazy.py` — Scanner with on-demand engine loading
- **Strategies:** quick (7 engines), standard (16 engines), full (all engines)
- **Startup time:** ~2s → ~0.14s (93% improvement)

#### Async Operations
- **New:** Async LLM review with `ThreadPoolExecutor`
- **Timeout:** 60s configurable timeout for LLM operations
- **Non-blocking:** Scanner returns immediately, LLM review in background

#### Scan Caching
- **New:** `lib/scan_cache.py` — Persistent cache with SHA256 validation
- **Cache location:** `~/.openclaw/cache/x-skill-scanner/`
- **Max age:** 7 days
- **Speedup:** ~10x on cache hits

#### Parallel Scanning
- **New:** `lib/parallel_scanner.py` — Multi-threaded/process scanning
- **Configurable workers:** 1-8 parallel workers
- **Speedup:** ~2-3x on multi-core systems

#### Multi-Platform Agent Adapter
- **New:** `lib/agent_adapter.py` — Abstract adapter interface and factory
- **New:** `lib/adapters/` — Platform-specific adapters
  - `openclaw_adapter.py` — OpenClaw (sessions_spawn)
  - `claude_code_adapter.py` — Claude Code (claude CLI)
  - `cursor_adapter.py` — Cursor/Windsurf (CLI)
  - `qclaw_adapter.py` — QClaw/CoPaw (CLI/API)
- **Config:** `config/agent_adapters.yaml` — Adapter configuration
- **Supported platforms:** OpenClaw, Claude Code, Cursor, Windsurf, QClaw, CoPaw, Heuristic

#### Environment Detection (v6.2)
- **New:** `lib/env_detector.py` — AI Agent 环境检测模块
- **Detection:** 自动检测当前 AI Agent 平台 (OpenClaw, Claude Code, Cursor, etc.)
- **LLM Config:** 获取 LLM 配置 (API Key, Endpoint, Model)
- **Connection Check:** 测试 LLM 是否可以正常调用
- **CLI Options:**
  - `--check-env-only`: 仅检测环境，不执行扫描
  - `--no-env-check`: 跳过环境检测
- **Auto-fallback:** LLM 连接异常时自动降级到启发式审查

### 📊 Enhanced Reporting

#### Layered Output
- **New:** `lib/reporter_enhanced.py` — Three output modes
  - `concise`: One line per finding (for terminals)
  - `standard`: Default detailed output
  - `detailed`: Full context with code snippets

#### HTML Reports
- **Chart.js visualization:** Risk distribution charts
- **Responsive design:** Mobile-friendly layout
- **Interactive:** Collapsible sections, search

### 🧪 Testing Improvements

#### Malicious Skill Samples
- **weather-query:** Base64 encoded backdoor
- **nova-stealer:** Credential theft with osascript phishing
- **reverse-shell:** C2 beacon and reverse shell

#### Test Suites
- **New:** `tests/test_malicious_detection.py` — Detection accuracy tests
- **New:** `tests/test_performance.py` — Performance benchmarks
- **Edge cases:** Security tool with security keywords (no false positives)

### 📝 Documentation

#### SKILL.md Optimization
- **Reduced:** 499 → 233 lines (53% reduction)
- **Layered triggers:** Core → Extended → Context
- **Moved:** Detailed installation docs to `references/installation-flows.md`

#### New Documentation
- `docs/OPTIMIZATION_REPORT.md` — Complete optimization report
- `references/installation-flows.md` — Detailed installation guide

---

## [6.0.0] - 2026-04-03

### 🚀 Major Architecture Changes

#### SubAgent-Based LLM Review (Breaking Change)
- **Replaced** direct HTTP API calls to idealab/OpenAI with OpenClaw `sessions_spawn` multi-agent communication
- **New file:** `lib/subagent_reviewer.py` — SubAgent-based review engine with heuristic fallback
- **Deprecated:** `lib/llm_reviewer.py` → renamed to `lib/_deprecated_llm_reviewer.py`
- **Benefits:**
  - Cross-platform compatibility (Windows/macOS/Linux)
  - No external API configuration required
  - Push-based result notification (zero polling cost)
  - Automatic fallback to heuristic review when SubAgent unavailable

#### Unified Data Models
- **Merged** `models.py` and `models_v2.py` into single unified schema
- **New unified `Finding` model** combines all fields from both legacy models
- **Added** `ThreatCategory` enum (replaces `FindingType`)
- **Added** `ScanResult` dataclass for complete scan results
- **Added** `Severity` comparison operators (`>`, `>=`)
- **Backward compatible:** `models_v2.py` now re-exports from `models.py`

### 🔧 Code Quality Improvements

- Consolidated method naming in `subagent_reviewer.py` (internal methods prefixed with `_`)
- Updated `self_check.py` to check new module names
- Updated `fp_filter.py` exclusion list for deprecated files
- Updated `llm_provider.py` docstring references
- All version references updated to v6.0.0

### 🐛 Bug Fixes (from v5.5.x)

- Fixed batch scanning mode for directories with multiple sub-skills
- Fixed PFC-004 autostart false positives in documentation files
- Added trusted domain whitelist for enterprise APIs (DingTalk, FBI, ODPS)
- Added LLM token context exclusion (12 patterns)
- Added Markdown table cell exclusion
- Added OpenClaw tool permission declaration exclusion
- Added npm postinstall script exclusion
- Added `.env.example` sample config exclusion
- Added `os.environ.items()` safe iteration exclusion

### 📊 Scanner Reliability (v5.6 improvements, now superseded)

- Exponential backoff retry (2s→4s→8s) for transient errors
- Circuit breaker mechanism (opens after 5 consecutive failures)
- Heuristic fallback classification when LLM unavailable
- Negative example detection (19 Chinese/English patterns)
- Batch LLM review by file grouping
- Elastic risk scoring based on LLM success rate

---

## [5.5.0] - 2026-04-02

### Architecture Upgrade
- Skill profiler integration
- Adaptive scanning strategies
- FP pre-filter engine
- LLM secondary review pipeline

---

## [5.2.0] - 2026-04-02

### Features
- Enhanced deobfuscation engines
- Improved threat intelligence matching

---

## [5.1.0] - 2026-04-01

### Features
- Baseline tracking for rug-pull detection
- Cross-layer correlation analysis

---

## [5.0.0] - 2026-03-31

### Initial Release
- Twelve-layer defense pipeline
- Threat intelligence engine
- Static analysis (194+ rules)
- AST deep analysis
- Dependency CVE checking
- Prompt injection probes
- Semantic audit
- Entropy analysis
- Install hook detection
- Network profiling
- Credential theft detection
