# Changelog

All notable changes to X-Skill-Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
