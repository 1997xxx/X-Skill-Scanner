# X-Skill-Scanner Version History

## Current Version: v6.1.0 (2026-04-04)

### v6.1.0 - Performance Optimization & Enhanced Testing

**Release Date:** 2026-04-04

**Major Changes:**
- Lazy loading engine system (startup time: ~2s → ~0.14s)
- Async LLM review with ThreadPoolExecutor
- Scan result caching with SHA256 validation
- Parallel scanning with configurable workers
- Layered output (concise/standard/detailed modes)
- Enhanced HTML reports with Chart.js visualization
- Comprehensive test suite with malicious skill samples

**New Files:**
- `lib/engine_loader.py` - Lazy loading engine manager
- `lib/scanner_lazy.py` - Lazy loading scanner implementation
- `lib/reporter_enhanced.py` - Enhanced reporter with layered output
- `lib/scan_cache.py` - Cache persistence module
- `lib/parallel_scanner.py` - Parallel scanning module
- `tests/test_malicious_detection.py` - Malicious skill detection tests
- `tests/test_performance.py` - Performance benchmark tests
- `references/installation-flows.md` - Installation documentation

**Test Data:**
- `tests/test_data/malicious/weather-query/` - Base64 backdoor sample
- `tests/test_data/malicious/nova-stealer/` - Credential theft sample
- `tests/test_data/malicious/reverse-shell/` - C2 beacon sample
- `tests/test_data/safe/simple-helper/` - Safe skill sample
- `tests/test_data/edge_cases/security-tool/` - Edge case sample

**Performance Metrics:**
- Startup time: 0.138s (7 engines loaded)
- Quick scan: ~30% faster than standard
- Cache hit: ~10x speedup
- Parallel scan: ~2-3x speedup on multi-core

**SKILL.md Optimization:**
- Reduced from 499 lines to 233 lines (53% reduction)
- Layered trigger words (core → extended → context)
- Moved detailed docs to references/

---

### v6.0.0 - Architecture Upgrade & Code Quality

**Release Date:** 2026-04-03

**Major Changes:**
- Uniﬁed data models (models.py + models_v2.py → single models.py)
- SubAgent-based review engine (replaced HTTP API calls)
- ThreatCategory enum (replaced FindingType)
- Severity comparison operators (>, >=)
- Heuristic fallback (when SubAgent unavailable)
- Negative example detection (19 patterns)
- Created constants.py for shared conﬁguration
- Replaced print() with _p() helper (stderr output)
- Extracted CSS to constants.py (HTML_CSS_BASE)
- Fixed Finding creation bug in static_analyzer.py
- Deprecated llm_reviewer.py (965 lines → _deprecated)
- Refactored SKILL.md (<500 lines core logic)
- Created references/ directory for detailed docs

**Code Quality:**
- Long lines reduced: 33 → 12 (>120 chars)
- Magic numbers replaced with constants
- Function length optimization ongoing

**Documentation:**
- README.md rewritten for v6.0
- CHANGELOG.md created
- DEFENSE_LAYERS.md and RISK_LEVELS.md added

**Testing:**
- All 29 modules load successfully
- Integration tests pass
- Self-scan validation pass

---

## Previous Versions

### v5.5.0 (2026-04-02) - Architecture Upgrade
- Adaptive scanning (quick/standard/full modes)
- Skill profiler with trust score
- False positive pre-filter
- Cross-layer correlation analysis

### v5.2.0 (2026-04-02) - Enhanced Deobfuscation
- Multi-line hex array reconstruction
- Base64 byte literal detection
- String concatenation assembly

### v5.1.0 (2026-04-01) - Baseline & Correlation
- SHA-256 baseline tracking (Rug-Pull detection)
- Cross-layer correlation engine
- Attack chain pattern recognition

### v5.0.0 (2026-03-31) - Initial Release
- 12-layer defense pipeline
- LLM secondary review
- Multi-format reports (Text/HTML/JSON/MD/SARIF)

---

## Version Policy

- **Major (X.0.0):** Breaking changes, architecture upgrades
- **Minor (x.Y.0):** New features, engines, capabilities
- **Patch (x.y.Z):** Bug ﬁxes, performance improvements

## Compatibility

- **OpenClaw:** v1.0+
- **Python:** 3.9+
- **Platform:** macOS / Linux / Windows (WSL)
