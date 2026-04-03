# X-Skill-Scanner Version History

## Current Version: v6.0.0 (2026-04-03)

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
