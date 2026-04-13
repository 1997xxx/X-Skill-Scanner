# X-Skill-Scanner Version History

## Current Version: v7.1.0 (2026-04-13)

### v7.1.0 - Platform Detection & AGENT.md Hook

**Release Date:** 2026-04-13

**Major Changes:**
- 保留完整 12 层防御管线（核心扫描能力）
- 新增平台检测功能（Step 0: 检测 OpenClaw/Claude Code/Cursor/Windsurf/QClaw）
- AGENT.md 钩子注入机制替代独立 hook 脚本
- LLM 语义审计通过 Skill Prompt 实现（不依赖 Python 代码调用 LLM API）
- scan_skill.sh 新增平台自动检测

**Changes:**
- SKILL.md: 添加 12 层防御管线详细表格，添加平台检测流程图
- postInstall: 改为注入 AGENT.md 规则而非创建独立 hook 脚本
- scripts/scan_skill.sh: 新增 detect_platform() 函数
- references/installation-flows.md: 更新 AGENT.md 注入说明

**平台检测逻辑:**
1. 检查 ~/.openclaw 目录 → OpenClaw
2. 检查环境变量 (CLAUDE_CODE, CURSOR, WINDSURF, QCLAW)
3. 检查配置文件 (~/.cursor/settings.json, ~/.windsurf/config.json, ~/.qclaw/config.json)
4. 默认 → unknown

---

### v7.0.0 - Pure Skill Architecture

**Release Date:** 2026-04-13

**Major Changes:**
- 纯 Skill 架构 - 标准化扫描流程
- 二次语义审计 Prompt 模板化
- 安装前自动触发机制 (pre_install hook)
- 跨平台兼容 (OpenClaw/Claude Code/Cursor/Windsurf/QClaw)
- 标准化工具定义 (Tools)
- 报告模板化

**New Files:**
- `scripts/scan_skill.sh` - 扫描入口脚本
- `prompts/semantic_review.md` - 二次语义审计 Prompt
- `prompts/scan_report.md` - 报告生成模板
- `prompts/install_advice.md` - 安装建议生成模板
- `prompts/scan_context.md` - 扫描上下文模板
- `hooks/pre_install_scan` - 安装前自动触发钩子

**Architecture:**
- Skill 工作流标准化 (检测 → 扫描 → 审计 → 报告 → 建议)
- 工具定义标准化 (scan_skill.sh, semantic_review, generate_report)
- Prompt 模板化 (支持多语言)
- 自动安装触发 (postInstall hook)

---

## v6.1.0 (2026-04-10)

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
