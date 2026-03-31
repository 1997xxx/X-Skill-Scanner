# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.6.0] - 2026-03-30

### Added
- **Credential Theft Detection Engine** (`lib/credential_theft_detector.py`)
  - osascript fake password dialog detection (Nova Stealer technique)
  - SSH/AWS/GCP/Azure credential path scanning
  - Browser data theft detection (localStorage, cookies, Keychain)
  - Credential exfiltration pattern detection (webhook.site, Discord webhooks)
- **CJK Adaptive Entropy Thresholds** — Chinese text naturally has higher Shannon entropy; thresholds auto-adjust to reduce false positives
- **Lock File Skip Logic** — Base64/entropy detectors skip `package-lock.json`, `yarn.lock` to avoid integrity hash false positives
- **Document File Down-weighting** — `.md`/`.txt` files get reduced confidence scores for privilege escalation patterns (sudo in docs ≠ actual exploitation)
- New IOC indicators: `webhook.site`, `socifiapp.com`, Nova Stealer C2 signatures
- New attack patterns: `osascript_password_phishing`, `browser_data_theft`, `webhook_exfiltration`, `nova_stealer_c2`

### Changed
- Threat intelligence database upgraded to v3.6.0 with sources from SmartChainArk, Tencent Keen Lab, SlowMist Security
- Default whitelist policy: zero-trust (empty defaults, explicit opt-in required)
- Safe functions whitelist audited: removed 23 potentially abusable functions (73 → 50)
- Scanner pipeline: 11 layers → 12 layers

### Fixed
- Dead code removal: `lib/reporter_part1.py`
- Version string consistency across all files
- SKILL.md and README.md updated to reflect current capabilities

### References
- [SmartChainArk skill-security-audit](https://github.com/smartchainark/skill-security-audit)
- [SlowMist ClawHub Poisoning Analysis](https://slowmist.com)
- [Tencent Keen Lab OpenClaw Skills Risk Analysis](https://ke.tencent.com)
- [MurphySec AI Agent Security Report](https://murphysec.com)

## [3.5.1] - 2026-03-30

### Added
- Floating navigation buttons in HTML reports (back to top/bottom)
- Clickable layer-by-layer results with smooth-scroll anchors
- Summary block flexbox layout (fixed table CSS interference)

### Changed
- Section reordering: Summary → Layer Results → Severity → Attack Patterns → Details
- Whitelist zero-trust overhaul: removed hardcoded `~/.openclaw/` exemptions

## [3.5.0] - 2026-03-30

### Added
- Comprehensive summary block in all report formats
- Layer-by-layer detection results display
- Attack pattern analysis chapter in reports
- Code snippet display for each finding

## [3.4.1] - 2026-03-30

### Fixed
- Code snippets now properly rendered in AST analysis reports (all formats)

## [3.4.0] - 2026-03-30

### Added
- MurphySec AI Agent Security Report integration
- Attack pattern analysis chapter in HTML/Markdown reports
- Default output format changed to HTML
- New IOC IPs: 95.92.242.30, 96.92.242.30, 202.161.50.59, 54.91.154.110
- New attack patterns: macos_staged_payload, reverse_shell, config_exfiltration, hidden_backdoor

## [3.3.0] - 2026-03-30

### Added
- **Entropy Analysis Engine** (`lib/entropy_analyzer.py`) — Shannon entropy calculation, high-entropy region detection
- **Install Hook Detector** (`lib/install_hook_detector.py`) — setup.py/cmdclass, postinstall, Shell RC modification, Cron injection
- **Network Behavior Profiler** (`lib/network_profiler.py`) — endpoint extraction, domain reputation, IP direct connection, covert channel detection, C2特征识别
- Enhanced risk scoring with new category weights

## [3.2.0] - 2026-03-30

### Added
- Threat intelligence comprehensive upgrade
- Koi.ai ClawHavoc Report integration (341 malicious skills)
- Snyk ToxicSkills Campaign data
- SkillJect Framework Analysis
- Multi-layer threat check pipeline
- Early exit on CRITICAL findings
- 50+ new static rules (supply_chain, time_bomb, crypto_abuse, anti_analysis)

## [3.1.0] - 2026-03-20

### Added
- Prompt injection probes (25+)
- Semantic audit refactoring (Provider API + Gateway fallback)
- `.scannerignore` gitignore-style exclusion rules
- SARIF output format

## [3.0.0] - 2026-03-20

### Added
- Deobfuscation engine (Base64/ROT13/Hex/BiDi/Zero-width/TR39/Zlib)
- AST depth analysis (taint tracking, indirect execution)
- Baseline tracking (SHA-256 fingerprint, Rug-Pull detection)
- Dependency checker (CVE matching)
- Path filter with shared filtering across all engines

## [2.0.0] - 2026-03-20

### Added
- Initial release with static analysis and threat intelligence
- 194+ detection rules
- 157 real malicious samples from MASB
- Multi-format reporting (text/json/html/md)

[Unreleased]: https://github.com/1997xxx/X-Skill-Scanner/compare/v3.6.0...HEAD
[3.6.0]: https://github.com/1997xxx/X-Skill-Scanner/compare/v3.5.1...v3.6.0
[3.5.1]: https://github.com/1997xxx/X-Skill-Scanner/compare/v3.5.0...v3.5.1
[3.5.0]: https://github.com/1997xxx/X-Skill-Scanner/compare/v3.4.1...v3.5.0
[3.4.1]: https://github.com/1997xxx/X-Skill-Scanner/compare/v3.4.0...v3.4.1
[3.4.0]: https://github.com/1997xxx/X-Skill-Scanner/compare/v3.3.0...v3.4.0
[3.3.0]: https://github.com/1997xxx/X-Skill-Scanner/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/1997xxx/X-Skill-Scanner/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/1997xxx/X-Skill-Scanner/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/1997xxx/X-Skill-Scanner/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/1997xxx/X-Skill-Scanner/releases/tag/v2.0.0
