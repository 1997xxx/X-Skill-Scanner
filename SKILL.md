---
name: x-skill-scanner
version: 3.6.0
author: 小龙虾一号
license: MIT
description: >
  X Skill Scanner — Enterprise-grade AI Agent skill security scanner.
  Twelve-layer defense pipeline detecting malicious skills, credential theft,
  prompt injection, obfuscated code, C2 communication, and more.
  Runs locally via built-in exec + Python script. No external service required.
  Triggers on: scan skill, audit skill, check skill security, 扫描技能, 安全检查技能, 审计AI技能.
keywords: [security, scan, audit, ai-agent, skill-security, credential-theft, prompt-injection, obfuscation]
triggers:
  - scan skill
  - audit skill
  - check skill security
  - skill vulnerability scan
  - scan for malware
  - check skill safety
  - 扫描技能
  - 安全检查技能
  - 审计AI技能
  - 检查技能漏洞
  - 技能安全扫描
metadata:
  {"openclaw":{"emoji":"🛡️","requires":{"bins":["python3"]},"primaryEnv":"XSS_SCAN_PATH","skillKey":"x-skill-scanner"}}
---

# X Skill Scanner

Enterprise-grade AI Agent skill security scanner. Twelve-layer defense pipeline running locally via `exec` + Python script.

## Language Detection Rule

Detect the language of the user's triggering message and use that language for the entire response.

| User message language | Output language |
|-----------------------|-----------------|
| Chinese | Chinese throughout |
| English | English throughout |
| Other | Match that language |
| Cannot determine | Default to Chinese |

---

## Use This Skill When

- the user asks to scan an AI skill / agent plugin for security risks
- the user mentions installing a new skill and wants a safety check first
- the user provides a local path or GitHub URL to a skill project
- the user asks about credential theft, prompt injection, or malicious code in a skill

## Do Not Use This Skill When

- the user asks to scan general web applications (not skill/plugin projects)
- the user expects continuous monitoring or background polling after the turn ends
- the user asks for runtime behavior analysis (this is static analysis only)

---

## Tooling Rules

This skill ships with `lib/scanner.py` — a self-contained Python CLI scanner.
The script path relative to the skill install directory is `lib/scanner.py`.

**Always use `scanner.py` via `exec`.** Command reference:

```bash
# Basic scan (all 12 layers)
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path>

# Quick mode (skip LLM semantic audit)
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --no-semantic

# JSON output (machine-readable)
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --json

# HTML report
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --format html -o report.html

# SARIF output (GitHub Security Tab)
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --format sarif -o results.sarif

# Scan remote skill URL
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py --url <skill-url>
```

---

## Canonical Flows

### 1. Local Skill Scan → `scanner.py -t <path>`

**Trigger phrases:** 扫描本地技能、安全检查技能、audit local skill, scan skill security

- If the user provides a local directory path containing a skill (has `SKILL.md`).
- Run `scanner.py -t <path>` and present the result.
- If risk level is HIGH or EXTREME, warn the user not to install.

### 2. Remote Skill Scan → `scanner.py --url <url>`

**Trigger phrases:** 扫描远程技能、scan remote skill, check GitHub skill security

- If the user provides a GitHub repository URL or remote skill URL.
- Clone to a temp directory first, then scan.
- Clean up the temp directory after scanning.

### 3. Install-Time Safety Check → auto-detect

**Trigger phrases:** 安装技能、install skill, clawhub install, add skill

- If the user mentions installing a skill, offer to scan it first.
- Ask for the skill path or let the user specify it.
- Run the scan before proceeding with installation advice.

---

## Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| 🟢 LOW | 0–19 | ✅ Safe to install |
| 🟡 MEDIUM | 20–49 | ⚠️ Review findings before installing |
| 🔴 HIGH | 50–79 | ❌ Do not install without approval |
| ⛔ EXTREME | 80–100 | ❌ Block immediately |

---

## Twelve-Layer Defense Pipeline

| Layer | Engine | Capability |
|-------|--------|------------|
| 1 | Threat Intelligence | 380+ malicious skill names · IOC domains/IPs · attack pattern matching |
| 2 | Deobfuscation Engine | Base64/ROT13/Hex · BiDi override · zero-width chars · TR39 · Zlib · string concatenation |
| 3 | Static Analysis | 194+ rules · credential leak · injection · supply chain · time bombs |
| 4 | AST Deep Analysis | indirect execution · data flow tracking · dynamic imports · deserialization |
| 5 | Dependency Checker | requirements.txt / package.json CVE matching (20+ high-risk packages) |
| 6 | Prompt Injection Probes | 25+ probes · system override · role hijacking · DAN/Jailbreak |
| 7 | Baseline Tracking | SHA-256 fingerprint · rug-pull detection · change auditing |
| 8 | Semantic Audit | LLM intent analysis (optional, triggered for high-risk files) |
| 9 | Entropy Analysis | Shannon entropy · CJK adaptive thresholds · encoded payload detection |
| 10 | Install Hook Detector | setup.py/cmdclass · postinstall · shell RC modification · cron injection |
| 11 | Network Behavior Profiler | endpoint extraction · IP direct connection · covert channels · C2 patterns |
| 12 | Credential Theft Detection | osascript phishing · SSH/AWS key reading · browser cookie theft · Keychain access |

---

## Guardrails

- Do not expose API keys or tokens in output shown to the user.
- Do not modify or delete any files in the scanned skill directory.
- Do not execute any code from the scanned skill — this is static analysis only.
- Clean up temporary directories after remote scans.
- Present scan results faithfully; do not downplay HIGH or EXTREME findings.

---

## Result Presentation

After running a scan, present results in this order:

1. **Risk Level & Score** — one-line verdict (e.g., "🔴 HIGH — 52/100")
2. **Summary** — total files scanned, total findings, breakdown by severity
3. **Critical Findings** — list all CRITICAL/HIGH findings with file, line, and remediation
4. **Recommendation** — clear install/block advice based on risk level

Use the user-facing risk labels (LOW/MEDIUM/HIGH/EXTREME), not internal score details, unless the user asks for them.
