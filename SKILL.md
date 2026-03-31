---
name: x-skill-scanner
version: 4.1.0
author: 吸音
license: MIT
description: >
  X Skill Scanner — 企业级 AI Agent 技能安全扫描器（技能画像 + 自适应扫描 + 误报预过滤 + LLM 二次审查）
  Enterprise-grade AI Agent skill security scanner with skill profiling, adaptive scanning, FP pre-filter, and LLM review.
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

**企业级 AI Agent 技能安全扫描器** — 十二层深度防御，保护你的 AI Agent 免受恶意技能投毒。

**Enterprise-grade AI Agent skill security scanner** — Twelve-layer defense pipeline protecting your AI agents from malicious skill poisoning.

## 语言检测规则 / Language Detection Rule

根据用户触发消息的语言，使用相同语言回复整个结果。

Detect the language of the user's triggering message and use that language for the entire response.

| 用户消息语言 | 输出语言 |
|-------------|---------|
| 中文 | 全文使用中文 |
| English | English throughout |
| 其他语言 | 匹配该语言 |
| 无法判断 | 默认使用中文 |

---

## 使用场景 / When to Use This Skill

- 用户请求扫描 AI 技能 / Agent 插件的安全风险
- 用户提到安装新技能，希望先做安全检查
- 用户提供本地路径或 GitHub URL 指向一个技能项目
- 用户询问技能中的凭证窃取、提示词注入或恶意代码问题

- The user asks to scan an AI skill / agent plugin for security risks
- The user mentions installing a new skill and wants a safety check first
- The user provides a local path or GitHub URL to a skill project
- The user asks about credential theft, prompt injection, or malicious code in a skill

## 不使用场景 / Do Not Use This Skill When

- 用户请求扫描通用 Web 应用（非技能/插件项目）
- 用户期望持续监控或后台轮询
- 用户请求运行时行为分析（本工具仅支持静态分析）

- The user asks to scan general web applications (not skill/plugin projects)
- The user expects continuous monitoring or background polling after the turn ends
- The user asks for runtime behavior analysis (this is static analysis only)

---

## 工具规则 / Tooling Rules

本技能包含 `lib/scanner.py` — 一个自包含的 Python CLI 扫描器。

This skill ships with `lib/scanner.py` — a self-contained Python CLI scanner.

**始终通过 `exec` 调用 `scanner.py`。** 命令参考：

**Always use `scanner.py` via `exec`.** Command reference:

```bash
# 完整扫描（十二层防御）/ Full scan (all 12 layers)
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path>

# 快速模式（跳过 LLM 语义审计）/ Quick mode (skip LLM semantic audit)
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --no-semantic

# 禁用 LLM 二次审查 / Disable LLM review
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --no-llm-review

# 仅输出技能画像 / Profile only
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --profile-only --json

# JSON 输出（机器可读）/ JSON output (machine-readable)
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --json

# HTML 报告 / HTML report
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --format html -o report.html

# SARIF 输出（对接 GitHub Security Tab）/ SARIF output (GitHub Security Tab)
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <skill-path> --format sarif -o results.sarif

# 扫描远程技能 URL / Scan remote skill URL
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py --url <skill-url>
```

---

## 标准工作流 / Canonical Flows

### 1. 本地技能扫描 → `scanner.py -t <path>`

**触发词 / Trigger phrases:** 扫描本地技能、安全检查技能、audit local skill, scan skill security

- 用户提供包含技能的本地目录路径（有 `SKILL.md`）。
- 运行 `scanner.py -t <path>` 并展示结果。
- 如果风险等级为 HIGH 或 EXTREME，警告用户不要安装。

- If the user provides a local directory path containing a skill (has `SKILL.md`).
- Run `scanner.py -t <path>` and present the result.
- If risk level is HIGH or EXTREME, warn the user not to install.

### 2. 远程技能扫描 → `scanner.py --url <url>`

**触发词 / Trigger phrases:** 扫描远程技能、scan remote skill, check GitHub skill security

- 用户提供 GitHub 仓库 URL 或远程技能 URL。
- 先克隆到临时目录，然后扫描。
- 扫描完成后清理临时目录。

- If the user provides a GitHub repository URL or remote skill URL.
- Clone to a temp directory first, then scan.
- Clean up the temp directory after scanning.

### 3. 安装时安全检查 → 自动检测

**触发词 / Trigger phrases:** 安装技能、install skill, clawhub install, add skill

- 用户提到安装技能时，主动提出先扫描。
- 询问技能路径或让用户指定。
- 在安装建议之前运行扫描。

- If the user mentions installing a skill, offer to scan it first.
- Ask for the skill path or let the user specify it.
- Run the scan before proceeding with installation advice.

---

## 风险等级 / Risk Levels

| 等级 / Level | 分数 / Score | 处理 / Action |
|-------------|-------------|--------------|
| 🟢 LOW | 0–19 | ✅ 可安全安装 / Safe to install |
| 🟡 MEDIUM | 20–49 | ⚠️ 安装前审查发现项 / Review findings before installing |
| 🔴 HIGH | 50–79 | ❌ 未经批准禁止安装 / Do not install without approval |
| ⛔ EXTREME | 80–100 | ❌ 立即阻止 / Block immediately |

---

## 架构升级 / Architecture Upgrade (v4.1)

**v4.0 → v4.1 核心改进：**

| 改进项 | v4.0 | v4.1 |
|-------|------|------|
| 扫描策略 | 所有技能同一管线 | 技能画像 → 自适应策略 |
| LLM 审查 | 需 `--llm-review` 手动开启 | 默认开启，`--no-llm-review` 关闭 |
| 误报处理 | 仅 LLM 审查 | 误报预过滤 + LLM 二次审查 |
| 规则引擎 | 12 层独立检测 | 跨层关联 + 上下文感知 |
| FP 过滤率 | ~70% | **~99%** (安全工具自引用) |

**新增模块：**
- `lib/skill_profiler.py` — 技能画像引擎（信任评分 + 策略推荐）
- `lib/fp_filter.py` — 误报预过滤器（8 类误报模式 + 5 类真实威胁指标）

**设计原则：**
- 安全工具自引用 → 自动标记 FP（规则定义、IOC 列表、探针文本）
- 真实恶意代码 → 全部保留（外传、凭证窃取、反向 Shell、混淆执行）
- 不确定 → 交给 LLM 二次审查

## 十二层防御管线 / Twelve-Layer Defense Pipeline

| 层级 / Layer | 引擎 / Engine | 检测能力 / Capability |
|-------------|--------------|----------------------|
| 1 | 🔍 威胁情报 / Threat Intel | 380+ 恶意技能名 · IOC 域名/IP · 攻击模式匹配 |
| 2 | 🧹 去混淆引擎 / Deobfuscation | Base64/ROT13/Hex · BiDi 覆盖 · 零宽字符 · TR39 · Zlib · 字符串拼接 |
| 3 | 🔎 静态分析 / Static Analysis | 194+ 规则 · 凭证泄露 · 注入 · 供应链 · 时间炸弹 |
| 4 | 🌳 AST 深度分析 / AST Deep Analysis | 间接执行 · 数据流追踪 · 动态导入 · 反序列化 |
| 5 | 📦 依赖检查 / Dependency Check | requirements.txt / package.json CVE 匹配（20+ 高危包） |
| 6 | 💉 提示词注入探针 / Prompt Injection | 25+ 探针 · 系统覆盖 · 角色劫持 · DAN/Jailbreak |
| 7 | 📋 基线追踪 / Baseline Tracking | SHA-256 指纹 · Rug-Pull 检测 · 变更审计 |
| 8 | 🧠 语义审计 / Semantic Audit | LLM 意图分析（可选，高风险文件触发） |
| 9 | 📊 熵值分析 / Entropy Analysis | Shannon 熵 · CJK 自适应阈值 · 编码 payload 检测 |
| 10 | 🔧 安装钩子检测 / Install Hooks | setup.py/cmdclass · postinstall · Shell RC 修改 · Cron 注入 |
| 11 | 🌐 网络行为画像 / Network Profiler | 端点提取 · IP 直连 · 隐蔽信道 · C2 特征 |
| 12 | 🔐 凭证窃取检测 / Credential Theft | osascript 伪造弹窗 · SSH/AWS 密钥读取 · 浏览器 Cookie 窃取 · Keychain 访问 |

---

## 安全边界 / Guardrails

- 不要在向用户展示的输出中暴露 API 密钥或令牌。
- 不要修改或删除被扫描技能目录中的任何文件。
- 不要执行被扫描技能中的任何代码 — 本工具仅支持静态分析。
- 远程扫描后清理临时目录。
- 如实呈现扫描结果；不要淡化 HIGH 或 EXTREME 级别的发现。

- Do not expose API keys or tokens in output shown to the user.
- Do not modify or delete any files in the scanned skill directory.
- Do not execute any code from the scanned skill — this is static analysis only.
- Clean up temporary directories after remote scans.
- Present scan results faithfully; do not downplay HIGH or EXTREME findings.

---

## 结果展示 / Result Presentation

运行扫描后，按以下顺序展示结果：

After running a scan, present results in this order:

1. **风险等级与分数 / Risk Level & Score** — 一行结论（例如 "🔴 HIGH — 52/100"）
2. **摘要 / Summary** — 扫描文件总数、发现项总数、按严重程度分类
3. **关键发现 / Critical Findings** — 列出所有 CRITICAL/HIGH 发现项，含文件、行号和修复建议
4. **建议 / Recommendation** — 基于风险等级给出明确的安装/阻止建议

使用面向用户的风险标签（LOW/MEDIUM/HIGH/EXTREME），除非用户要求，否则不展示内部评分细节。

Use the user-facing risk labels (LOW/MEDIUM/HIGH/EXTREME), not internal score details, unless the user asks for them.
