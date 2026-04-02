# 🔍 X Skill Scanner

**企业级 AI Agent 技能安全扫描器** — 十二层深度防御，保护你的 AI Agent 免受恶意技能投毒。

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-v5.2.0-blue.svg)](CHANGELOG.md)
[![GitHub Stars](https://img.shields.io/github/stars/1997xxx/X-Skill-Scanner?style=social)](https://github.com/1997xxx/X-Skill-Scanner)

📖 [English README →](README.md)

---

## 🚨 为什么需要这个工具

ClawHub 已被 **472+ 恶意 Skills** 渗透（慢雾安全监测），包括下载量最高的热门技能。每个安装的技能都是一份信任——这份信任值得被审视。

### 真实攻击案例

| 攻击手法 | 案例 | 影响 |
|---------|------|------|
| Base64 编码后门 + 远程代码执行 | `weather-query` 伪装成天气工具，实际下载勒索软件 | 文件系统加密 |
| osascript 伪造密码弹窗 | Nova Stealer 窃取 macOS 钥匙串凭证 | 账号泄露 |
| SSH/AWS 密钥外传 | 通过 Discord Webhook 发送窃取的凭证 | 云资源沦陷 |
| 浏览器 Cookie 窃取 | 读取 localStorage / Keychain 中的会话令牌 | 会话劫持 |

---

## ✨ 核心功能

### 1️⃣ 十二层深度防御 — 从静态到语义的全方位检测

X Skill Scanner 不是简单的正则匹配工具。它构建了 **12 层独立检测引擎**，覆盖从表面特征到深层意图的完整攻击面：

- **表层检测** — 威胁情报匹配（380+ 已知恶意技能名、IOC 域名/IP）、白名单校验
- **代码分析** — 194+ 静态规则、AST 污点追踪、依赖 CVE 检查、去混淆引擎
- **行为画像** — 网络端点提取、安装钩子检测、凭证窃取模式识别
- **语义理解** — LLM 驱动的意图分析，识别肉眼无法发现的隐蔽威胁
- **关联分析** — 跨引擎攻击链检测，发现多阶段组合攻击

**开箱即用，零配置。** 扫描器自动发现 OpenClaw 的 LLM Provider 配置，无需额外设置环境变量。

### 2️⃣ 智能去混淆 — 还原多层混淆后的真实载荷

恶意技能最常用的手法是混淆。扫描器内置 **5 种去混淆引擎**，能穿透任意层数的编码伪装：

| 技术 | 说明 | 示例 |
|------|------|------|
| Base64 解码 | 自动识别并解码 `base64.b64decode()`、`b'...'` 字面量 | `Y3VybCAtcy...` → `curl -s ...` |
| Hex 数组重组 | 跨行收集 `[0x63, 0x75, 0x72, ...]` 字节数组，去除空字节后还原 | `curl\x00 -s\x00` → `curl -s` |
| 字符串拼接还原 | 识别 `_part1_ + _part2_ + ...` 模式，重组后解码 | 分散的 Base64 片段 → 完整命令 |
| BiDi 字符检测 | 检测 Unicode 双向覆盖字符（CVE-2021-42574） | 视觉欺骗型文件名 |
| 零宽字符检测 | 检测不可见字符注入 | 隐藏的水印/标识符 |

**报告直接展示解码后的恶意载荷** — 不再需要人工逆向混淆代码。

### 3️⃣ 画像驱动自适应扫描 — 速度与深度的最佳平衡

不是所有技能都需要全量扫描。扫描器先对技能进行**信任画像评估**，自动选择扫描策略：

```
信任评分 ≥ 70  → 快速模式 (3 层)    ~3 秒
信任评分 40-69 → 标准模式 (12 层)   ~15 秒
信任评分 < 40  → 全面模式 (12 层 + LLM 逐条审查)  ~60 秒
```

画像评估维度：作者可信度、技能类型、文件结构合理性、红旗标记等。

### 4️⃣ LLM 批量二次审查 — API 调用减少 70%+

传统方案对每条发现单独调用 LLM，API 开销巨大。扫描器采用**按文件分组批量审查**策略：

- 同一文件的所有发现合并为一次 LLM 调用
- 附带完整代码上下文，提高判断准确率
- 自动过滤误报（安全工具自引用、文档内容、测试数据）
- 支持跨 Provider 别名解析，自动适配你的 OpenClaw 默认模型

### 5️⃣ 跨层关联分析 — 发现多阶段攻击链

单个检测引擎的发现可能是孤立的，但多个引擎的组合信号才是真正的威胁。扫描器识别 **6 种攻击链模式**：

| 攻击链 | 组成引擎 | 典型场景 |
|--------|---------|---------|
| C2 渗透链 | 去混淆 + 网络 + 持久化 | 混淆下载远控 → 建立 C2 → 持久化 |
| 凭据收割链 | 凭据窃取 + 数据外传 | 读取 SSH 密钥 → Webhook 外发 |
| 供应链攻击 | 恶意依赖 + 安装钩子 | 引入恶意包 → postinstall 执行 |
| Rug-Pull 模式 | 基线变更 + 语义风险 | 正常技能更新后植入恶意代码 |
| 社交工程链 | 提示词注入 + 利用 | 绕过系统指令 → 执行危险操作 |
| 反向 Shell 链 | 反向 Shell + 网络 + 混淆 | 混淆反弹 Shell 连接 |

### 6️⃣ 多格式报告 — 对接你的工作流

| 格式 | 用途 |
|------|------|
| **Text** | 终端快速查看 |
| **HTML** | 交互式报告，含解码恶意载荷高亮区块 |
| **JSON** | 机器可读，CI/CD 集成 |
| **Markdown** | GitHub Issues / PR 评论 |
| **SARIF** | GitHub Security Tab 原生集成 |

---

## 🛡️ 十二层防御管线

| 层级 | 引擎 | 能力 |
|------|------|------|
| 0 | 🎯 技能画像 | 信任评分 · 扫描策略推荐 · 风险指纹 |
| 1 | 🔍 威胁情报 | 380+ 恶意技能名 · IOC 域名/IP · 攻击模式 |
| 2 | 🧹 去混淆 | Base64/十六进制/双向字符/零宽字符/TR39/Zlib/字符串拼接 |
| 3 | 🔎 静态分析 | 194+ 规则 · 凭据/注入/供应链/逻辑炸弹检测 |
| 4 | 🌳 AST 深度分析 | 污点追踪 · 间接执行 · 动态导入 |
| 5 | 📦 依赖检查 | requirements.txt / package.json CVE 漏洞匹配（Python/Node.js） |
| 6 | 💉 提示注入 | 25+ 探针 · 系统覆盖 · 角色劫持 · DAN/越狱检测 |
| 7 | 📋 基线追踪 | SHA-256 指纹 · 撤资跑路检测 |
| 8 | 🧠 语义审计 | LLM 意图分析（可选，针对高风险文件） |
| 9 | 📊 熵值分析 | 香农熵 · 中日韩自适应阈值 · 编码载荷检测 |
| 10 | 🔧 安装钩子 | postinstall · setup.py · Shell 启动项 · Cron 注入 |
| 11 | 🌐 网络画像 | 端点提取 · IP 直连 · 隐蔽通道 · C2 通信检测 |
| 12 | 🔐 凭据窃取 | osascript 钓鱼 · SSH/AWS 密钥 · 浏览器 Cookie · 钥匙串 |
| 🔗 | 跨层关联 | 多引擎攻击链检测 · 关联评分 |

---

## 🚀 快速开始

### 作为 OpenClaw 技能（推荐）

```bash
# 克隆到 skills 目录
git clone https://github.com/1997xxx/X-Skill-Scanner.git \
  ~/.openclaw/skills/x-skill-scanner

# 重启 OpenClaw — 技能自动注册
openclaw gateway restart

# 现在只需说："安装 xxx skill" 或 "扫描这个技能"
# 扫描器会在任何技能安装前自动触发
```

### 独立命令行

```bash
# 扫描本地技能
python3 lib/scanner.py -t ./my-skill/

# 扫描远程技能 URL
python3 lib/scanner.py --url https://github.com/user/skill-repo

# 快速模式（跳过 LLM 语义审计）
python3 lib/scanner.py -t ./my-skill/ --no-semantic

# HTML 报告（含解码恶意载荷高亮）
python3 lib/scanner.py -t ./my-skill/ --format html -o report.html

# SARIF 输出（对接 GitHub Security Tab）
python3 lib/scanner.py -t ./my-skill/ --format sarif -o results.sarif
```

### 配置

**零配置模式：** 扫描器自动从 `~/.openclaw/openclaw.json` 发现 LLM Provider，无需手动设置。

如需自定义 Provider：
```bash
export OPENAI_BASE_URL="https://your-provider.com/v1/chat/completions"
export OPENAI_API_KEY="your-api-key"
export OPENAI_MODEL="gpt-4o-mini"
```

### 命令行选项

```
-t TARGET             目标技能目录或文件
--url URL             远程技能 URL（自动克隆并扫描）
--no-semantic         跳过 LLM 语义审计
--no-llm-review       跳过 LLM 二次审查
--no-fp-filter        跳过误报预过滤器
--format FORMAT       输出格式：text(默认)/html/json/md/sarif
-o OUTPUT             输出文件路径
--whitelist FILE      自定义白名单 JSON
--threat-intel FILE   自定义威胁情报 JSON
--path-filter PATTERN 路径排除正则
--install             扫描后询问是否安装
--no-prompt           跳过安装询问（CI/自动化）
--install-to PATH     指定安装目录
```

---

## 🔄 持续防护

X Skill Scanner 不仅仅是在需要时扫描 — 它提供**三层持续防护**，确保环境中的每个技能都经过审计：

### 1. 安装前自动扫描（AGENTS.md 注入）

作为 OpenClaw 技能安装后，扫描器会自动向 `AGENTS.md` 注入安全规则。这意味着**每次技能安装都会先触发扫描** — 无需手动操作。

```
用户："安装 xxx skill"
     → Agent 先自动扫描该技能
     → 展示结果（SAFE / MEDIUM / EXTREME）
     → 仅在风险可接受时才安装
```

### 2. 会话启动检查

每次新会话启动时自动检测新增或变更的技能：

```bash
# 检查所有技能目录自上次快照以来的变更
bash ~/.openclaw/skills/clawhub/scripts/check-skills-change.sh
```

如果发现新增或修改的技能 → 自动执行完整扫描并报告。

### 3. 每日定时安全巡检（Cron Job）

设置每日定时任务，主动审计所有已安装技能：

```bash
# 推荐：每天上午 9:00（Asia/Shanghai 时区）
# 扫描所有技能目录的未授权变更
# 报告任何新发现或基线偏离
```

**通过 OpenClaw 设置：**
```
对 Agent 说："设置每天早上 9 点的技能安全巡检"
```

定时任务会：
- 运行 `check-skills-change.sh` 检测变更
- 对新技能或变更技能执行完整扫描
- 报告发现项（无变更则回复 HEARTBEAT_OK）
- 为未知技能创建初始基线

---

## 📊 风险等级

| 等级 | 分数 | 处理方式 |
|------|------|---------|
| 🟢 SAFE | 0–4 | ✅ 无显著问题 |
| 🟢 LOW | 5–19 | ✅ 可安全安装 |
| 🟡 MEDIUM | 20–49 | ⚠️ 建议人工审查后决定 |
| 🔴 HIGH | 50–79 | ❌ 未经批准禁止安装 |
| ⛔ EXTREME | 80–100 | ❌ 立即阻断 |

---

## 🏗️ 架构概览

```
技能输入（本地目录 / GitHub URL / zip）
    │
    ▼
┌─ 前置合法性检查 ─────────────────────────────────────────────┐
│  验证 SKILL.md 结构，阻止非技能输入                          │
├─ 白名单检查 ─────────────────────────────────────────────────┤
│  已知安全技能跳过完整扫描                                    │
├─ 技能画像 ───────────────────────────────────────────────────┤
│  信任评分 → 扫描策略（快速 / 标准 / 全面）                   │
├─ 12 层检测管线 ──────────────────────────────────────────────┤
│                                                              │
│  威胁情报 → 去混淆 → 静态分析 → AST                         │
│  依赖 → 提示注入 → 基线 → 语义                              │
│  熵值 → 安装钩子 → 网络 → 凭据窃取                          │
│                                                              │
├─ 跨层关联分析 ───────────────────────────────────────────────┤
│  识别 6 种攻击链模式                                         │
├─ 误报预过滤 ─────────────────────────────────────────────────┤
│  自动过滤安全工具自引用、文档、测试数据                      │
├─ LLM 批量审查 ───────────────────────────────────────────────┤
│  按文件分组发现 → 每个文件一次 LLM 调用                      │
├─ 风险评分 ───────────────────────────────────────────────────┤
│  跨层叠加 + 关联加成 + 最终判定                              │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
报告：文本 / HTML（含解码载荷） / JSON / Markdown / SARIF
```

---

## 🆕 版本亮点

### v5.2.0 (2026-04-02)
- 🚨 **解码恶意载荷** — 报告顶部醒目展示完整还原的恶意命令
- 🔓 **多层去混淆** — Hex 数组重组、Base64 bytes literal 检测、字符串拼接还原
- 🎯 **Provider 别名解析** — 跨 provider 自动解析模型名（修复 LLM 超时问题）
- 🧹 **碎片去重** — 仅展示完整载荷，碎片自动过滤

### v5.1.0 (2026-04-01)
- 伦理合规框架（六大原则）
- 项目卫生清理 + 版本同步

### v5.0.0 (2026-03-31)
- 画像驱动自适应扫描（快速/标准/全面模式）
- LLM 批量审查（API 调用减少 70%+）
- 跨层关联引擎（6 种攻击链模式）
- 风险评分升级（上下文感知修饰因子）

---

## 🤝 致谢

本项目的威胁情报和检测能力参考了以下安全团队的研究成果：

- [Koi.ai](https://koi.ai) — ClawHavoc Report (341 malicious skills)
- [Snyk](https://snyk.io) — ToxicSkills Campaign Analysis
- [SmartChainArk](https://github.com/smartchainark/skill-security-audit) — 13 detectors + false positive tuning
- [慢雾安全](https://slowmist.com) — ClawHub 投毒分析
- [腾讯科恩实验室](https://ke.tencent.com) — OpenClaw Skills 风险分析
- [MurphySec](https://murphysec.com) — AI Agent 安全报告

---

## 📄 许可证

MIT License

---

**X Skill Scanner Team** — 你的 AI 技能安全卫士 🛡️

*版本：v5.2.0 | 更新日期：2026-04-02*
