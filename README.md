# 🔍 X Skill Scanner

**企业级 AI Agent 技能安全扫描器** — 十二层深度防御，保护你的 AI Agent 免受恶意技能投毒。

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-v3.6.0-blue.svg)](CHANGELOG.md)

---

## 🚨 为什么需要这个工具？

ClawHub 已被 **472+ 恶意 Skills** 渗透（慢雾安全监测），包括下载量最高的热门技能。攻击手法包括：
- Base64 编码后门 + 远程代码执行
- osascript 伪造 macOS 系统密码弹窗（Nova Stealer）
- SSH/AWS 密钥窃取 + webhook 外传
- 浏览器 Cookie/LocalStorage 数据窃取

> ⚠️ **每个安装的技能都是对代码的信任 — 这份信任值得被审视。**

---

## 🛡️ 十二层防御管线

| 层级 | 引擎 | 检测能力 |
|------|------|---------|
| 1 | 🔍 威胁情报 | 380+ 恶意技能名 · IOC 域名/IP · 攻击模式匹配 |
| 2 | 🧹 去混淆引擎 | Base64/Hex/BiDi/零宽字符/TR39/Zlib/字符串拼接 |
| 3 | 🔎 静态分析 | 194+ 规则 · 凭证/注入/供应链/时间炸弹 |
| 4 | 🌳 AST 深度分析 | Taint 追踪 · 间接执行 · 动态导入 |
| 5 | 📦 依赖检查 | requirements.txt / package.json CVE 匹配 |
| 6 | 💉 提示词注入探针 | 25+ 探针 · DAN/Jailbreak/系统覆盖 |
| 7 | 📋 基线追踪 | SHA-256 指纹 · Rug-Pull 检测 |
| 8 | 🧠 语义审计 | LLM 深度意图分析（可选） |
| 9 | 📊 熵值分析 | Shannon 熵 · CJK 自适应阈值 · 编码 payload |
| 10 | 🔧 安装钩子检测 | postinstall · setup.py · Shell RC · Cron |
| 11 | 🌐 网络行为画像 | 端点提取 · IP 直连 · 隐蔽信道 · C2 特征 |
| 12 | 🔐 凭证窃取检测 | osascript 弹窗 · SSH/AWS 密钥 · 浏览器数据 · Keychain |

---

## 🚀 快速开始

```bash
# 克隆仓库
git clone https://github.com/1997xxx/x-skill-scanner.git
cd skill-scanner

# 安装依赖
pip install -r requirements.txt

# 扫描单个技能
./scan -t ./my-skill/

# 快速模式（跳过 LLM 语义审计）
./scan -t ./my-skill/ --no-semantic

# HTML 报告
./scan -t ./my-skill/ --format html -o report.html

# SARIF 输出（对接 GitHub Security Tab）
./scan -t ./my-skill/ --format sarif -o results.sarif
```

---

## 📊 风险等级

| 等级 | 分数 | 处理 |
|------|------|------|
| 🟢 LOW | 0-19 | ✅ 自动通过 |
| 🟡 MEDIUM | 20-49 | ⚠️ 人工确认 |
| 🔴 HIGH | 50-79 | ❌ 禁止安装 |
| ⛔ EXTREME | 80-100 | ❌ 立即阻止 |

---

## 📖 文档

| 文档 | 说明 |
|------|------|
| [使用指南](docs/USAGE.md) | 安装、配置、API 参考 |
| [架构设计](docs/ARCHITECTURE.md) | 系统架构与技术实现 |
| [威胁情报来源](docs/THREAT_INTEL_SOURCES.md) | IOC 数据来源与统计 |
| [贡献指南](CONTRIBUTING.md) | 如何贡献代码 |
| [变更日志](CHANGELOG.md) | 版本历史 |
| [安全政策](SECURITY.md) | 漏洞报告流程 |

---

## 🤝 致谢

本项目的威胁情报和检测能力参考了以下安全团队的研究成果：

- [Koi.ai](https://koi.ai) — ClawHavoc Report (341 malicious skills)
- [Snyk](https://snyk.io) — ToxicSkills Campaign Analysis
- [SmartChainArk](https://github.com/smartchainark/skill-security-audit) — 13 检测器 + 误报调优
- [慢雾安全](https://slowmist.com) — ClawHub 恶意 skills 投毒分析
- [腾讯科恩实验室](https://ke.tencent.com) — OpenClaw Skills 风险分析
- [MurphySec](https://murphysec.com) — AI Agent Security Report

---

## 📄 许可证

MIT License

---

**X Skill Scanner Team** — 您的 AI 技能安全守护者 🛡️

*版本: v3.6.0 | 更新时间: 2026-03-30*
