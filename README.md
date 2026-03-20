# 🔍 Ant International Skill Scanner

**企业级 AI Agent 技能安全扫描器** - 整合 MaliciousAgentSkillsBench 157 个真实恶意样本

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## 🚀 快速开始

```bash
pip3 install -r requirements.txt
python3 install_hook.py
```

**完整文档：** [docs/USAGE.md](docs/USAGE.md)

---

## 🛡️ 核心能力

| 层级 | 检测内容 | 数量 |
|------|----------|------|
| **静态分析** | 凭证泄露、提示词注入、恶意代码 | 194+ 规则 |
| **威胁情报** | 已知恶意样本比对 + 技能名称黑名单 | 157 个 + 155 个名称 |
| **语义审计** | LLM 辅助意图识别 | 可选 |

### 检测的攻击模式

- 🔴 **凭证窃取** (45% 恶意技能)
- 🔴 **远程代码执行** (39%)
- 🔴 **行为操纵** (33%)
- 🔴 **数据外泄** (27%)

---

## 📖 文档

| 文档 | 说明 |
|------|------|
| [使用指南](docs/USAGE.md) | 安装、配置、API 参考 |
| [威胁情报来源](docs/THREAT_INTEL_SOURCES.md) | 恶意样本来源与统计 |
| [架构设计](docs/ARCHITECTURE.md) | 系统架构与技术实现 |
| [贡献指南](CONTRIBUTING.md) | 如何贡献代码 |

---

## 📄 许可证

MIT License

---

## 📞 支持

- **问题反馈：** GitHub Issues
- **安全漏洞：** SECURITY.md
- **讨论交流：** Discord/Slack

---

**Ant International Security Team** - 您的 AI 技能安全守护者！🛡️

*版本：v2.0.0 | 更新时间：2026-03-20*
