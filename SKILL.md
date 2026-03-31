---
name: x-skill-scanner
description: X Skill Scanner v3.6 - AI 技能安全扫描器（十二层防御 + 凭证窃取检测 + CJK 自适应熵值 + 零信任白名单）
metadata:
  {
    "openclaw": {
      "emoji": "🛡️",
      "requires": {
        "bins": ["python3"]
      },
      "install": [
        {
          "id": "pip",
          "kind": "pip",
          "packages": ["pyyaml"],
          "label": "安装 Python 依赖 (pip)"
        }
      ]
    }
  }
---

# X Skill Scanner v3.6

**企业级 AI Agent 技能安全扫描解决方案** — 十二层深度防御，参考 ClawGuard Auditor / SecureClaw / Astrix Security / SmartChainArk / 慢雾安全 / 腾讯科恩实验室业界最佳实践。

## 版本演进

| 版本 | 新增能力 |
|------|---------|
| v3.0 | 去混淆引擎 · AST 分析 · 基线追踪 · 依赖检查 · SARIF 输出 |
| v3.1 | 提示词注入探针 (25+) · 语义审计重构 · .scannerignore |
| v3.2 | 威胁情报全面升级 — ClawHavoc/Snyk/SkillJect (316+ 恶意技能) |
| v3.3 | 熵值分析 · 安装钩子检测 · 网络行为画像 |
| v3.4 | MurphySec 报告整合 · 攻击手法分析章节 |
| v3.5 | 报告格式全面升级 · 浮动导航 · Summary flexbox 布局 |
| **v3.6** | **凭证窃取检测 · CJK 自适应熵值 · 零信任白名单 · 误报调优** |

## 十二层防御管线

| 层级 | 引擎 | 检测能力 | 参考 |
|------|------|---------|------|
| 1 | 🔍 威胁情报 | 380+ 恶意技能名 · 6 恶意作者 · IOC 域名/IP · 攻击模式匹配 | Koi.ai / Snyk / MurphySec |
| 2 | 🧹 去混淆引擎 | Base64/ROT13/Hex · BiDi 覆盖 · 零宽字符 · TR39 混淆 · Zlib · 字符串拼接 | — |
| 3 | 🔎 静态分析 | 43+ TTP 模式 · 194+ 规则 · 凭证/注入/恶意代码/供应链/时间炸弹 | MASB |
| 4 | 🌳 AST 深度分析 | 间接执行 · 数据流追踪 · 动态导入 · 反序列化 · Shell 注入 | — |
| 5 | 📦 依赖检查 | requirements.txt / package.json CVE 匹配 (20+ 高危包) | — |
| 6 | 💉 提示词注入探针 | 25+ 探针 · 系统覆盖 · 角色劫持 · DAN/Jailbreak | — |
| 7 | 📋 基线追踪 | SHA-256 指纹 · Rug-Pull 检测 · 变更审计 | — |
| 8 | 🧠 语义审计 | LLM 深度意图分析（可选，高风险文件才触发） | — |
| 9 | 📊 熵值分析 | Shannon 熵计算 · CJK 自适应阈值 · 高熵区域定位 · 编码 payload 检测 | ClawGuard Auditor |
| 10 | 🔧 安装钩子检测 | setup.py/cmdclass · postinstall · Shell RC 修改 · Cron 注入 · 环境变量篡改 | SecureClaw |
| 11 | 🌐 网络行为画像 | 端点提取 · 域名信誉 · IP 直连检测 · 数据外传 · 隐蔽信道 · C2 特征 | Astrix Security |
| 12 | 🔐 **凭证窃取检测** | osascript 伪造弹窗 · SSH/AWS 密钥读取 · 浏览器 Cookie 窃取 · Keychain 访问 · webhook 外传 | Nova Stealer / 慢雾安全 |

### 核心模块

| 模块 | 文件 | 说明 |
|------|------|------|
| 主扫描器 | `lib/scanner.py` | 十二层管线编排 |
| 静态分析 | `lib/static_analyzer.py` | YAML 规则驱动 |
| 威胁情报 | `lib/threat_intel.py` + `lib/threat_intel.json` | 多层匹配引擎 |
| 去混淆 | `lib/deobfuscator.py` | 7 种混淆技术检测 |
| AST 分析 | `lib/ast_analyzer.py` | Taint 追踪 + 间接执行 |
| 基线追踪 | `lib/baseline.py` | Rug-Pull 检测 |
| 依赖检查 | `lib/dependency_checker.py` | CVE 数据库 |
| 语义审计 | `lib/semantic_auditor.py` | LLM 意图分析 |
| 熵值分析 | `lib/entropy_analyzer.py` | Shannon 熵 + CJK 自适应 |
| 安装钩子 | `lib/install_hook_detector.py` | 安装阶段恶意行为 |
| 网络画像 | `lib/network_profiler.py` | 网络行为深度分析 |
| **凭证窃取** | `lib/credential_theft_detector.py` | osascript/SSH/浏览器/Keychain |
| 风险评分 | `lib/risk_scorer.py` | 统一阈值 (CRITICAL≥80) |
| 报告生成 | `lib/reporter.py` | text/json/html/md/sarif |
| 白名单 | `lib/whitelist.py` | 零信任默认，显式配置 |
| Shield 监控 | `lib/shield_monitor.py` | 实时文件变化监控 |

## 快速开始

```bash
# 完整扫描（十二层防御）
./scan -t ./my-skill/                 # 默认启用语义审计
./scan -t ./my-skill/ --no-semantic   # 快速模式（跳过语义审计）

# SARIF 输出（对接 GitHub Security Tab）
./scan -t ./my-skill/ --format sarif -o results.sarif

# JSON 管道化（进度走 stderr，JSON 走 stdout）
./scan -t ./my-skill/ --json | jq '.risk_level'

# HTML 报告（双语，防溢出布局，可点击跳转）
./scan -t ./my-skill/ --format html -o report.html

# 仅基线比对
./scan -t ./my-skill/ --baseline-only

# 实时 Shield 监控
python3 lib/shield_monitor.py ./my-skill/

# 更新威胁情报
python3 scripts/update_threat_intel.py
```

## 风险等级（统一阈值）

| 等级 | 分数 | 处理 |
|------|------|------|
| 🟢 LOW | 0-19 | ✅ 自动通过 |
| 🟡 MEDIUM | 20-49 | ⚠️ 人工确认 |
| 🔴 HIGH | 50-79 | ❌ 禁止安装 |
| ⛔ EXTREME | 80-100 | ❌ 立即阻止 |

## 输出格式

`text` · `json` · `html` · `md` · **`sarif`**

## ⛔ 立即拒绝的红旗行为

- curl/wget 管道到 shell 执行
- 发送数据到外部服务器
- 读取 ~/.ssh, ~/.aws, ~/.config 无合理理由
- 访问 MEMORY.md / USER.md / SOUL.md
- base64 解码执行 · 动态代码执行函数
- BiDi 覆盖字符 · 零宽字符隐藏
- getattr(__builtins__, ...) 间接调用
- pickle/marshal 反序列化
- 已知漏洞依赖版本
- 提示词注入模式 (DAN/Jailbreak/系统覆盖)
- setup.py cmdclass 覆盖
- postinstall 脚本含危险操作
- IP 直连非标准端口
- C2 Beacon/Heartbeat 模式
- 文件熵值异常（CJK 自适应阈值）
- **osascript 伪造密码弹窗** (v3.6)
- **浏览器 Cookie/LocalStorage 窃取** (v3.6)
- **webhook.site / Discord Webhook 外传** (v3.6)
- **macOS Keychain 未授权访问** (v3.6)

## 威胁情报来源

| 来源 | 内容 | 数量 |
|------|------|------|
| Koi.ai ClawHavoc Report | 恶意 OpenClaw 技能 | 341 |
| Snyk ToxicSkills Campaign | 凭证窃取活动样本 | — |
| PiedPiper0709 CSV | 已知恶意技能列表 | — |
| GitHub Issue #9197 | IOC 域名/IP 列表 | 4 |
| MurphySec AI Agent Security Report | auto-updater 系列批量投放 | 66+ |
| SmartChainArk skill-security-audit | 13 检测器 + 误报调优经验 | — |
| 腾讯科恩实验室 | Nova Stealer / Poseidon 组织溯源 | 295 样本 |
| 慢雾安全 | ClawHub 投毒分析 | 472+ 恶意技能 |
| 本地规则库 | 静态检测规则 | 194+ |

**情报库版本:** v3.6.0 (