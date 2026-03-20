---
name: ant-intl-skill-scanner
description: Ant International Skill Scanner - AI 技能安全扫描器（静态分析 + 威胁情报 + 语义审计）
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

# Ant International Skill Scanner - AI 技能安全扫描器

## 描述

**企业级 AI Agent 技能安全扫描解决方案** - 安装前强制安全扫描，保护所有技能安装操作

整合腾讯 AI-Infra-Guard、Aguara、MaliciousAgentSkillsBench 等安全能力，提供三层防御体系：
- 🔍 **静态分析** - 43 个 TTP 模式 +194+ 检测规则
- 🛡️ **威胁情报** - 573 个恶意技能名称 +17 个恶意域名 +5 个恶意 IP
- 🧠 **语义审计** - 使用 OpenClaw llm-task 工具进行深度分析

---

## 🔒 安装前扫描协议 (Pre-Install Scan Protocol)

**核心原则：任何技能安装前必须经过安全扫描**

### 适用场景

本扫描器覆盖以下所有技能安装方式：

| 安装方式 | 命令示例 | 扫描触发 |
|---------|---------|---------|
| **ClawHub** | `clawhub install <skill>` | ✅ 自动扫描 |
| **GitHub 克隆** | `git clone <repo>` + 手动安装 | ✅ 手动扫描 |
| **本地技能** | 本地开发的技能 | ✅ 开发时扫描 |
| **技能市场** | 其他技能市场 | ✅ 安装前扫描 |
| **共享技能** | 其他 Agent 分享的 | ✅ 强制扫描 |

### 扫描流程

```
┌─────────────────────────────────────────────────────────────┐
│  用户请求安装技能                                            │
│  (任何来源：ClawHub / GitHub / 本地 / 共享)                  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤 1: 来源验证 (Source Verification)                      │
│  • 来源可信度评估 (官方/知名/未知)                           │
│  • 作者声誉检查                                              │
│  • 下载量/Star 数检查                                         │
│  • 最后更新时间检查                                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤 2: 静态分析 (Static Analysis)                          │
│  • 43 个 TTP 攻击模式检测                                      │
│  • 194+ 恶意代码规则匹配                                      │
│  • 危险函数调用检测 (eval, exec, os.system 等)               │
│  • 凭证泄露模式检测 (AWS Key, API Key, Password 等)         │
│  • 提示词注入模式检测                                        │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤 3: 威胁情报匹配 (Threat Intelligence)                  │
│  • 573 个恶意技能名称比对                                     │
│  • 17 个恶意域名黑名单                                        │
│  • 5 个恶意 IP 黑名单                                          │
│  • 已知攻击签名匹配                                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤 4: 语义审计 (Semantic Audit)                           │
│  • 使用 LLM 深度分析代码意图                                  │
│  • 检测隐蔽的恶意行为                                        │
│  • 评估权限范围合理性                                        │
│  • 识别社会工程攻击                                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤 5: 风险评估与报告 (Risk Assessment)                    │
│  • 风险等级评定 (🟢 LOW / 🟡 MEDIUM / 🔴 HIGH / ⛔ EXTREME)  │
│  • 生成详细扫描报告                                          │
│  • 提供安装建议                                              │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
         ┌────────────────────┐
         │   风险等级判断     │
         └─────────┬──────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
    ▼              ▼              ▼
┌────────┐   ┌──────────┐   ┌──────────┐
│ 🟢 LOW │   │ 🟡 MEDIUM│   │ 🔴 HIGH  │
│ 自动   │   │ 需人工   │   │ ⛔ EXTREME│
│ 通过   │   │ 确认     │   │ 禁止安装  │
└────────┘   └──────────┘   └──────────┘
```

### 风险等级定义

| 等级 | 标识 | 定义 | 示例 | 处理方式 |
|------|------|------|------|---------|
| **LOW** | 🟢 | 无风险或极低风险 | 笔记、天气、格式化工具 | 自动通过，可安装 |
| **MEDIUM** | 🟡 | 中等风险，需要审查 | 文件操作、浏览器访问、API 调用 | 人工确认后安装 |
| **HIGH** | 🔴 | 高风险，敏感操作 | 凭证访问、系统文件修改、网络通信 | 必须人工批准 |
| **EXTREME** | ⛔ | 极高风险，恶意行为 | Root 权限、安全配置修改、已知恶意代码 | **禁止安装** |

### 🚨 立即拒绝的红旗行为 (RED FLAGS)

发现以下任何一项，**立即拒绝安装**：

```
⛔ 立即拒绝安装的情况：
─────────────────────────────────────────────────────────
• curl/wget 到未知 URL 并执行
• 发送数据到外部服务器（无明确说明）
• 请求凭证/令牌/API Key/密码
• 读取 ~/.ssh, ~/.aws, ~/.config 无合理理由
• 访问 MEMORY.md, USER.md, SOUL.md, IDENTITY.md
• 使用 base64 解码执行
• 使用 eval() 或 exec() 处理外部输入
• 修改工作区外的系统文件
• 未列出的包安装
• 网络调用到 IP 而非域名
• 混淆代码（压缩、编码、混淆）
• 请求 elevated/sudo 权限
• 访问浏览器 cookie/session
• 接触凭证文件
• 反向 shell 模式 (/dev/tcp/, nc -e)
• 加密货币挖矿 (xmrig, cryptonight)
• 破坏性命令 (rm -rf /)
─────────────────────────────────────────────────────────
```

### 扫描报告模板

每次扫描后生成以下报告：

```
═══════════════════════════════════════════════════════════
           SKILL SECURITY SCAN REPORT
═══════════════════════════════════════════════════════════
Skill: [技能名称]
Source: [ClawHub / GitHub / Local / Other]
Author: [作者用户名]
Version: [版本号]
Scan Date: [扫描时间]
───────────────────────────────────────────────────────────
METRICS:
• Downloads/Stars: [数量]
• Last Updated: [日期]
• Files Reviewed: [文件数]
• Lines of Code: [代码行数]
───────────────────────────────────────────────────────────
RED FLAGS: [无 / 列出所有发现的问题]

STATIC ANALYSIS:
• TTP Patterns Matched: [数量]
• Dangerous Functions: [列表或"无"]
• Credential Patterns: [列表或"无"]

THREAT INTELLIGENCE:
• Malicious Skill Match: [是/否]
• Blacklisted Domain: [是/否]
• Blacklisted IP: [是/否]

SEMANTIC AUDIT:
• LLM Risk Assessment: [风险等级]
• Suspicious Intent: [是/否]
• Permission Scope: [合理/过度]

PERMISSIONS NEEDED:
• Files Read: [列表或"无"]
• Files Write: [列表或"无"]
• Network Access: [列表或"无"]
• Commands: [列表或"无"]
───────────────────────────────────────────────────────────
RISK LEVEL: [🟢 LOW / 🟡 MEDIUM / 🔴 HIGH / ⛔ EXTREME]

VERDICT: [✅ SAFE TO INSTALL / ⚠️ INSTALL WITH CAUTION / ❌ DO NOT INSTALL]

NOTES: [其他观察和建议]
═══════════════════════════════════════════════════════════
```

### 集成到安装流程

#### 方式 1: ClawHub 包装脚本 (推荐)

创建 `~/.openclaw/workspace/scripts/clawhub-safe-install.sh`:

```bash
#!/bin/bash
# ClawHub 安全安装包装脚本

SKILL_NAME="$1"
SCANNER_DIR="$HOME/.openclaw/workspace/skills/ant-intl-skill-scanner"

echo "🔍 开始技能安全扫描: $SKILL_NAME"

# 1. 先下载/获取技能（不安装）
TEMP_DIR=$(mktemp -d)
clawhub install "$SKILL_NAME" --dir "$TEMP_DIR"

# 2. 运行安全扫描
python3 "$SCANNER_DIR/scanner.py" -t "$TEMP_DIR/$SKILL_NAME" --semantic

# 3. 检查扫描结果
if [ $? -eq 0 ]; then
    echo "✅ 扫描通过，开始安装..."
    clawhub install "$SKILL_NAME"
else
    echo "❌ 扫描失败，终止安装"
    rm -rf "$TEMP_DIR"
    exit 1
fi

rm -rf "$TEMP_DIR"
```

#### 方式 2: 手动扫描流程

对于 GitHub 或本地技能：

```bash
# 1. 克隆/复制到临时目录
git clone <repo-url> /tmp/skill-to-scan

# 2. 运行扫描
python3 ~/.openclaw/workspace/skills/ant-intl-skill-scanner/scanner.py \
    -t /tmp/skill-to-scan --semantic

# 3. 检查报告，决定是否安装
```

#### 方式 3: Agent 自动化集成

在 Agent 的 SKILL.md 中添加：

```markdown
## 安装前安全检查

安装此技能前，必须运行安全扫描：

```bash
python3 ~/.openclaw/workspace/skills/ant-intl-skill-scanner/scanner.py \
    -t ./this-skill --semantic
```

扫描报告显示 🟢 LOW 或 🟡 MEDIUM 风险等级方可安装。
```

## 🚀 开箱即用

### 1. 自动配置（推荐）

运行自动配置脚本，一键完成所有设置：

```bash
cd ~/.openclaw/workspace/skills/ant-intl-skill-scanner
python3 ./scripts/setup_semantic_audit.py
```

### 2. 手动配置

如需手动配置，请编辑 `~/.openclaw/openclaw.json`：

```json
{
  "plugins": {
    "entries": {
      "llm-task": {
        "enabled": true,
        "config": {
          "defaultProvider": "<your-provider>",
          "defaultModel": "<your-model>",
          "timeoutMs": 60000
        }
      }
    }
  },
  "agents": {
    "list": [
      {
        "id": "main",
        "tools": {
          "allow": ["llm-task"]
        }
      }
    ]
  },
  "skills": {
    "entries": {
      "ant-intl-skill-scanner": {
        "enabled": true
      }
    }
  }
}
```

> **注意：** 请将 `<your-provider>` 和 `<your-model>` 替换为你自己的配置。不要使用示例中的具体值。

## 使用方式

### 快速开始

```bash
# 1. 安装依赖
pip3 install -r requirements.txt

# 2. 配置语义审计
python3 ./scripts/setup_semantic_audit.py

# 3. 扫描技能
python3 scanner.py -t ./my-skill/ --semantic
```

### 安全安装（推荐）

使用包装脚本自动执行扫描 + 安装：

```bash
# ClawHub 技能
./hooks/install_wrapper.sh clawhub install <skill-name>

# 或添加别名到 ~/.zshrc
alias clawhub-safe="~/.openclaw/workspace/skills/ant-intl-skill-scanner/hooks/install_wrapper.sh clawhub"
```

### 手动扫描

```bash
# 完整扫描（静态 + 威胁情报 + 语义）
./scan -t ./my-skill/ --semantic

# 快速扫描（仅静态 + 威胁情报）
./scan -t ./my-skill/

# 递归扫描目录
./scan -t ~/.openclaw/workspace/skills/ -r

# 输出 JSON 报告
./scan -t ./my-skill/ --json -o report.json
```

### 更新威胁情报

威胁情报库采用**手工维护**模式：

```bash
# 查看当前版本
python3 -c "from core.threat_intel import ThreatIntelligence; print(ThreatIntelligence().get_version())"

# 手工编辑 data/threat_intel.json 添加新威胁
```

## 语义审计实现

本技能使用 OpenClaw 官方的 **llm-task 工具** 进行语义审计：

- ✅ **使用 OpenClaw 配置的大模型** - 自动使用 `agents.defaults.model`
- ✅ **无需外部 API Key** - 直接使用 OpenClaw 已配置的认证
- ✅ **JSON Schema 验证** - 确保输出格式正确
- ✅ **企业内部友好** - 数据不会发送到外部服务
- ✅ **开箱即用** - 启用插件即可使用

参考文档：https://docs.openclaw.ai/tools/llm-task

## 威胁情报来源

| 来源 | 恶意技能数 |
|------|------------|
| MaliciousAgentSkillsBench | 157 |
| ClawHavoc (Koi Security) | 341 |
| ToxicSkills (Snyk) | 534 |
| Poseidon | 120 |
| SlowMist 慢雾安全 | 472 |
| Tencent Keen Lab 腾讯科恩 | 295 |
| **总计** | **1500+ (去重 573)** |

## 配置说明

### 语义审计配置

在 `~/.openclaw/openclaw.json` 的 `skills.entries.ant-intl-skill-scanner.config` 中：

```json
{
  "semantic": {
    "enabled": true,
    "provider": "llm-task",
    "timeout_ms": 60000,
    "max_tokens": 1500,
    "thinking": "low"
  }
}
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| enabled | 是否启用语义审计 | true |
| provider | 语义分析提供者 | llm-task |
| timeout_ms | LLM 调用超时 (毫秒) | 60000 |
| max_tokens | 最大 token 数 | 1500 |
| thinking | 思考级别 (low/medium/high) | low |

## 测试

```bash
# 运行语义审计测试
python3 ./scripts/test_llm_task_audit.py

# 运行自动配置脚本
python3 ./scripts/setup_semantic_audit.py
```

## 文件结构（优化后）

```
ant-intl-skill-scanner/
├── SKILL.md                    # 技能定义
├── scanner.py                  # 主扫描器（入口）
├── requirements.txt            # Python 依赖
│
├── core/                       # 核心引擎模块
│   ├── __init__.py
│   ├── static_analyzer.py      # 静态分析引擎
│   ├── threat_intel.py         # 威胁情报匹配
│   ├── semantic_auditor.py     # 语义审计引擎
│   └── reporter.py             # 报告生成器
│
├── hooks/                      # 安装拦截 Hook
│   ├── clawhub_hook.py         # ClawHub 安装前扫描
│   └── install_wrapper.sh      # 安全安装包装脚本
│
├── scripts/                    # 工具脚本
│   ├── setup_semantic_audit.py # 自动配置
│   ├── update_threat_intel.py  # 威胁情报更新
│   └── test_llm_task_audit.py  # 测试脚本
│
├── data/                       # 数据文件
│   └── threat_intel.json       # 威胁情报库
│
├── rules/                      # 检测规则
│   └── static_rules.yaml       # 静态分析规则
│
├── configs/                    # 配置示例
│   └── openclaw_llm_task.example.json
│
├── tests/                      # 测试用例
│   └── test_suites/
│
└── docs/                       # 文档
    ├── INSTALL.md              # 安装与使用指南
    ├── API.md                  # 开发者 API
    └── THREAT_INTEL_SOURCES.md # 威胁情报来源
```

**优化效果：**
- 目录体积：524KB → ~200KB (-62%)
- 代码精简：2861 行 → ~1500 行
- 文档精简：26 个文件 → 3 个核心文档

## 许可证

MIT

---

**Ant International Skill Scanner - 您的 AI 技能安全守护者！** 🛡️
