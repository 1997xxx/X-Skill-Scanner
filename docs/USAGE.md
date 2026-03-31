# 使用指南

## 🚀 快速开始

### 1. 安装依赖

```bash
cd x-skill-scanner
pip3 install -r requirements.txt
```

### 2. 配置 OpenClaw

运行自动配置脚本：

```bash
python3 ./scripts/setup_semantic_audit.py
```

或手动编辑 `~/.openclaw/openclaw.json`：

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
      "x-skill-scanner": {
        "enabled": true,
        "config": {
          "semantic": {
            "enabled": true,
            "provider": "llm-task",
            "timeout_ms": 60000,
            "max_tokens": 1500,
            "thinking": "low"
          }
        }
      }
    }
  }
}
```

> **注意：** 将 `<your-provider>` 和 `<your-model>` 替换为你的配置。

### 3. 重启 Gateway

```bash
openclaw gateway restart
```

---

## 📖 使用方式

### 自动扫描（推荐）

配置后，安装技能时自动触发安全检查。

### 会话触发扫描

**当用户在会话中提及"skill 安装"相关命令时，Agent 会自动：**

1. **检测安装意图** - 识别关键词（安装 skill, install skill 等）
2. **提示安全扫描** - 告知用户需要先扫描
3. **执行扫描** - 自动运行 `./scan -t <skill-path>`
4. **显示结果** - 展示风险等级和结论
5. **允许安装** - 扫描通过后才继续安装

**触发关键词：**
- 中文：安装 skill、安装技能、下载技能、添加技能
- 英文：install skill, skill install, add skill, download skill
- 命令：clawhub install, aone-kit skill install, AIWay install

**多路径监控：** 自动监控以下所有技能安装位置：

- `~/.openclaw/skills/` - OpenClaw 标准路径
- `~/.openclaw/workspace/skills/` - Workspace 路径
- `~/.openclaw/workspace/.claude/skills/` - Claude 风格路径
- `~/.claude/skills/` - 用户 Claude 路径
- `./.claude/skills/` - 当前工作区路径
- `~/.aone/skills/` - Aone-kit 路径
- `~/.aiway/skills/` - AIWay 路径

### 手动扫描

```bash
# 基础扫描（默认启用语义审计）
python3 scanner.py -t ./my-skill/

# 快速模式（跳过语义审计）
python3 scanner.py -t ./my-skill/ --no-semantic

# 输出 JSON 报告
python3 scanner.py -t ./my-skill/ --json > report.json

# 递归扫描所有技能
python3 scanner.py -t ~/.openclaw/workspace/skills/ -r
```

### 变更检测

```bash
# 检查所有监控路径的技能变化
bash check-skills-change.sh

# 强制重新创建快照
bash check-skills-change.sh --force
```

### 风险等级

| 等级 | 标识 | 含义 | 建议 |
|------|------|------|------|
| **LOW** | 🟢 | 无风险 | 可安全安装 |
| **MEDIUM** | 🟡 | 中等风险 | 人工审查后决定 |
| **HIGH** | 🔴 | 高风险 | 需人工批准 |
| **EXTREME** | ⛔ | 极高风险 | 禁止安装 |

---

## 🔧 CLI 参考

### 基本用法

```bash
python3 scanner.py [选项] -t <目标路径>
```

### 参数说明

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--target` | `-t` | 扫描目标路径（必需） | - |
| `--url` | - | 扫描远程技能 URL | - |
| `--format` | - | 输出格式 (text/json/html/md/sarif) | html |
| `--lang` | - | 报告语言 (zh/en) | zh |
| `--no-semantic` | - | 跳过语义审计 | false（默认启用） |
| `--recursive` | `-r` | 递归扫描目录 | false |
| `--json` | `-j` | 输出 JSON 格式 | false |
| `--output` | `-o` | 输出文件路径 | reports/ 目录自动生成 |
| `--timeout` | `-T` | 语义审计超时（秒） | 60 |
| `--verbose` | `-v` | 详细输出 | false |

---

## 🐍 Python API

### 导入模块

```python
from scanner import SkillScanner, ScanConfig
```

### 创建扫描器

```python
# 默认配置
scanner = SkillScanner()

# 自定义配置
config = ScanConfig(
    enable_semantic=True,
    enable_threat_intel=True,
    timeout_ms=60000,
    risk_threshold="MEDIUM"
)
scanner = SkillScanner(config=config)
```

### 执行扫描

```python
# 扫描单个技能
result = scanner.scan("./my-skill/")

# 扫描目录（递归）
results = scanner.scan_directory("./skills/", recursive=True)
```

### 解析结果

```python
print(f"风险等级：{result.risk_level}")
print(f"风险分数：{result.risk_score}")
print(f"发现项：{result.total_findings}")

# 获取详细发现
for finding in result.findings:
    print(f"- [{finding.severity}] {finding.title}")
    print(f"  文件：{finding.file_path}:{finding.line_number}")
    print(f"  修复：{finding.remediation}")
```

---

## 📊 扫描结果结构

```json
{
  "target": "./my-skill/",
  "scan_time": "2026-03-20T10:00:00Z",
  "total_files": 5,
  "total_findings": 3,
  "findings_by_severity": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 0
  },
  "risk_score": 45,
  "risk_level": "MEDIUM",
  "verdict": "INSTALL_WITH_CAUTION",
  "findings": [
    {
      "rule_id": "CRED_005",
      "severity": "HIGH",
      "category": "credential_leak",
      "title": "数据库连接串",
      "file_path": "./my-skill/config.py",
      "line_number": 15,
      "remediation": "使用环境变量或配置文件"
    }
  ]
}
```

---

## ❓ 故障排查

### Q: 语义审计失败？

检查 `llm-task` 插件是否启用：

```bash
openclaw config get plugins.entries.llm-task.enabled
```

### Q: 扫描超时？

增加超时时间：

```bash
python3 scanner.py -t ./my-skill/ --semantic --timeout 120
```

### Q: 误报？

在配置中添加信任技能：

```json
{
  "skills": {
    "entries": {
      "x-skill-scanner": {
        "config": {
          "ignore_skills": ["weather", "calendar"]
        }
      }
    }
  }
}
```

### Q: 威胁情报库更新？

威胁情报库采用手工维护模式，编辑 `data/threat_intel.json` 添加新威胁。

---

## 📚 参考文档

- [威胁情报来源](THREAT_INTEL_SOURCES.md)
- [架构设计](ARCHITECTURE.md)
- [SKILL.md](../SKILL.md)

---
*最后更新：2026-03-20*
