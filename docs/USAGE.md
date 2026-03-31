# Usage Guide / 使用指南

## Quick Start / 快速开始

### 1. Install Dependencies / 安装依赖

```bash
cd X-Skill-Scanner
pip install -r requirements.txt
```

### 2. Configure Semantic Audit (Optional) / 配置语义审计（可选）

Semantic audit uses OpenClaw's LLM task plugin for deep intent analysis. It is optional and only triggers for high-risk files.

语义审计使用 OpenClaw 的 LLM 任务插件进行深度意图分析，为可选功能，仅对高风险文件触发。

Edit `~/.openclaw/openclaw.json` to enable the `llm-task` plugin:

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
  "skills": {
    "entries": {
      "x-skill-scanner": {
        "enabled": true,
        "config": {
          "semantic": {
            "enabled": true,
            "provider": "llm-task",
            "timeout_ms": 60000
          }
        }
      }
    }
  }
}
```

Then restart the gateway:

```bash
openclaw gateway restart
```

---

## Usage Modes / 使用方式

### Automatic Scan on Skill Install / 安装时自动扫描

When configured in OpenClaw, the scanner automatically triggers during skill installation:

在 OpenClaw 中配置后，安装技能时会自动触发安全检查：

1. **Detect install intent** — Keywords: "install skill", "clawhub install", etc.
2. **Run security scan** — Automatically executes `./scan -t <skill-path>`
3. **Show results** — Displays risk level and findings
4. **Allow or block** — Proceeds with install only if scan passes

### Manual Scan / 手动扫描

```bash
# Full scan (all 12 layers, semantic audit enabled by default)
./scan -t ./my-skill/

# Quick mode (skip LLM semantic audit)
./scan -t ./my-skill/ --no-semantic

# JSON output
./scan -t ./my-skill/ --json > report.json

# HTML report
./scan -t ./my-skill/ --format html -o report.html

# SARIF output (GitHub Security Tab)
./scan -t ./my-skill/ --format sarif -o results.sarif

# Recursive scan (multiple skills in directory)
python3 lib/scanner.py -t ~/.openclaw/skills/ -r
```

### Remote URL Scan / 远程 URL 扫描

```bash
./scan --url https://github.com/user/repo
```

---

## CLI Reference / 命令行参考

### Basic Usage / 基本用法

```bash
python3 lib/scanner.py [options] -t <target-path>
```

### Parameters / 参数说明

| Parameter | Short | Description | Default |
|-----------|-------|-------------|---------|
| `--target` | `-t` | Target path (required) | - |
| `--url` | - | Remote skill URL | - |
| `--format` | - | Output format (text/json/html/md/sarif) | html |
| `--no-semantic` | - | Skip semantic audit | false |
| `--recursive` | `-r` | Recursive directory scan | false |
| `--json` | `-j` | JSON output | false |
| `--output` | `-o` | Output file path | auto-generated in reports/ |
| `--verbose` | `-v` | Verbose output | false |

---

## Python API

### Import

```python
from lib.scanner import SkillScanner, ScanConfig
```

### Create Scanner

```python
# Default configuration
scanner = SkillScanner()

# Custom configuration
config = ScanConfig(
    enable_semantic=True,
    enable_threat_intel=True,
    timeout_ms=60000,
    risk_threshold="MEDIUM"
)
scanner = SkillScanner(config=config)
```

### Execute Scan

```python
# Scan single skill
result = scanner.scan("./my-skill/")

# Scan directory (recursive)
results = scanner.scan_directory("./skills/", recursive=True)
```

### Parse Results

```python
print(f"Risk Level: {result['risk_level']}")
print(f"Risk Score: {result['risk_score']}")
print(f"Total Findings: {len(result['findings'])}")

for finding in result['findings']:
    print(f"- [{finding['severity']}] {finding['title']}")
    print(f"  File: {finding['file_path']}:{finding['line_number']}")
    print(f"  Remediation: {finding['remediation']}")
```

---

## Scan Result Structure / 扫描结果结构

```json
{
  "target": "./my-skill/",
  "scan_time": "2026-03-31T10:00:00Z",
  "total_files": 5,
  "scanned_files": 5,
  "skipped_files": 0,
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
      "title": "Database connection string",
      "file_path": "./my-skill/config.py",
      "line_number": 15,
      "remediation: "Use environment variables instead of hardcoding"
    }
  ]
}
```

---

## Troubleshooting / 故障排查

### Q: Semantic audit fails? / 语义审计失败？

Check if the `llm-task` plugin is enabled:

```bash
openclaw config get plugins.entries.llm-task.enabled
```

### Q: Scan timeout? / 扫描超时？

Increase the timeout:

```bash
./scan -t ./my-skill/ --timeout 120
```

### Q: False positive? / 误报？

Submit feedback via GitHub Issues with the scan output and explanation.

通过 GitHub Issues 提交误报反馈，附上扫描输出和说明。

### Q: Update threat intelligence? / 更新威胁情报？

The threat intelligence database uses manual maintenance. Edit `data/threat_intel.json` to add new threats.

威胁情报库采用手工维护模式，编辑 `data/threat_intel.json` 添加新威胁。

---

## References / 参考文档

- [Architecture Design](ARCHITECTURE.md)
- [Threat Intel Sources](THREAT_INTEL_SOURCES.md)
- [SKILL.md](../SKILL.md)

---

*Last updated: 2026-03-31*
