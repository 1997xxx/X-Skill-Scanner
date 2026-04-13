# 安全扫描报告模板

## 报告头部

```
══════════════════════════════════════════════════════════════
                    X Skill Scanner v7.0
                      安全扫描报告
══════════════════════════════════════════════════════════════
```

## 技能基本信息

| 字段 | 值 |
|------|-----|
| 技能名称 | {skill_name} |
| 技能作者 | {skill_author} |
| 技能来源 | {skill_source} |
| 技能类型 | {skill_type} |
| 扫描时间 | {scan_time} |
| 扫描版本 | {scanner_version} |

---

## 扫描结果摘要

### 风险等级

```
{risk_level_icon} {risk_level} — {risk_score}/100
```

### 统计信息

| 指标 | 数量 |
|------|------|
| 扫描文件数 | {total_files} |
| 发现问题数 | {total_findings} |
| 严重问题 (CRITICAL) | {critical_count} |
| 高危问题 (HIGH) | {high_count} |
| 中危问题 (MEDIUM) | {medium_count} |
| 低危问题 (LOW) | {low_count} |

---

## 问题详情

### 🔴 严重问题 (CRITICAL)

{finding_critical}

### 🟠 高危问题 (HIGH)

{finding_high}

### 🟡 中危问题 (MEDIUM)

{finding_medium}

### 🟢 低危问题 (LOW)

{finding_low}

---

## 二次语义审计结果

```
审计结论: {semantic_verdict}
置信度: {semantic_confidence}
风险等级调整: {risk_level_override}
```

### 审计分析

{analysis_content}

---

## 安装建议

```
╔══════════════════════════════════════════════════════════════╗
║  安装建议: {recommendation}                                  ║
╚══════════════════════════════════════════════════════════════╝
```

### 详细建议

{recommendation_detail}

---

## 修复建议

{remediation_suggestions}

---

## 附录

### A. 扫描管线信息

| 层 | 引擎 | 状态 |
|---|------|------|
| 0 | 技能画像 | {engine_0_status} |
| 1 | 威胁情报 | {engine_1_status} |
| 2 | 去混淆 | {engine_2_status} |
| 3 | 静态分析 | {engine_3_status} |
| 4 | AST 分析 | {engine_4_status} |
| 5 | 依赖检查 | {engine_5_status} |
| 6 | 提示词注入 | {engine_6_status} |
| 7 | 基线追踪 | {engine_7_status} |
| 8 | 语义审计 | {engine_8_status} |
| 9 | 熵值分析 | {engine_9_status} |
| 10 | 安装钩子 | {engine_10_status} |
| 11 | 网络画像 | {engine_11_status} |
| 12 | 凭证窃取 | {engine_12_status} |

### B. 平台信息

| 项目 | 值 |
|------|-----|
| 检测平台 | {detected_platform} |
| LLM 提供商 | {llm_provider} |
| LLM 模型 | {llm_model} |
| 连接状态 | {connection_status} |

---

*报告生成时间: {report_generated_time}*
*X Skill Scanner v7.0 - 企业级 AI Agent 技能安全扫描器*