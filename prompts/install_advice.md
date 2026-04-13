# 安装建议生成 Prompt 模板

## 任务描述

根据扫描结果和二次语义审计结果，生成明确的安装建议。

---

## 输入信息

### 扫描结果
- 风险等级: {risk_level}
- 风险分数: {risk_score}
- 发现数量: {finding_count}
- 严重问题: {critical_count}
- 高危问题: {high_count}

### 审计结果
- 审计结论: {semantic_verdict}
- 置信度: {semantic_confidence}
- 建议: {semantic_recommendation}

---

## 决策逻辑

### ✅ 可安全安装 (SAFE)

满足以下任一条件：
1. 风险等级为 LOW，且审计结论为 FALSE_POSITIVE
2. 风险等级为 MEDIUM，但所有问题都被确认为误报
3. 无任何发现 (findings = 0)

### ⚠️ 需要人工审查 (REVIEW)

满足以下任一条件：
1. 风险等级为 MEDIUM
2. 审计结论为 UNCERTAIN
3. 存在无法确认的问题

### ❌ 阻止安装 (BLOCK)

满足以下任一条件：
1. 风险等级为 HIGH 或 EXTREME
2. 审计结论为 TRUE_POSITIVE
3. 存在已确认的真实威胁

---

## 输出格式

```json
{
  "verdict": "SAFE" | "REVIEW" | "BLOCK",
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "EXTREME",
  "title": "安装建议标题",
  "summary": "一句话总结",
  "reasons": [
    "原因1",
    "原因2"
  ],
  "actions": [
    {
      "type": "proceed" | "review" | "block",
      "description": "操作描述",
      "command": "可选的具体命令"
    }
  ],
  "next_steps": [
    "后续步骤1",
    "后续步骤2"
  ]
}
```

---

## 中文模板

### 可安全安装

```
✅ 可以安装

该技能通过了安全扫描，未发现恶意代码或可疑行为。

建议操作：
- 继续安装流程
- 定期关注技能更新
```

### 需要人工审查

```
⚠️ 建议人工审查

该技能存在以下需要关注的问题：
{issues_summary}

建议操作：
- 仔细审查发现的问题
- 确认问题是否为误报
- 如有疑问，请联系技能作者确认
```

### 阻止安装

```
🔴 不建议安装

该技能存在以下安全风险：
{issues_summary}

建议操作：
- 不要安装此技能
- 如必须使用，请联系安全团队
- 报告给技能平台管理员
```

---

## English Template

### Safe to Install

```
✅ Safe to Install

This skill has passed the security scan. No malicious code or suspicious behavior detected.

Recommended actions:
- Proceed with installation
- Monitor for updates
```

### Review Required

```
⚠️ Review Required

This skill has the following issues that need attention:
{issues_summary}

Recommended actions:
- Carefully review the findings
- Confirm if issues are false positives
- Contact the skill author if in doubt
```

### Block Installation

```
🔴 Do Not Install

This skill has the following security risks:
{issues_summary}

Recommended actions:
- Do not install this skill
- Contact security team if required
- Report to platform administrator
```