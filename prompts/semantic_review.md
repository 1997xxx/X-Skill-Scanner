# 二次语义审计 Prompt 模板

## 审计任务描述

你是资深安全工程师，需要对技能进行二次语义审计，判断扫描器发现的问题是否为真实威胁。

---

## 技能信息

```
- 技能名称: {skill_name}
- 技能作者: {skill_author}
- 技能来源: {skill_source}
- 技能类型: {skill_type}
- 文件数量: {file_count}
- 信任分数: {trust_score}/100
```

---

## 初步扫描结果

```
- 风险等级: {risk_level}
- 风险分数: {risk_score}/100
- 发现数量: {finding_count}
- 扫描时间: {scan_time}
```

---

## 发现的问题摘要

{findings_summary}

---

## 完整代码上下文

{code_contexts}

---

## 审查标准

### ✅ 判断为误报 (FALSE_POSITIVE) 的条件

1. **凭证从环境变量读取** — 使用 `os.environ.get()`、`process.env`、`os.getenv()` 等方式读取凭证，而非硬编码
2. **发送到企业内网可信域名** — 目标地址属于企业内部可信域名（如 `*.alibaba-inc.com`、`*.aliyun.com`、`*.antgroup-inc.cn`）
3. **正常的 API 认证流程** — 仅包含标准的 API 认证逻辑，没有额外的凭证收集行为
4. **没有恶意特征** — 不包含混淆、动态执行、反向 Shell、持久化等恶意特征
5. **威胁情报匹配的是规则定义** — 匹配的是文档字符串或示例代码，不是实际可执行代码
6. **正常的数据访问模式** — `.get('token')`、`.get('secret')` 是正常的数据访问，非凭证收集

### ⛔ 判断为真实威胁 (TRUE_POSITIVE) 的条件

1. **硬编码凭证** — API key、password、secret 直接写在源码中
2. **发送到未知外部服务器** — 目标地址非企业可信域名
3. **凭证窃取行为** — 读取 SSH 密钥、浏览器 Cookie、系统凭证文件（Keychain、Credential Manager）
4. **动态代码执行** — 使用 eval、exec、subprocess 执行动态生成的代码
5. **社会工程学攻击** — 钓鱼提示、伪造系统对话框、假冒知名品牌
6. **编码隐藏 payload** — Base64、Hex 编码后执行的 payload
7. **持久化后门** — 反向 Shell、计划任务、启动项修改

### ⚠️ 判断为不确定 (UNCERTAIN) 的条件

1. **无法确定凭证来源** — 需要更多上下文
2. **网络目标不明确** — 需要人工确认
3. **代码逻辑复杂** — 需要深入分析

---

## 输出格式

请输出以下 JSON 格式的最终判断：

```json
{
  "verdict": "FALSE_POSITIVE" | "TRUE_POSITIVE" | "UNCERTAIN",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "risk_level_override": "LOW" | "MEDIUM" | "HIGH" | "EXTREME" | null,
  "analysis": {
    "credential_source": "描述凭证来源（环境变量/硬编码/不存在）",
    "network_targets": ["列出所有网络请求目标域名/IP"],
    "trusted_domains": ["识别出的可信企业域名"],
    "suspicious_patterns": ["真正可疑的模式，如果没有则空数组"],
    "fp_explanations": ["对每个误报发现的解释"]
  },
  "recommendation": "可安全安装" | "需要进一步调查" | "阻止安装",
  "reasoning": "详细的分析过程和理由"
}
```

---

## 语言要求

请使用 **{language}** 语言输出分析结果。