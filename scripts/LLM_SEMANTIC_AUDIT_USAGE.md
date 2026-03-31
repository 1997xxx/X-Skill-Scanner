# 语义审计 - OpenClaw 会话内运行

**用途**: 在 OpenClaw 会话中直接运行此脚本，使用当前会话的 LLM 进行语义分析。

**与 `lib/semantic_auditor.py` 的区别**:
- `lib/semantic_auditor.py`: 在 subprocess 中运行，只能输出请求标记
- `llm_semantic_audit.py`: 在 OpenClaw 会话中直接运行，可以直接使用 LLM

## 使用方法

### 方法 1: 在 OpenClaw 会话中运行

```bash
cd ~/.openclaw/workspace/skills/x-skill-scanner
python3 scripts/llm_semantic_audit.py -t /path/to/skill
```

### 方法 2: 分析特定文件

```bash
python3 scripts/llm_semantic_audit.py --file /path/to/code.py
```

### 方法 3: 分析粘贴的内容

```bash
echo "你的代码内容" | python3 scripts/llm_semantic_audit.py --stdin
```

## 输出

JSON 格式的分析结果，包含：
- `risk_level`: 整体风险等级 (LOW/MEDIUM/HIGH/CRITICAL)
- `findings`: 风险发现列表
- `summary`: 总结

## 实现说明

此脚本设计为在 OpenClaw 会话中运行。由于 OpenClaw 的 Python 环境可以直接访问 LLM，
脚本会将分析请求发送给当前会话的 LLM，然后解析响应。

**注意**: 如果直接在终端运行（不在 OpenClaw 会话中），脚本会降级为仅规则检查。