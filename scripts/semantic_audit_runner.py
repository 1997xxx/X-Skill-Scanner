#!/usr/bin/env python3
"""
语义审计执行器 - 使用 OpenClaw sessions_spawn 进行 LLM 语义分析

使用方法:
    python3 semantic_audit_runner.py "<待分析的代码/内容>"

或者从文件读取:
    python3 semantic_audit_runner.py --file /path/to/code.py

输出: JSON 格式的分析结果
"""

import sys
import json
import argparse
import os

def create_audit_prompt(content: str) -> str:
    """创建审计提示词"""
    return f"""你是一位专业的代码安全审计专家。请分析以下内容，识别潜在的安全风险。

**分析重点:**
1. 凭证泄露 (API keys, passwords, tokens 硬编码)
2. 注入风险 (SQL, command, path traversal)
3. 权限问题 (权限提升、未授权访问)
4. 数据暴露 (敏感数据未加密、日志泄露)
5. 依赖风险 (已知漏洞的第三方库)
6. 配置问题 (不安全默认值、调试模式开启)

**返回格式 (严格的 JSON，不要用 markdown 包裹):**
{{
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "findings": [
        {{
            "severity": "LOW|MEDIUM|HIGH|CRITICAL",
            "category": "credential_leak|injection|privilege_escalation|data_exposure|dependency_risk|config_issue|other",
            "title": "简洁的风险标题",
            "description": "详细描述风险内容",
            "line": 行号（整数或 null，如果无法确定）,
            "evidence": "触发风险的代码片段（最多 100 字符）",
            "confidence": 0.0-1.0 之间的置信度（浮点数）,
            "remediation": "具体修复建议"
        }}
    ],
    "summary": "2-3 句话的整体安全评估总结"
}}

**如果没有发现风险:**
{{"risk_level": "LOW", "findings": [], "summary": "未发现明显安全风险。代码遵循了基本的安全最佳实践。"}}

---

**待分析内容:**

{content}

---

请开始分析，只返回 JSON 结果："""

def main():
    parser = argparse.ArgumentParser(description='语义审计执行器')
    parser.add_argument('content', nargs='?', help='待分析的内容')
    parser.add_argument('--file', '-f', help='从文件读取内容')
    parser.add_argument('--output', '-o', help='输出结果到文件')
    args = parser.parse_args()
    
    # 获取待分析内容
    if args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
    elif args.content:
        content = args.content
    else:
        # 从 stdin 读取
        content = sys.stdin.read()
    
    if not content.strip():
        print(json.dumps({
            "error": "无输入内容",
            "risk_level": "UNKNOWN",
            "findings": [],
            "summary": "未提供待分析的内容"
        }, ensure_ascii=False, indent=2))
        return 1
    
    # 创建提示词
    prompt = create_audit_prompt(content)
    
    # 输出特殊标记，父会话会拦截并使用 sessions_spawn 处理
    marker_start = "@@OPENCLAW_SEMANTIC_AUDIT@@"
    marker_end = "@@END_AUDIT@@"
    
    print(f"\n{marker_start}")
    print(json.dumps({
        "type": "semantic_audit_request",
        "prompt": prompt,
        "content_length": len(content),
        "content_preview": content[:500] + "..." if len(content) > 500 else content
    }, ensure_ascii=False))
    print(f"{marker_end}\n")
    
    # 注意：实际的 sessions_spawn 调用需要由父会话处理
    # 这里只是输出请求，等待父会话响应
    # 由于这是 subprocess，无法直接调用 sessions_spawn
    # 所以使用文件通信机制
    
    print("⚠️  注意：此脚本需要父会话配合处理审计请求")
    print("在 OpenClaw 会话中运行时，父会话应拦截上述标记并使用 sessions_spawn 处理")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())