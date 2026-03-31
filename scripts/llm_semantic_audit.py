#!/usr/bin/env python3
"""
LLM 语义审计脚本 - 使用 OpenClaw sessions_spawn

此脚本在 OpenClaw 会话中运行，使用 sessions_spawn 创建子代理进行代码安全分析。

使用方法:
    # 在 OpenClaw 会话中运行
    python3 scripts/llm_semantic_audit.py -t /path/to/skill
    
    # 或分析特定文件
    python3 scripts/llm_semantic_audit.py --file /path/to/code.py
"""

import sys
import os
import json
import argparse
import tempfile
import time

def create_audit_prompt(content: str, filename: str = "") -> str:
    """创建详细的审计提示词"""
    return f"""你是一位专业的代码安全审计专家，专注于 AI 技能和自动化脚本的安全分析。

请分析以下代码/配置文件，识别潜在的安全风险。

**分析维度:**
1. **凭证泄露**: API keys、passwords、tokens 是否硬编码
2. **注入风险**: SQL、command、path traversal 等注入点
3. **权限问题**: 权限提升、未授权访问、过度权限
4. **数据暴露**: 敏感数据未加密、日志泄露、隐私数据
5. **依赖风险**: 使用已知漏洞的第三方库
6. **配置问题**: 不安全默认值、调试模式、暴露内部信息
7. **执行风险**: eval/exec、动态代码执行、反序列化

**返回格式 (严格的 JSON，不要使用 markdown 包裹):**
{{
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "findings": [
        {{
            "severity": "LOW|MEDIUM|HIGH|CRITICAL",
            "category": "credential_leak|injection|privilege_escalation|data_exposure|dependency_risk|config_issue|execution_risk|other",
            "title": "简洁的风险标题",
            "description": "详细描述风险内容及其影响",
            "line": 行号（整数或 null）,
            "evidence": "触发风险的代码片段（最多 100 字符）",
            "confidence": 0.0-1.0 之间的置信度，
            "remediation": "具体修复建议"
        }}
    ],
    "summary": "2-3 句话的整体安全评估总结"
}}

**如果没有发现风险:**
{{"risk_level": "LOW", "findings": [], "summary": "未发现明显安全风险。代码遵循了基本的安全最佳实践。"}}

---

**文件**: {filename if filename else "未命名"}

**待分析内容:**

{content}

---

请开始分析，只返回 JSON 结果（不要包含其他文字）："""

def run_llm_analysis_via_sessions_spawn(prompt: str) -> dict:
    """
    使用 sessions_spawn 创建子代理进行 LLM 分析
    
    通过文件通信机制：
    1. 将分析请求写入临时文件
    2. 输出特殊标记，OpenClaw 会话会捕获
    3. OpenClaw 会话使用 sessions_spawn 处理
    4. 结果写入响应文件
    5. 本函数读取并返回结果
    """
    
    work_dir = tempfile.gettempdir()
    task_id = f"audit_{os.getpid()}_{int(time.time())}"
    request_file = os.path.join(work_dir, f"{task_id}_request.json")
    result_file = os.path.join(work_dir, f"{task_id}_result.json")
    
    try:
        # 写入请求
        with open(request_file, 'w', encoding='utf-8') as f:
            json.dump({
                "type": "semantic_audit",
                "task_id": task_id,
                "prompt": prompt,
                "timeout_seconds": 120,
                "created_at": time.time()
            }, f, ensure_ascii=False, indent=2)
        
        # 输出特殊标记，OpenClaw 会话会捕获
        print("\n" + "="*70, file=sys.stderr, flush=True)
        print("🔍 OPENCLAW_SESSIONS_SPAWN_REQUEST", file=sys.stderr, flush=True)
        print("="*70, file=sys.stderr, flush=True)
        print(json.dumps({
            "action": "sessions_spawn",
            "request_file": request_file,
            "result_file": result_file,
            "mode": "run",
            "runtime": "subagent"
        }, ensure_ascii=False, indent=2), file=sys.stderr, flush=True)
        print("="*70, file=sys.stderr, flush=True)
        print("END_SESSIONS_SPAWN_REQUEST 🔍", file=sys.stderr, flush=True)
        print("="*70 + "\n", file=sys.stderr, flush=True)
        
        # 轮询结果
        print(f"⏳ 等待 LLM 分析（最多 120 秒）...", file=sys.stderr, flush=True)
        start_time = time.time()
        max_wait = 120
        
        while time.time() - start_time < max_wait:
            if os.path.exists(result_file):
                try:
                    with open(result_file, 'r', encoding='utf-8') as f:
                        result = json.load(f)
                    # 清理临时文件
                    for rf in [request_file, result_file]:
                        try:
                            os.remove(rf)
                        except:
                            pass
                    return result
                except Exception as e:
                    print(f"⚠️ 读取结果失败：{e}", file=sys.stderr, flush=True)
                    return {"error": str(e), "risk_level": "UNKNOWN"}
            time.sleep(1)
        
        print(f"⚠️ 语义审计超时（{max_wait}秒）", file=sys.stderr, flush=True)
        return {"error": "timeout", "risk_level": "UNKNOWN"}
        
    except Exception as e:
        print(f"⚠️ 请求失败：{e}", file=sys.stderr, flush=True)
        return {"error": str(e), "risk_level": "UNKNOWN"}

def analyze_file(filepath: str) -> dict:
    """分析单个文件"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    prompt = create_audit_prompt(content, filepath)
    return run_llm_analysis_via_sessions_spawn(prompt)

def analyze_directory(dirpath: str) -> dict:
    """分析目录（只分析关键文件）"""
    files_to_analyze = []
    
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', 'dist', 'build']]
        
        for file in files:
            if file.endswith(('.py', '.js', '.ts', '.json', '.yml', '.yaml', '.md')):
                filepath = os.path.join(root, file)
                files_to_analyze.append(filepath)
    
    print(f"📁 发现 {len(files_to_analyze)} 个文件待分析", file=sys.stderr, flush=True)
    
    all_findings = []
    risk_scores = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}
    max_risk = "LOW"
    
    for filepath in files_to_analyze[:10]:  # 限制最多 10 个文件
        print(f"🔍 分析：{filepath}", file=sys.stderr, flush=True)
        try:
            result = analyze_file(filepath)
            if result.get('findings'):
                for finding in result['findings']:
                    finding['file'] = filepath
                    all_findings.append(finding)
                if risk_scores.get(result.get('risk_level', 'LOW'), 0) > risk_scores.get(max_risk, 0):
                    max_risk = result.get('risk_level', 'LOW')
        except Exception as e:
            print(f"⚠️ 分析失败 {filepath}: {e}", file=sys.stderr, flush=True)
    
    return {
        "risk_level": max_risk,
        "findings": all_findings,
        "summary": f"分析了 {min(len(files_to_analyze), 10)} 个文件，发现 {len(all_findings)} 个安全问题",
        "files_analyzed": min(len(files_to_analyze), 10)
    }

def main():
    parser = argparse.ArgumentParser(description='LLM 语义审计（使用 sessions_spawn）')
    parser.add_argument('-t', '--target', help='扫描目标（文件或目录）')
    parser.add_argument('--file', '-f', help='分析单个文件')
    parser.add_argument('--stdin', action='store_true', help='从 stdin 读取内容')
    parser.add_argument('--output', '-o', help='输出结果到文件')
    args = parser.parse_args()
    
    result = None
    
    try:
        if args.stdin:
            content = sys.stdin.read()
            prompt = create_audit_prompt(content)
            result = run_llm_analysis_via_sessions_spawn(prompt)
        
        elif args.file:
            result = analyze_file(args.file)
        
        elif args.target:
            if os.path.isfile(args.target):
                result = analyze_file(args.target)
            elif os.path.isdir(args.target):
                result = analyze_directory(args.target)
            else:
                print(f"❌ 目标不存在：{args.target}", file=sys.stderr)
                return 1
        else:
            parser.print_help()
            return 1
        
        # 输出结果
        output = json.dumps(result, ensure_ascii=False, indent=2)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"✅ 结果已保存到：{args.output}")
        else:
            print("\n" + "="*60)
            print("📊 语义审计结果")
            print("="*60)
            print(output)
        
        risk_exit_codes = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3, "UNKNOWN": 1}
        return risk_exit_codes.get(result.get('risk_level', 'UNKNOWN'), 1)
        
    except KeyboardInterrupt:
        print("\n⚠️ 用户中断", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"❌ 错误：{e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())