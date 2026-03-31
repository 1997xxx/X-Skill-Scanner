#!/usr/bin/env python3
"""
语义审计协调器

在 OpenClaw 会话中运行此脚本，它会：
1. 执行扫描器
2. 拦截语义审计请求
3. 使用 sessions_spawn 创建子代理分析
4. 返回完整结果

使用方法:
    python3 scripts/semantic_audit_coordinator.py -t /path/to/skill
"""

import subprocess
import sys
import json
import os
import tempfile
import time
import argparse

def call_llm_via_sessions_spawn(prompt: str) -> dict:
    """
    使用 sessions_spawn 创建子代理进行 LLM 分析
    
    注意：此函数需要在 OpenClaw 会话环境中运行
    实际调用方式取决于 OpenClaw 的 Python SDK
    """
    # 由于无法直接导入 sessions_spawn（这是 OpenClaw 内部工具）
    # 我们通过输出特殊标记，让 OpenClaw 宿主环境处理
    
    print(f"\n@@REQUEST_SESSIONS_SPAWN@@")
    print(json.dumps({
        "type": "llm_analysis",
        "prompt": prompt,
        "mode": "run"
    }, ensure_ascii=False))
    print(f"@@END_REQUEST@@\n")
    
    # 等待响应（通过临时文件通信）
    task_id = f"llm_{os.getpid()}_{int(time.time())}"
    result_file = os.path.join(tempfile.gettempdir(), f"{task_id}_result.json")
    
    # 轮询结果
    max_wait = 120
    start = time.time()
    while time.time() - start < max_wait:
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        time.sleep(1)
    
    return {"error": "timeout", "risk_level": "UNKNOWN"}

def run_scan_with_semantic_audit(target: str, config_file: str = None):
    """运行扫描器并处理语义审计请求"""
    
    # 构建扫描命令
    scanner_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scan_cmd = [os.path.join(scanner_dir, 'scan'), '-t', target]
    
    if config_file:
        scan_cmd.extend(['-c', config_file])
    
    print(f"🔍 开始扫描：{target}")
    print(f"命令：{' '.join(scan_cmd)}\n")
    
    # 运行扫描器
    process = subprocess.Popen(
        scan_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    audit_queue = []  # 待审计请求队列
    
    # 逐行处理输出
    for line in process.stdout:
        line = line.strip()
        
        # 检测语义审计请求标记
        if '@@OPENCLAW_SEMANTIC_AUDIT@@' in line or '@@OPENCLAW_SEMANTIC_AUDIT_REQUEST@@' in line:
            # 下一行是请求文件路径
            request_file_line = next(process.stdout, '').strip()
            if os.path.exists(request_file_line):
                with open(request_file_line, 'r', encoding='utf-8') as f:
                    request = json.load(f)
                audit_queue.append(request)
                print(f"📋 捕获语义审计请求")
                continue
        
        print(line)
    
    # 处理所有审计请求
    stderr = process.stderr.read()
    if stderr:
        print(f"\n⚠️ 扫描器输出:\n{stderr}", file=sys.stderr)
    
    if audit_queue:
        print(f"\n🔍 共有 {len(audit_queue)} 项需要语义审计\n")
        for request in audit_queue:
            print(f"分析：{request.get('prompt', '')[:200]}...")
            # 使用 LLM 分析
            # result = call_llm_via_sessions_spawn(request['prompt'])
            # TODO: 实际调用
    
    process.wait()
    return process.returncode

def main():
    parser = argparse.ArgumentParser(description='语义审计协调器')
    parser.add_argument('-t', '--target', required=True, help='扫描目标路径')
    parser.add_argument('-c', '--config', help='配置文件路径')
    args = parser.parse_args()
    
    return run_scan_with_semantic_audit(args.target, args.config)

if __name__ == '__main__':
    sys.exit(main())