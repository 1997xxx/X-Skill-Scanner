# OpenClaw 父会话处理器

当 `llm_semantic_audit.py` 脚本运行时，它会输出特殊标记。父会话需要捕获这些标记并使用 `sessions_spawn` 处理。

## 处理器代码

在 OpenClaw 会话中运行以下 Python 代码来处理语义审计请求：

```python
import json
import os
import time

def handle_sessions_spawn_request():
    """
    监听并处理 sessions_spawn 请求
    
    此函数应在 OpenClaw 会话中运行，监听 stderr 输出中的特殊标记
    """
    # 轮询临时目录中的请求文件
    work_dir = '/tmp'
    
    while True:
        # 查找请求文件
        for filename in os.listdir(work_dir):
            if filename.startswith('audit_') and filename.endswith('_request.json'):
                request_file = os.path.join(work_dir, filename)
                
                try:
                    with open(request_file, 'r', encoding='utf-8') as f:
                        request = json.load(f)
                    
                    if request.get('type') == 'semantic_audit':
                        task_id = request['task_id']
                        prompt = request['prompt']
                        result_file = request_file.replace('_request.json', '_result.json')
                        
                        print(f"🔍 处理语义审计请求：{task_id}")
                        
                        # 使用 sessions_spawn 创建子代理
                        # 注意：以下是伪代码，实际 API 请参考 OpenClaw 文档
                        
                        # 方法 1: 直接在当前会话中使用 LLM
                        # result = call_current_llm(prompt)
                        
                        # 方法 2: 使用 sessions_spawn 创建子代理
                        # session = sessions_spawn(
                        #     task=prompt,
                        #     mode="run",
                        #     runtime="subagent",
                        #     cleanup="delete"
                        # )
                        # result = session.get_result()
                        
                        # 将结果写入文件
                        with open(result_file, 'w', encoding='utf-8') as f:
                            json.dump(result, f, ensure_ascii=False, indent=2)
                        
                        print(f"✅ 审计完成：{task_id}")
                    
                except Exception as e:
                    print(f"⚠️ 处理请求失败：{e}")

# 运行处理器（在后台）
# handle_sessions_spawn_request()
```

## 简化的方法：直接在当前会话处理

更简单的方式是在运行 `llm_semantic_audit.py` 时，手动将提示词发送给当前会话的 LLM：

1. 运行脚本：`python3 scripts/llm_semantic_audit.py -t /path/to/skill`
2. 脚本会输出 `🔍 OPENCLAW_SESSIONS_SPAWN_REQUEST` 标记
3. 标记中包含 JSON 格式的提示词
4. 将提示词复制并发送给当前 OpenClaw 会话
5. LLM 返回分析结果
6. 将结果保存为 `result.json`

## 自动化处理器（推荐）

创建一个后台脚本自动处理：

```bash
# monitor_audit_requests.sh
#!/bin/bash

while true; do
    # 查找请求文件
    for file in /tmp/audit_*_request.json; do
        if [ -f "$file" ]; then
            result_file="${file/_request/_result}"
            
            # 提取提示词
            prompt=$(python3 -c "import json; print(json.load(open('$file'))['prompt'])")
            
            # 调用 OpenClaw LLM (需要使用 OpenClaw API)
            # 这里需要根据实际 API 调整
            result=$(openclaw-llm "$prompt")
            
            # 保存结果
            echo "$result" > "$result_file"
            
            echo "✅ 处理完成：$file"
        fi
    done
    
    sleep 2
done
```

## 注意事项

1. **权限**: 确保脚本有权限读写 `/tmp` 目录
2. **超时**: 请求文件应在 120 秒内被处理
3. **清理**: 处理完成后应删除临时文件
4. **并发**: 多个请求可能同时到达，需要处理并发

## 测试

```bash
# 终端 1: 运行处理器
python3 scripts/openclaw_session_handler.py

# 终端 2: 运行审计
python3 scripts/llm_semantic_audit.py --file /path/to/test.py
```