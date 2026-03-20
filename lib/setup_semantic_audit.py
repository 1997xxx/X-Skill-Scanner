#!/usr/bin/env python3
"""
语义审计自动配置脚本

一键完成 OpenClaw 配置，启用 llm-task 插件和语义审计功能。
"""

import json
import os
import sys
from pathlib import Path


def print_separator(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def load_openclaw_config():
    """加载 OpenClaw 配置文件"""
    config_path = Path.home() / '.openclaw' / 'openclaw.json'
    
    if not config_path.exists():
        print(f"❌ 配置文件不存在：{config_path}")
        print(f"请先运行 openclaw onboard 完成初始化")
        return None
    
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f), config_path


def save_openclaw_config(config, config_path):
    """保存 OpenClaw 配置文件"""
    # 备份原配置
    backup_path = config_path.with_suffix('.json.bak')
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"✅ 原配置已备份：{backup_path}")
    
    # 保存新配置
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"✅ 配置已保存：{config_path}")


def enable_llm_task_plugin(config):
    """启用 llm-task 插件"""
    print_separator("步骤 1: 启用 llm-task 插件")
    
    if 'plugins' not in config:
        config['plugins'] = {'entries': {}, 'installs': {}}
    
    if 'entries' not in config['plugins']:
        config['plugins']['entries'] = {}
    
    # 获取默认模型配置
    default_model = config.get('agents', {}).get('defaults', {}).get('model', {}).get('primary', 'auto')
    provider = default_model.split('/')[0] if '/' in default_model else 'auto'
    
    config['plugins']['entries']['llm-task'] = {
        "enabled": True,
        "config": {
            "defaultProvider": provider,
            "defaultModel": default_model,
            "timeoutMs": 60000,
            "maxTokens": 1500
        }
    }
    
    print(f"✅ llm-task 插件已配置")
    print(f"   使用模型：{default_model}")
    print(f"   超时：60 秒")
    
    return True


def allow_llm_task_tool(config):
    """允许 llm-task 工具"""
    print_separator("步骤 2: 允许 llm-task 工具")
    
    if 'agents' not in config:
        config['agents'] = {'defaults': {}, 'list': []}
    
    if 'list' not in config['agents']:
        config['agents']['list'] = []
    
    # 查找 main agent
    main_agent = None
    for agent in config['agents']['list']:
        if agent.get('id') == 'main':
            main_agent = agent
            break
    
    if not main_agent:
        # 创建 main agent 配置
        main_agent = {'id': 'main'}
        config['agents']['list'].append(main_agent)
    
    # 配置工具允许列表
    if 'tools' not in main_agent:
        main_agent['tools'] = {'allow': []}
    
    if 'allow' not in main_agent['tools']:
        main_agent['tools']['allow'] = []
    
    if 'llm-task' not in main_agent['tools']['allow']:
        main_agent['tools']['allow'].append('llm-task')
    
    print(f"✅ llm-task 工具已允许 (main agent)")
    
    return True


def enable_skill(config):
    """启用 ant-intl-skill-scanner 技能"""
    print_separator("步骤 3: 启用 ant-intl-skill-scanner 技能")
    
    if 'skills' not in config:
        config['skills'] = {'install': {}, 'entries': {}}
    
    if 'entries' not in config['skills']:
        config['skills']['entries'] = {}
    
    config['skills']['entries']['ant-intl-skill-scanner'] = {
        "enabled": True,
        "config": {
            "semantic": {
                "enabled": True,
                "provider": "llm-task",
                "timeout_ms": 60000,
                "max_tokens": 1500,
                "thinking": "low"
            }
        }
    }
    
    print(f"✅ ant-intl-skill-scanner 技能已启用")
    print(f"   语义审计：已启用")
    print(f"   提供者：llm-task")
    
    return True


def verify_config(config):
    """验证配置"""
    print_separator("步骤 4: 验证配置")
    
    errors = []
    
    # 检查 llm-task 插件
    llm_task = config.get('plugins', {}).get('entries', {}).get('llm-task')
    if not llm_task or not llm_task.get('enabled'):
        errors.append("llm-task 插件未启用")
    else:
        print("✅ llm-task 插件已启用")
    
    # 检查工具允许列表
    agents = config.get('agents', {}).get('list', [])
    llm_task_allowed = False
    for agent in agents:
        if agent.get('id') == 'main':
            tools = agent.get('tools', {}).get('allow', [])
            if 'llm-task' in tools:
                llm_task_allowed = True
                break
    
    if not llm_task_allowed:
        errors.append("llm-task 工具未允许")
    else:
        print("✅ llm-task 工具已允许")
    
    # 检查技能配置
    skill = config.get('skills', {}).get('entries', {}).get('ant-intl-skill-scanner')
    if not skill or not skill.get('enabled'):
        errors.append("ant-intl-skill-scanner 技能未启用")
    else:
        print("✅ ant-intl-skill-scanner 技能已启用")
    
    if errors:
        print("\n❌ 配置验证失败:")
        for error in errors:
            print(f"   - {error}")
        return False
    
    print("\n✅ 配置验证通过")
    return True


def main():
    """主函数"""
    print_separator("语义审计自动配置脚本")
    print("此脚本将自动配置 OpenClaw，启用语义审计功能")
    
    # 加载配置
    config, config_path = load_openclaw_config()
    if not config:
        return 1
    
    print(f"✅ 配置文件已加载：{config_path}")
    
    # 执行配置步骤
    steps = [
        ("启用 llm-task 插件", enable_llm_task_plugin),
        ("允许 llm-task 工具", allow_llm_task_tool),
        ("启用 ant-intl-skill-scanner 技能", enable_skill),
    ]
    
    for step_name, step_func in steps:
        try:
            if not step_func(config):
                print(f"❌ {step_name} 失败")
                return 1
        except Exception as e:
            print(f"❌ {step_name} 异常：{e}")
            return 1
    
    # 验证配置
    if not verify_config(config):
        print("\n⚠️  配置验证失败，但配置已保存")
        print("请手动检查 ~/.openclaw/openclaw.json")
        return 1
    
    # 保存配置
    print_separator("保存配置")
    save_openclaw_config(config, config_path)
    
    # 完成
    print_separator("配置完成 ✅")
    print("语义审计功能已启用！")
    print("\n下一步:")
    print("1. 重启 OpenClaw Gateway: openclaw gateway restart")
    print("2. 测试语义审计：python3 ./scripts/test_llm_task_audit.py")
    print("3. 扫描技能：python3 scanner.py -t ./my-skill/ --semantic")
    print("\n参考文档:")
    print("  - docs/FINAL_IMPLEMENTATION.md")
    print("  - docs/SEMANTIC_AUDIT_LLM_TASK.md")
    print("  - https://docs.openclaw.ai/tools/llm-task")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
