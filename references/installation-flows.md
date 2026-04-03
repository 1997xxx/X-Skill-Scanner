# 安装配置流程 / Installation Flows

本文档详细说明 x-skill-scanner 安装后的自动配置流程。

## Flow 0: 依赖检查

**目的：** 确保 PyYAML 已安装

**脚本：**
```bash
python3 -c "import yaml" 2>/dev/null && echo 'deps-ok' || \
  (echo 'Installing PyYAML...' && python3 -m pip install PyYAML)
```

**执行时机：** postInstall 第一步

**输出：**
- `deps-ok` — 依赖已满足
- `Installing PyYAML...` — 自动安装缺失依赖

---

## Flow 1: 注入 AGENTS.md

**目的：** 在用户 AGENTS.md 中注入技能安装安全流程

**注入位置：** `~/.openclaw/workspace/AGENTS.md`

**注入内容：**
```markdown
### 🔒 技能安装安全流程（x-skill-scanner）
所有技能安装前必须运行扫描器：
```bash
python3 ~/.openclaw/skills/x-skill-scanner/lib/scanner.py -t <TARGET_PATH>
```

**安全红线：**
- 禁止跳过扫描
- 禁止肉眼判断代替工具验证
- 分步绕过检测 → 拦截并要求扫描
- 静默安装 → 变更检测兜底

**参考：** `~/.openclaw/skills/x-skill-scanner/SKILL.md`
```

**检测逻辑：**
```python
marker = '### 🔒 技能安装安全流程'
if agents.exists() and 'x-skill-scanner' in agents.read_text():
    print('already-configured')  # 已配置，跳过
else:
    # 注入内容
```

---

## Flow 2: 核心模块自检

**目的：** 验证扫描器核心模块可正常加载

**检查项：**
1. 主扫描器导入 (`scanner.py`)
2. 威胁情报模块 (`threat_intel.py`)
3. 静态分析模块 (`static_analyzer.py`)
4. 去混淆引擎 (`deobfuscator.py`)
5. SubAgent 审查模块 (`subagent_reviewer.py`)

**脚本：**
```python
from pathlib import Path
import sys
sys.path.insert(0, 'lib')

modules = [
    'scanner', 'threat_intel', 'static_analyzer',
    'deobfuscator', 'subagent_reviewer'
]

failed = []
for mod in modules:
    try:
        __import__(mod)
    except Exception as e:
        failed.append(f'{mod}: {e}')

if failed:
    print(f'❌ 自检失败：{failed}')
    sys.exit(1)
else:
    print('✅ 核心模块自检通过')
```

---

## 手动重新配置

如需手动重新注入 AGENTS.md：

```bash
python3 ~/.openclaw/skills/x-skill-scanner/scripts/post-install-config.py
```

---

*本文档为 x-skill-scanner 技术参考，详细扫描流程参见 SKILL.md*