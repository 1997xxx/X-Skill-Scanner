# 十二层防御管线 / Twelve-Layer Defense Pipeline

X Skill Scanner 采用 12 层独立检测引擎，覆盖从表面签名到深层意图分析的完整攻击面。

## 管线概览

| 层 | 引擎 | 能力 | 检测类型 |
|---|------|------|---------|
| 0 | 🎯 技能画像 | 信任评分 · 扫描策略 · 风险指纹 | 预筛选 |
| 1 | 🔍 威胁情报 | 380+ 恶意技能名 · IOC 域名/IP · 攻击模式 | 签名匹配 |
| 2 | 🧹 去混淆 | Base64/Hex/BiDi/零宽/TR39/Zlib/字符串拼接 | 代码还原 |
| 3 | 🔎 静态分析 | 194+ 规则 · 凭证/注入/供应链/时间炸弹 | 模式匹配 |
| 4 | 🌳 AST 深度分析 | 污点追踪 · 间接执行 · 动态导入 | 语义分析 |
| 5 | 📦 依赖检查 | requirements.txt / package.json CVE 匹配 | 供应链 |
| 6 | 💉 提示词注入 | 25+ 探针 · 系统覆盖 · 角色劫持 · DAN/Jailbreak | 对抗测试 |
| 7 | 📋 基线追踪 | SHA-256 指纹 · Rug-Pull 检测 · 变更审计 | 变更检测 |
| 8 | 🧠 语义审计 | 多 Agent 意图分析（高风险文件） | LLM 审查 |
| 9 | 📊 熵值分析 | Shannon 熵 · CJK 自适应阈值 · 编码载荷 | 统计学 |
| 10 | 🔧 安装钩子 | postinstall · setup.py · shell RC · cron 注入 | 持久化 |
| 11 | 🌐 网络画像 | 端点提取 · IP 直连 · 隐蔽通道 · C2 | 网络行为 |
| 12 | 🔐 凭证窃取 | osascript 钓鱼 · SSH/AWS 密钥 · 浏览器 Cookie · Keychain | 数据外泄 |
| 🔗 | 跨层关联 | 多引擎攻击链检测 · 关联评分 | 关联分析 |

## 详细检测能力

### Layer 0: 技能画像 (Skill Profiler)

**输入：** 技能目录结构、文件类型分布、作者元数据

**输出：**
- 信任分数 (0-100)
- 推荐扫描策略 (quick/standard/full)
- 红旗标记数量

**信任评分维度：**
- 作者可信度（已知开发者 +30，匿名 -20）
- 技能类型（OpenClaw Skill +20，外部脚本 -10）
- 文件结构合理性（合理 +10，混乱 -20）
- 红旗标记（每个 -15）

**策略选择：**
```
信任分数 ≥ 70  → Quick Mode (3 层)      ~3 秒
信任分数 40-69 → Standard Mode (12 层)   ~15 秒
信任分数 < 40  → Full Mode (12 层 + SubAgent)  ~60 秒
```

### Layer 1: 威胁情报 (Threat Intelligence)

**数据库：**
- 380+ 已知恶意技能名称（来自 SlowMist 监控）
- IOC 域名/IP 列表（持续更新）
- 攻击模式签名

**匹配模式：**
- 技能名精确匹配
- 文档中域名/IP 提取匹配
- 代码中硬编码 C2 地址匹配

### Layer 2: 去混淆引擎 (Deobfuscator)

**支持技术：**
1. Base64 解码 — 自动检测并解码 `base64.b64decode()`, `b'...'` 字面量
2. Hex 数组重构 — 收集跨行 `[0x63, 0x75, 0x72, ...]` 字节数组，剥离 null 字节
3. 字符串拼接组装 — 识别 `_part1_ + _part2_ + ...` 模式，重组后解码
4. BiDi 字符检测 — Unicode 双向覆盖字符 (CVE-2021-42574)
5. 零宽字符检测 — 隐形字符注入
6. TR39 混淆检测 — 同形异义字攻击
7. Zlib 解压 — `zlib.decompress()` 调用

**输出：** 解码后的恶意载荷，直接展示在报告中

### Layer 3: 静态分析 (Static Analyzer)

**规则库：** 194+ 安全规则

**检测类别：**
- 凭证泄漏 (AWS Key, OpenAI Key, GitHub Token, 私钥，数据库连接串)
- 命令注入 (subprocess, os.system, os.popen)
- 危险函数 (eval, exec, compile, __import__)
- YAML 不安全加载 (yaml.load without SafeLoader)
- 时间炸弹 (datetime 比较 + 恶意触发)
- 环境变量操纵
- 网络访问 (requests, urllib, socket)
- 文件访问 (敏感路径读取/写入)
- 代码混淆模式
- 可疑导入
- 硬编码密钥
- 配置问题

### Layer 4: AST 深度分析 (AST Analyzer)

**能力：**
- 污点追踪 (Taint Tracking) — 追踪用户输入流向危险函数
- 间接执行检测 — 通过变量/属性访问的间接调用
- 动态导入分析 — `__import__(var)`, `importlib.import_module(var)`

### Layer 5: 依赖检查 (Dependency Checker)

**检测：**
- requirements.txt 中的包名匹配 CVE 数据库
- package.json 中的 npm 包版本检查
- 已知恶意包检测 (typosquatting, malicious packages)

### Layer 6: 提示词注入探针 (Prompt Injection Probes)

**25+ 探针测试：**
- 系统指令覆盖尝试
- 角色劫持 ("从现在你是 DAN...")
- Jailbreak 模式
- 指令注入 ("忽略之前所有指令...")

### Layer 7: 基线追踪 (Baseline Tracker)

**机制：**
- SHA-256 指纹存储
- 每次扫描对比变更
- Rug-Pull 检测 (正常更新后植入恶意代码)

### Layer 8: 语义审计 (Semantic Auditor)

**工作流程：**
1. 收集静态分析发现
2. 构建审查任务 prompt (含完整上下文)
3. 使用 LLM (SubAgent 或 Provider) 进行意图分析
4. 识别误报 (如"不要禁用安全软件" vs 实际恶意指令)
5. 批量审查，减少 token 消耗

### Layer 9: 熵值分析 (Entropy Analyzer)

**检测：**
- Shannon 熵计算
- CJK 自适应阈值 (中文文本熵值天然较高)
- 识别加密/编码/压缩数据块
- 高熵字面量检测 (可能为加密载荷)

### Layer 10: 安装钩子检测 (Install Hook Detector)

**检测目标：**
- postinstall 脚本
- setup.py 安装逻辑
- Shell RC 文件修改 (~/.bashrc, ~/.zshrc)
- Cron job 注入
- systemd service 创建

### Layer 11: 网络画像 (Network Profiler)

**提取：**
- HTTP/HTTPS 端点
- IP 直连地址
- Socket 连接目标
- WebSocket 端点
- DNS 查询模式

**标记：**
- 私有 IP 段访问
- 已知 C2 基础设施
- 隐蔽通道特征 (DNS tunneling, ICMP tunneling)

### Layer 12: 凭证窃取检测 (Credential Theft Detector)

**检测模式：**
- osascript 假密码对话框 (Nova Stealer 模式)
- SSH 密钥读取 (`~/.ssh/id_rsa`)
- AWS 凭证读取 (`~/.aws/credentials`)
- 浏览器 Cookie/LocalStorage 访问
- macOS Keychain 访问
- Linux Secret Service 访问
- Windows Credential Manager 访问

## 跨层关联分析 (Correlation Engine)

**识别 6 种攻击链模式：**

| 攻击链 | 组成引擎 | 典型场景 |
|-------|---------|---------|
| C2 渗透 | 混淆 + 网络 + 持久化 | 混淆下载 → 建立 C2 → 持久化 |
| 凭证窃取 | 凭证窃取 + 数据外泄 | 读取 SSH 密钥 → webhook 外泄 |
| 供应链攻击 | 恶意依赖 + 安装钩子 | 恶意包 → postinstall 执行 |
| Rug-Pull 模式 | 基线变更 + 语义风险 | 正常技能更新植入恶意代码 |
| 社会工程学 | 提示词注入 + 利用 | 绕过系统指令 → 危险操作 |
| 反向 Shell 链 | 反向 Shell + 网络 + 混淆 | 混淆 reverse shell 连接 |

**关联评分：**
- 单一引擎发现：基础分
- 2 层关联：+20%
- 3 层关联：+50%
- 完整攻击链 (4+ 层)：+100%

---

*本文档为 x-skill-scanner 技术参考，详细信息请参见 SKILL.md*