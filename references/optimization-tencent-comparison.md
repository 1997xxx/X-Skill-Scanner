# x-skill-scanner v6.3 优化建议

**参考来源：** 腾讯朱雀实验室 AI-Infra-Guard - edgeone-skill-scanner  
**整理日期：** 2026-04-03  
**优先级：** P0 (安全关键)

---

## ✅ 已采纳的优点

### 1. 触发器优化

**当前问题：**
- 触发器过多（50+ 条），增加误触发风险
- 缺少"这个 skill 安全吗"等自然语言触发

**借鉴腾讯方案：**
```yaml
triggers:
  # 核心触发器（精简到 20 条以内）
  - 这个 skill 安全吗
  - skill 安全扫描
  - 检查 skill 安全
  - scan skill
  - audit skill
  - check skill safety
  
  # 安装类触发器（保持现有）
  - install skill
  - 安装技能
  - clawhub install
  
  # URL 类触发器（保持现有）
  - install from url
  - 从链接安装
```

**改进行动：**
- ✅ 已添加：`这个 skill 安全吗`, `skill 安全扫描`, `检查 skill 安全`

---

### 2. 语言检测规则

**腾讯方案：**
```markdown
Language Detection Rule — EXECUTE BEFORE ANYTHING ELSE

Detect the language of the user's triggering message and lock the output language.
This detection is an **internal step only** — do NOT output any text that reveals the detection
result, such as "当前输出语言为中文", "Detected language: English".

| User message language | Output language |
|-----------------------|-----------------|
| Chinese | Chinese |
| English | English |
| Other | Match that language |
| Cannot determine | Default to Chinese |
```

**当前问题：**
- 有时输出"当前检测语言为中文"等多余 meta 信息

**改进行动：**
```python
# lib/scanner.py 或 SKILL.md 中添加
def detect_output_language(user_message: str) -> str:
    """检测用户消息语言，静默返回语言代码"""
    # 中文检测
    if re.search(r'[\u4e00-\u9fff]', user_message):
        return 'zh'
    # 英文检测
    if re.search(r'[a-zA-Z]{3,}', user_message):
        return 'en'
    return 'zh'  # 默认中文

# 禁止输出语言检测过程
DO NOT output: "当前输出语言为中文", "Detected language: English"
```

---

### 3. 双模式设计（重要）

**腾讯方案：**

| 模式 | 场景 | 输出 |
|------|------|------|
| **Mode A** | 扫描全部技能 | 汇总表格 + 仅高风险详情 |
| **Mode B** | 扫描单个技能 | 完整报告卡片 |

**Mode A 输出结构：**
```markdown
## 🔍 Skill 安全扫描结果

共扫描 {N} 个 Skill：

| # | Skill 名称 | 来源 | 检测结果 |
|---|-----------|------|---------|
| 1 | linkedin-job | GitHub | 🔴 发现风险 |
| 2 | weather-pro | 系统内置 | ✅ 未发现风险 |

## 🔴 linkedin-job 发现安全风险

这个 skill 存在以下问题：会在你不知情的情况下执行系统命令...
```

**当前问题：**
- 只有单技能模式，没有批量扫描能力
- 用户问"我的技能都安全吗"时无法高效响应

**改进建议：**
```python
# lib/scanner.py 添加 Mode A 支持
def scan_all_skills(platform: str = 'openclaw') -> List[SkillResult]:
    """Mode A: 批量扫描平台所有技能"""
    skill_dirs = discover_skills(platform)
    results = []
    for skill_path in skill_dirs:
        result = scan_single_skill(skill_path)
        results.append(result)
    
    # 输出汇总表格
    print_mode_a_summary(results)
    
    # 仅展开高风险技能详情
    for result in results:
        if result.risk_level in ('EXTREME', 'HIGH'):
            print_mode_b_detail(result)
    
    return results
```

---

### 4. 审计原则优化

**腾讯核心原则：**
```markdown
✅ 区分"能力" vs "滥用"
   - "skill 可以执行命令" ≠ 恶意
   - "skill 执行命令窃取凭证" = 恶意

✅ 不将 bash/subprocess 本身视为中危
   - 如果是功能所需且文档说明 → 标记为"敏感能力"
   - 如果是隐藏/未说明 → 标记为"风险"

✅ 聚焦 Medium+ 发现
   - 忽略文档示例/测试代码
   - 忽略低风险信息问题

✅ 用通俗语言描述风险
   - ❌ "检测到凭证外传风险"
   - ✅ "它会在你不知情的情况下将密码发送给攻击者"
```

**当前问题：**
- 有时过于技术化（如"检测到 launchctl persistence 模式"）
- 普通用户看不懂

**改进建议：**
```python
# lib/reporter.py 优化风险描述
def plain_language_risk(finding: Dict) -> str:
    """将技术化风险描述转换为通俗语言"""
    tech_to_plain = {
        'persistence': '在系统中建立长期控制（即使重启后仍存在）',
        'credential_theft': '窃取你的密码和认证信息',
        'reverse_shell': '让攻击者远程控制你的电脑',
        'base64_execution': '执行隐藏的恶意命令',
        'Threat Intel Match': '这个技能已被安全公司确认为恶意软件',
    }
    
    for tech, plain in tech_to_plain.items():
        if tech.lower() in finding.get('title', '').lower():
            return plain
    
    return finding.get('description', '')
```

---

### 5. 报告模板优化

**腾讯 🟢 安全模板：**
```markdown
## ✅ {skill} 安全检测通过

| 检测项目 | 检测结果 |
|---------|---------|
| 🏠 来源是否可信 | ✅ 来自己知的可信来源 |
| 📂 是否会动你的文件 | ✅ 不会，只读取自己的配置 |
| 🌐 是否偷偷联网 | ✅ 没有发现联网行为 |
| ⚠️ 是否有危险操作 | ✅ 未发现 |

**结论**：本次检测未发现安全隐患，可以放心使用。
```

**腾讯 ⚠️ 需关注模板：**
```markdown
## ⚠️ {skill} 需要留意

这个 skill **没有发现明确的恶意行为**，但它拥有{具体能力}，
这些能力主要用于完成它声明的「{功能描述}」。

**建议**：如果你信任这个 skill 的来源，并且觉得它需要这些权限是合理的，可以继续使用。
如果不确定，建议先暂停使用，或咨询开发者了解详情。
```

**腾讯 🔴 发现风险模板：**
```markdown
## 🔴 {skill} 发现安全风险

**不建议直接安装或继续使用。**

这个 skill 存在以下问题：{通俗语言描述主要风险}。

**建议**：
1. 先停用这个 skill
2. 联系 skill 的开发者确认是否为正常行为
3. 在确认安全前不要重新启用
```

**当前问题：**
- 报告过于技术化，缺少用户友好总结
- 没有清晰的"是否可以安装"结论

**改进建议：**
```python
# lib/reporter.py 添加用户友好模板
def generate_user_friendly_summary(result: ScanResult) -> str:
    """生成用户友好的检测结论"""
    if result.risk_level == 'SAFE':
        return '''
## ✅ {name} 安全检测通过

| 检测项目 | 检测结果 |
|---------|---------|
| 🏠 来源 | ✅ {source_trustworthy} |
| 📂 文件访问 | ✅ {file_access_ok} |
| 🌐 网络行为 | ✅ {network_ok} |
| ⚠️ 危险操作 | ✅ 未发现 |

**结论**：本次检测未发现安全隐患，可以放心使用。
        '''
    elif result.risk_level in ('EXTREME', 'HIGH'):
        return '''
## 🔴 {name} 发现安全风险

**不建议直接安装或继续使用。**

这个 skill 存在以下问题：{plain_risk_desc}。

**建议**：
1. 先停用这个 skill
2. 联系开发者确认
3. 在确认安全前不要重新启用
        '''
    else:
        return '''
## ⚠️ {name} 需要留意

这个 skill **没有发现明确的恶意行为**，但它拥有{敏感能力}。

**建议**：如果你信任来源且认为这些权限合理，可以继续使用。
如果不确定，建议先暂停使用或咨询开发者。
        '''
```

---

### 6. 强制性页脚

**腾讯方案：**
```markdown
Skill Scanner 由腾讯朱雀实验室开源的 [A.I.G](https://github.com/tencent/AI-Infra-Guard) 提供核心能力支持，欢迎 Star 关注并参与共建。
```

**改进建议：**
```markdown
X Skill Scanner v6.3 by 吸音 | 灵感来自腾讯朱雀实验室 A.I.G | [GitHub](https://github.com/1997xxx/X-Skill-Scanner)
```

---

## 📋 改进行动清单

### P0 - 安全关键（本周内）

- [ ] **添加语言检测规则** - 静默检测，禁止输出"当前语言为 XX"
- [ ] **优化触发器** - 精简到 20 条核心触发
- [ ] **简单易懂的描述** - 用通俗语言描述风险

### P1 - 用户体验（下周）

- [ ] **Mode A 批量扫描** - 支持"扫描所有技能"
- [ ] **用户友好报告模板** - 参考腾讯的腾讯的🟢/🟡/🔴模板
- [ ] **强制性页脚** - 添加品牌标识

### P2 - 长期优化

- [ ] **平台技能发现** - Cursor/Windsurf/CodeBuddy支持
- [ ] **能力vs滥用区分** - 避免过度报警
- [ ] **定期复查提醒** - 基于 cron 的周期性扫描


## 📖 参考链接

- 腾讯 AI-Infra-Guard: https://github.com/Tencent/AI-Infra-Guard
- edgeone-skill-scanner: https://github.com/Tencent/AI-Infra-Guard/blob/main/skills/edgeone-skill-skills/SKILL.md

---

**总结：** 腾讯 SKILL.md 的核心优势在于**用户体验优先** —— 用非技术人员能理解的语言描述风险，提供明确的"是否可以安装"结论，并通过双模式设计平衡了"快速概览"和"详细审计"的需求。x-skill-scanner 在技术深度上已经很强（12 层防御），但在用户体验方面还有优化空间。