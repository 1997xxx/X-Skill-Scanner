# 贡献指南

感谢你对 Ant International Skill Scanner 的兴趣！

## 🚀 快速开始

### 1. Fork 项目

```bash
git clone https://github.com/your-username/ant-intl-skill-scanner.git
cd ant-intl-skill-scanner
```

### 2. 安装依赖

```bash
pip3 install -r requirements.txt
```

### 3. 创建分支

```bash
git checkout -b feature/your-feature-name
```

---

## 📝 贡献类型

### 代码贡献

- ✅ 修复 Bug
- ✅ 添加新检测规则
- ✅ 优化性能
- ✅ 改进错误处理

### 文档贡献

- ✅ 修正拼写错误
- ✅ 改进说明文档
- ✅ 添加使用示例
- ✅ 翻译文档

### 威胁情报贡献

- ✅ 报告新的恶意技能
- ✅ 添加恶意域名/IP
- ✅ 更新攻击模式

---

## 🔧 添加检测规则

### 1. 编辑规则文件

`rules/static_rules.yaml`:

```yaml
- id: CRED_006
  category: credential_leak
  severity: HIGH
  pattern: "api_key\\s*=\\s*['\"][a-zA-Z0-9]+"
  description: "检测到 API Key"
  remediation: "使用环境变量存储 API Key"
  cwe_id: "CWE-798"
```

### 2. 测试规则

```bash
python3 scanner.py -t ./test-skill/ --verbose
```

### 3. 提交 PR

```bash
git add rules/static_rules.yaml
git commit -m "feat: add API Key detection rule (CRED_006)"
git push origin feature/your-feature-name
```

---

## 🧪 测试要求

### 单元测试

```bash
# 运行所有测试
./scripts/run_all_tests.sh

# 运行特定测试
python3 -m pytest tests/test_static_analyzer.py
```

### 测试覆盖

- ✅ 白样本测试（确保不误报）
- ✅ 黑样本测试（确保不漏报）
- ✅ 边界测试（极端情况）

---

## 📋 PR 指南

### PR 标题格式

```
<type>: <description>

示例：
feat: add new credential leak detection
fix: resolve false positive in AWS key detection
docs: update installation guide
test: add test cases for semantic audit
```

### PR 描述模板

```markdown
## 变更说明
- 描述你的变更内容

## 测试
- [ ] 已添加测试用例
- [ ] 所有测试通过
- [ ] 测试覆盖率 > 90%

## 相关 Issue
Fixes #123
```

---

## 🐛 报告 Bug

### Bug 报告模板

```markdown
**描述问题**
清晰简洁的问题描述

**复现步骤**
1. 执行 '...'
2. 出现 '...'

**预期行为**
应该发生什么

**截图**
如适用，添加截图

**环境信息**
- Python 版本：3.10
- 操作系统：macOS 14.0
- 扫描器版本：v2.0.0
```

---

## 💡 功能建议

### 功能请求模板

```markdown
**功能描述**
清晰简洁的功能描述

**使用场景**
这个功能能解决什么问题

**实现建议**
如何实现这个功能（可选）
```

---

## 📖 代码风格

### Python 代码

- 遵循 PEP 8
- 使用 4 空格缩进
- 函数添加文档字符串
- 类型注解（Python 3.10+）

### 提交信息

- 使用现在时（"add feature" 而非 "added feature"）
- 首字母大写
- 不超过 72 字符

---

## 🔒 安全政策

### 报告安全漏洞

发现安全漏洞时，请：

1. **不要** 公开报告
2. 发送邮件到 security@example.com
3. 包含详细复现步骤
4. 等待 48 小时获取回复

### 负责任的披露

- 我们会在第 1 个工作日内确认
- 7 天内提供修复计划
- 修复后公开致谢

---

## 📜 行为准则

### 我们的承诺

- 开放友好的交流环境
- 尊重不同观点和经验
- 优雅地接受建设性批评
- 关注对社区最有利的事情

### 不可接受的行为

- 使用性别化的语言或图像
- 人身攻击或侮辱性评论
- 公开或私下骚扰
- 未经许可发布他人隐私信息

---

## 📞 联系方式

- **GitHub Issues:** 功能请求和 Bug 报告
- **Discord:** 日常讨论和交流
- **Email:** security@example.com（安全问题）

---

## 🙏 致谢

感谢所有为这个项目做出贡献的人！

---
*最后更新：2026-03-20*
