# 贡献指南

感谢你对 X Skill Scanner 的兴趣！

## 🚀 快速开始

```bash
git clone https://github.com/your-username/x-skill-scanner.git
cd x-skill-scanner
pip3 install -r requirements.txt
```

## 📝 贡献类型

- ✅ 修复 Bug
- ✅ 添加新检测规则
- ✅ 优化性能
- ✅ 改进文档
- ✅ 报告恶意样本

## 🔧 添加检测规则

编辑 `rules/static_rules.yaml`，添加新规则后提交 PR。

## 🧪 测试

```bash
python3 scanner.py -t ./test-skill/ --verbose
```

## 📋 PR 指南

- 使用清晰的提交信息
- 添加测试用例
- 更新相关文档

详细文档：[docs/USAGE.md](docs/USAGE.md)

---
*X Skill Scanner Team*
