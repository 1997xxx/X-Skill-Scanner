# Contributing Guide / 贡献指南

Thank you for your interest in X Skill Scanner!

感谢你对 X Skill Scanner 的兴趣！

## Quick Start / 快速开始

```bash
git clone https://github.com/1997xxx/X-Skill-Scanner.git
cd X-Skill-Scanner
pip install -r requirements.txt
```

## Contribution Types / 贡献类型

- Bug fixes / 修复 Bug
- New detection rules / 添加新检测规则
- Performance improvements / 优化性能
- Documentation improvements / 改进文档
- Report malicious samples / 报告恶意样本

## Adding Detection Rules / 添加检测规则

Edit `rules/static_rules.yaml` to add new rules, then submit a PR.

编辑 `rules/static_rules.yaml` 添加新规则后提交 PR。

## Testing / 测试

```bash
python3 -m pytest tests/ -v
```

## PR Guidelines / PR 指南

- Use clear commit messages / 使用清晰的提交信息
- Add test cases for new features / 为新功能添加测试用例
- Update relevant documentation / 更新相关文档

---

*X Skill Scanner Team*
