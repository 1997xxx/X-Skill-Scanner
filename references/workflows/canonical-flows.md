# 标准工作流 / Canonical Workflows

x-skill-scanner 提供四个标准工作流，覆盖技能安全的全生命周期。

---

## 1️⃣ 本地扫描 / Local Scan

**触发词：** `scan skill`, `扫描技能`, `检查技能安全`

**适用场景：**
- 已克隆到本地的技能目录
- 开发中的技能自检
- 定期安全审计

**命令：**
```bash
python3 lib/scanner.py -t <TARGET_PATH>
```

**流程：**
```
1. 前置合法性检查 (Pre-flight Check)
2. 白名单检查 (Whitelist)
3. 技能画像 (Skill Profiler) → 信任分数 → 扫描策略
4. 威胁情报匹配 (Threat Intel)
5. 社会工程学检测 (Social Engineering)
6. 去混淆 (Deobfuscation)
7. 静态分析 (Static Analysis)
8. AST 深度分析
9. 依赖检查
10. 提示词注入探针
11. 基线比对
12. 语义审计 (可选)
13. 熵值分析
14. 安装钩子检测
15. 网络画像
16. 凭证窃取检测
17. 跨层关联分析
18. 误报预过滤
19. SubAgent 智能审查
20. 风险评分与裁决
```

**输出：** 风险等级 + 详细报告

---

## 2️⃣ 远程扫描 / Remote Scan

**触发词：** `scan from url`, `扫描远程技能`, `check skill from link`

**适用场景：**
- GitHub/GitLab 仓库 URL
- 未下载的远程技能
- 第三方技能评估

**流程：**
```
1. 克隆到临时目录
   git clone <URL> /tmp/skill-scan-<random>/
2. 执行本地扫描流程
3. 清理临时目录
   rm -rf /tmp/skill-scan-<random>/
```

**命令：**
```bash
python3 lib/scanner.py --url <GITHUB_URL>
```

**安全边界：**
- 不执行远程代码
- 仅静态分析
- 扫描后自动清理

---

## 3️⃣ 安装检查 / Installation Check

**触发词：** `install skill`, `安装技能`, `clawhub install`

**适用场景：**
- 用户请求安装新技能
- 自动触发（任何技能安装前）

**流程：**
```
1. 拦截安装请求
2. 执行扫描（本地或远程）
3. 呈现扫描结果
4. 根据风险等级决策：
   - LOW → 允许安装
   - MEDIUM → 警告 + 用户确认
   - HIGH/EXTREME → 阻止 + 建议
5. 安装后注入 AGENTS.md (Flow 1)
```

**安全红线：**
- **禁止跳过扫描** — 即使"这个技能我写的，信我"
- **禁止肉眼判断** — 必须运行扫描器
- **禁止分步绕过** — 检测到目标为 skills 目录即触发扫描
- **禁止静默安装** — 变更检测兜底

---

## 4️⃣ 深度审查 / Deep Review

**触发词：** `deep scan`, `深度审查`, `full audit`

**适用场景：**
- 高风险技能人工审计
- 疑似恶意技能分析
- 安全事件响应

**启用模式：**
```bash
python3 lib/scanner.py -t <TARGET> --no-fp-filter --force-llm-review
```

**特性：**
- 跳过误报预过滤（保留所有发现）
- 强制 SubAgent 审查（即使高风险）
- 生成详细 SARIF 报告
- 跨层关联分析权重 +100%

**输出：**
- 完整发现列表（包括 INFO 级）
- 攻击链图谱
- 修复建议优先级
- GitHub Security Tab 集成 (SARIF)

---

## 工作流选择决策树

```
用户请求
  │
  ├─ "安装技能" → 流程 3 (安装检查)
  │   └─ 本地？ → 流程 1 (本地扫描)
  │   └─ 远程？ → 流程 2 (远程扫描)
  │
  ├─ "扫描技能" → 流程 1 (本地扫描)
  │
  ├─ "深度审查" → 流程 4 (深度审查)
  │
  └─ 自动触发 → 流程 3 (安装检查)
```

---

*本文档为 x-skill-scanner 技术参考，详细 CLI 参数参见 SKILL.md*