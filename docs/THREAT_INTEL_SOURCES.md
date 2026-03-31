# 威胁情报来源

## 数据来源

本扫描器整合多个权威安全来源的威胁情报：

| 来源 | 类型 | 更新频率 | 贡献者 |
|------|------|---------|--------|
| **MaliciousAgentSkillsBench** | 恶意技能基准 | 每周 | 学术界 |
| **ClawHavoc (Koi Security)** | 威胁情报源 | 每日 | Koi Security |
| **ToxicSkills (Snyk)** | 漏洞技能库 | 每日 | Snyk |
| **Poseidon** | 攻击活动追踪 | 每周 | 安全社区 |
| **SlowMist (慢雾)** | 区块链安全 | 每周 | 慢雾科技 |
| **Tencent Keen Lab (腾讯科恩)** | APT 情报 | 每周 | 腾讯安全 |
| **GitHub Security Advisories** | 安全公告 | 每日 | GitHub |
| **NPM Audit** | 包安全 | 每日 | npm |
| **PyPI Safety** | Python 包安全 | 每日 | SafetyDB |

---

## 统计信息

截至 **2026-03-20**：

| 类别 | 数量 |
|------|------|
| 恶意技能名称 | 573 |
| 恶意域名 | 17 |
| 恶意 IP | 5 |
| TTP 攻击模式 | 40 |
| 攻击活动 | 20 |
| 静态检测规则 | 194+ |

---

## 手工维护

威胁情报库采用**手工维护**模式，定期手动更新 `data/threat_intel.json`。

### 查看当前版本

```bash
python3 -c "from core.threat_intel import ThreatIntelligence; intel = ThreatIntelligence(); print('版本:', intel.get_version()); print('更新:', intel.get_updated())"
```

### 手工更新步骤

1. 收集新的威胁情报（恶意技能名称、域名、IP 等）
2. 编辑 `data/threat_intel.json`
3. 更新 `version` 和 `updated` 字段
4. 提交到版本控制

### 情报格式

```json
{
  "version": "7.0.0",
  "updated": "2026-03-20",
  "malicious_skill_names": ["new-malicious-skill", "..."],
  "malicious_domains": ["evil.com", "..."],
  "malicious_ips": ["91.92.242.30", "..."]
}
```

---

## 情报格式

威胁情报库使用统一 JSON 格式：

```json
{
  "version": "7.0.0",
  "updated": "2026-03-20",
  "statistics": {
    "total_malicious": 1500,
    "unique_campaigns": 20
  },
  "malicious_patterns": [
    {
      "id": "TTP_001",
      "name": "Reverse Shell TCP",
      "pattern": "/dev/tcp/...",
      "severity": "CRITICAL"
    }
  ],
  "malicious_skill_names": ["project-init", "..."],
  "malicious_domains": ["evil.com", "..."],
  "malicious_ips": ["91.92.242.30", "..."]
}
```

---

## 贡献情报

发现新的恶意技能或攻击模式？请提交到：

- GitHub Issues: https://github.com/openclaw/skills/issues
- 邮件：security@x-skill-scanner.com

### 提交格式

```json
{
  "type": "malicious_skill",
  "name": "evil-skill",
  "source": "ClawHub",
  "description": "窃取凭证的恶意技能",
  "evidence": ["代码片段", "行为分析"],
  "severity": "CRITICAL"
}
```

---

## 误报反馈

如遇到误报，请提交反馈：

```bash
python3 ./scripts/report_false_positive.py --skill <skill-name> --reason <原因>
```

---

## 参考链接

- [MaliciousAgentSkillsBench](https://github.com/agent-security/malicious-skills-bench)
- [ClawHavoc Report](https://www.koi-security.com/clawhavoc)
- [ToxicSkills (Snyk)](https://snyk.io/toxic-skills)
- [SlowMist](https://slowmist.io)
- [Tencent Keen Lab](https://keenlab.tencent.com)
