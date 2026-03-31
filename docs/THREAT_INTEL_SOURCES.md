# Threat Intelligence Sources / 威胁情报来源

## Data Sources / 数据来源

This scanner integrates threat intelligence from multiple authoritative security sources:

本扫描器整合多个权威安全来源的威胁情报：

| Source | Type | Update Frequency | Contributor |
|--------|------|-----------------|-------------|
| **MaliciousAgentSkillsBench** | Malicious skill benchmark | Weekly | Academic research |
| **ClawHavoc (Koi Security)** | Threat intelligence feed | Daily | Koi Security |
| **ToxicSkills (Snyk)** | Vulnerable skill database | Daily | Snyk |
| **Poseidon** | Attack campaign tracking | Weekly | Security community |
| **SlowMist (慢雾)** | Blockchain security | Weekly | SlowMist Technology |
| **Tencent Keen Lab (腾讯科恩)** | APT intelligence | Weekly | Tencent Security |
| **GitHub Security Advisories** | Security advisories | Daily | GitHub |
| **NPM Audit** | Package security | Daily | npm |
| **PyPI Safety** | Python package security | Daily | SafetyDB |

---

## Statistics / 统计信息

As of **2026-03-31**:

截至 **2026-03-31**：

| Category | Count |
|----------|-------|
| Malicious skill names | 380+ |
| Malicious domains | 17+ |
| Malicious IPs | 5+ |
| TTP attack patterns | 43+ |
| Attack campaigns | 20+ |
| Static detection rules | 194+ |

---

## Maintenance Mode / 维护模式

The threat intelligence database uses **manual maintenance** mode with periodic updates to `data/threat_intel.json`.

威胁情报库采用**手工维护**模式，定期更新 `data/threat_intel.json`。

### Check Current Version / 查看当前版本

```bash
python3 -c "from lib.threat_intel import ThreatIntelligence; ti = ThreatIntelligence(); print(ti.get_statistics())"
```

### Manual Update Steps / 手工更新步骤

1. Collect new threat intelligence (malicious skill names, domains, IPs)
   收集新的威胁情报（恶意技能名称、域名、IP 等）
2. Edit `data/threat_intel.json`
3. Update the `version` and `updated` fields
4. Commit to version control

### Intelligence Format / 情报格式

```json
{
  "version": "3.6.0",
  "updated": "2026-03-31",
  "malicious_skill_names": ["new-malicious-skill"],
  "malicious_domains": ["evil.com"],
  "malicious_ips": ["91.92.242.30"]
}
```

---

## Contributing Intelligence / 贡献情报

Discovered a new malicious skill or attack pattern? Please submit via:

发现新的恶意技能或攻击模式？请通过以下方式提交：

- GitHub Issues: https://github.com/1997xxx/X-Skill-Scanner/issues
- Email: Use GitHub Security Advisories for sensitive reports

### Submission Format / 提交格式

```json
{
  "type": "malicious_skill",
  "name": "evil-skill",
  "source": "ClawHub",
  "description": "Credential theft via webhook exfiltration",
  "evidence": ["code snippet", "behavior analysis"],
  "severity": "CRITICAL"
}
```

---

## False Positive Feedback / 误报反馈

If you encounter false positives, please submit feedback:

如遇到误报，请提交反馈：

```bash
./scan -t ./my-skill/ --verbose
```

Include the scan output and explain why the finding is incorrect in your issue report.

在 Issue 报告中附上扫描输出并说明为什么该发现是误报。

---

## References / 参考链接

- [MaliciousAgentSkillsBench](https://github.com/agent-security/malicious-skills-bench)
- [ClawHavoc Report](https://www.koi-security.com/clawhavoc)
- [ToxicSkills (Snyk)](https://snyk.io/toxic-skills)
- [SlowMist](https://slowmist.io)
- [Tencent Keen Lab](https://keenlab.tencent.com)

---

*Last updated: 2026-03-31*
