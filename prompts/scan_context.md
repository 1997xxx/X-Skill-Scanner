# 扫描上下文模板

## 技能基本信息

```yaml
skill:
  name: "{skill_name}"
  author: "{skill_author}"
  source: "{skill_source}"
  type: "{skill_type}"
  description: "{skill_description}"
  version: "{skill_version}"
  license: "{skill_license}"

location:
  path: "{skill_path}"
  is_local: {is_local}
  is_url: {is_url}
  is_market: {is_market}

metadata:
  file_count: {file_count}
  total_lines: {total_lines}
  primary_language: "{primary_language}"
  has_tests: {has_tests}
  has_documentation: {has_documentation}
```

## 扫描配置

```yaml
scan:
  version: "7.1.0"
  mode: "{scan_mode}"  # quick | standard | full
  timestamp: "{scan_timestamp}"

engines:
  threat_intel: {enabled_threat_intel}
  deobfuscation: {enabled_deobfuscation}
  static_analysis: {enabled_static_analysis}
  ast_analysis: {enabled_ast_analysis}
  dependency_check: {enabled_dependency_check}
  prompt_injection: {enabled_prompt_injection}
  baseline_tracking: {enabled_baseline}
  semantic_audit: {enabled_semantic}
  entropy_analysis: {enabled_entropy}
  install_hook: {enabled_install_hook}
  network_profiling: {enabled_network}
  credential_theft: {enabled_credential}

platform:
  detected: "{detected_platform}"
  llm_provider: "{llm_provider}"
  llm_model: "{llm_model}"
  connection_status: "{connection_status}"
```

## 技能画像

```yaml
profile:
  trust_score: {trust_score}
  scan_strategy: "{scan_strategy}"  # quick | standard | full
  risk_fingerprint:
    red_flags: [{red_flags}]
    suspicious_patterns: [{suspicious_patterns}]
    indicators: [{indicators}]
```

## 扫描结果摘要

```yaml
results:
  risk_level: "{risk_level}"
  risk_score: {risk_score}
  verdict: "{verdict}"

  statistics:
    total_files: {total_files}
    findings_count: {findings_count}
    critical: {critical_count}
    high: {high_count}
    medium: {medium_count}
    low: {low_count}

  by_category:
    threat_intel: {threat_intel_count}
    deobfuscation: {deobfuscation_count}
    static: {static_count}
    ast: {ast_count}
    dependency: {dependency_count}
    prompt_injection: {prompt_injection_count}
    baseline: {baseline_count}
    semantic: {semantic_count}
    entropy: {entropy_count}
    install_hook: {install_hook_count}
    network: {network_count}
    credential: {credential_count}

  correlation:
    chains_detected: {chains_detected}
    correlation_score: {correlation_score}
```

## 发现的问题列表

```yaml
findings:
  - id: 1
    rule_id: "{rule_id}"
    severity: "{severity}"  # CRITICAL | HIGH | MEDIUM | LOW
    category: "{category}"
    title: "{title}"
    description: "{description}"
    file_path: "{file_path}"
    line_number: {line_number}
    remediation: "{remediation}"
    source: "{source}"
    code_evidence: "{code_evidence}"
```

## 二次语义审计上下文

```yaml
semantic_review:
  enabled: true
  threshold: "{threshold}"  # ALL | MEDIUM | HIGH | NEVER
  results:
    total_reviewed: {total_reviewed}
    false_positives: {fp_count}
    true_positives: {tp_count}
    human_review_needed: {hr_count}
```

## 环境信息

```yaml
environment:
  os: "{os_type}"
  python_version: "{python_version}"
  scanner_location: "{scanner_location}"

  openclaw:
    version: "{openclaw_version}"
    config_path: "{config_path}"
    skills_dir: "{skills_dir}"

  llm:
    provider: "{llm_provider}"
    model: "{llm_model}"
    base_url: "{base_url}"
    has_api_key: {has_api_key}
```