# X Skill Scanner v5.0 重构任务

## 目标
将扫描器从 v4.1 升级到 v5.0：画像驱动自适应扫描 + LLM 批量审查 + 跨层关联分析 + 风险评分升级

## CRITICAL RULES
1. After editing EACH file, verify syntax: `python3 -c "import py_compile; py_compile.compile('path/to/file', doraise=True)"`
2. Do NOT break any existing functionality
3. Work through phases sequentially
4. The static_analysis block indentation in scanner.py is the trickiest part — be very careful

---

## Phase 1: lib/scanner.py — 画像驱动自适应扫描

### 1.1 添加两个新方法

在 `_extract_skill_metadata` 方法之后（`_detect_campaign_patterns` 之前），添加这两个方法到 `SkillScanner` 类中：

```python
    def _should_run_engine(self, engine_name: str) -> bool:
        """根据画像策略决定是否运行某引擎"""
        if not self._skill_profile:
            return True
        strategy = self._skill_profile.scan_strategy
        if strategy == "quick":
            return engine_name in {"threat_intel", "static_analysis", "credential_theft"}
        return True

    def _get_llm_review_threshold(self) -> str:
        """根据画像策略决定 LLM 审查阈值"""
        if not self._skill_profile:
            return "MEDIUM"
        strategy = self._skill_profile.scan_strategy
        if strategy == "quick":
            return "NEVER"
        elif strategy == "standard":
            return "MEDIUM"
        else:
            return "ALL"
```

### 1.2 在每个引擎调用前加上 _should_run_engine() 检查

修改 scan() 方法中的每个引擎块。以下是具体的替换规则：

**威胁情报:**
找 `if self.threat_intel:` → 改为 `if self.threat_intel and self._should_run_engine("threat_intel"):`

**去混淆:**
找 `if self.deobfuscator and not target.is_file():` → 改为 `if self.deobfuscator and not target.is_file() and self._should_run_engine("deobfuscation"):`

**静态分析（最复杂，注意缩进）:**
找到以下代码块：
```python
        # 3. 静态分析
        _p("\n📊 步骤 3/7: 静态分析...")
        if target.is_file():
            static_findings = self.static_analyzer.analyze_file(target)
        else:
            static_findings = self.static_analyzer.analyze_directory(target, recursive=True, path_filter=self.path_filter)

        for f in static_findings:
            # 构建增强描述：包含匹配的代码片段
            desc = f.description
            evidence = getattr(f, 'evidence', '') or getattr(f, 'matched_text', '')
            if evidence and evidence not in desc:
                desc += f"\n\n📋 匹配代码:\n```\n{evidence[:300]}\n```"
            
            all_findings.append({
                'rule_id': getattr(f, 'rule_id', '') or f.category,
                'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                'category': getattr(f, 'category', 'static'),
                'title': f.title,
                'description': desc,
                'file_path': f.file_path,
                'line_number': getattr(f, 'line_number', 0),
                'remediation': f.remediation,
                'source': 'static_analysis',
                'code_evidence': evidence[:500] if evidence else '',
            })
        _p(f"   发现 {len(static_findings)} 个静态分析问题")
```

替换为：
```python
        # 3. 静态分析
        if self._should_run_engine("static_analysis"):
            _p("\n📊 步骤 3/7: 静态分析...")
            if target.is_file():
                static_findings = self.static_analyzer.analyze_file(target)
            else:
                static_findings = self.static_analyzer.analyze_directory(target, recursive=True, path_filter=self.path_filter)

            for f in static_findings:
                desc = f.description
                evidence = getattr(f, 'evidence', '') or getattr(f, 'matched_text', '')
                if evidence and evidence not in desc:
                    desc += f"\n\n📋 匹配代码:\n```\n{evidence[:300]}\n```"
                
                all_findings.append({
                    'rule_id': getattr(f, 'rule_id', '') or f.category,
                    'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    'category': getattr(f, 'category', 'static'),
                    'title': f.title,
                    'description': desc,
                    'file_path': f.file_path,
                    'line_number': getattr(f, 'line_number', 0),
                    'remediation': f.remediation,
                    'source': 'static_analysis',
                    'code_evidence': evidence[:500] if evidence else '',
                })
            _p(f"   发现 {len(static_findings)} 个静态分析问题")
        else:
            static_findings = []
            _p("\n⏭️  跳过静态分析（快速模式）")
```

**AST 分析:**
找 `if self.ast_analyzer and not target.is_file():` → 改为 `if self.ast_analyzer and not target.is_file() and self._should_run_engine("ast_analysis"):`

**依赖检查:**
找 `if self.dep_checker and not target.is_file():` → 改为 `if self.dep_checker and not target.is_file() and self._should_run_engine("dependency_check"):`

**提示词注入:**
找 `if self.prompt_injection_tester and not target.is_file():` → 改为 `if self.prompt_injection_tester and not target.is_file() and self._should_run_engine("prompt_injection"):`

**基线比对:**
找 `if self.baseline_tracker and not target.is_file():` → 改为 `if self.baseline_tracker and not target.is_file() and self._should_run_engine("baseline_change"):`

**语义审计:**
找 `if self.enable_semantic:` → 改为 `if self.enable_semantic and self._should_run_engine("semantic_audit"):`

**熵值分析:**
找 `if self.entropy_analyzer and not target.is_file():` → 改为 `if self.entropy_analyzer and not target.is_file() and self._should_run_engine("entropy_analysis"):`

**安装钩子:**
找 `if self.hook_detector and not target.is_file():` → 改为 `if self.hook_detector and not target.is_file() and self._should_run_engine("install_hook"):`

**网络画像:**
找 `if self.network_profiler and not target.is_file():` → 改为 `if self.network_profiler and not target.is_file() and self._should_run_engine("network_behavior"):`

**凭证窃取:**
找 `if self.credential_theft_detector and not target.is_file():` → 改为 `if self.credential_theft_detector and not target.is_file() and self._should_run_engine("credential_theft"):`

### 1.3 确保 static_findings 有默认值

在 scan() 方法中 `all_findings: List[Dict] = []` 这一行之后，添加：
```python
        static_findings = []  # default, may be set by engine
```

### 1.4 替换 LLM 审查部分

找到这段代码（在 FP filter 之后）：
```python
            # 步骤 2: LLM 二次审查（仅对不确定的发现）
            if self.enable_llm_review and self.llm_reviewer and all_findings:
                _p("\n🤖 v4.1 LLM 二次审查...")
                try:
                    filtered_findings, reviews = self.llm_reviewer.filter_findings(
                        all_findings, str(target)
                    )
                    llm_review_summary = self.llm_reviewer.get_review_summary(reviews)
                    
                    llm_fp = llm_review_summary['by_verdict'].get('FP', 0)
                    llm_tp = llm_review_summary['by_verdict'].get('TP', 0)
                    llm_hr = llm_review_summary['by_verdict'].get('HUMAN_REVIEW', 0)
                    
                    _p(f"   LLM审查: {len(all_findings)} 条 → "
                       f"{llm_fp} 误报 | {llm_tp} 真实威胁 | {llm_hr} 需人工审查")
                    
                    all_findings = filtered_findings
                except Exception as e:
                    _p(f"   ⚠️  LLM 审查失败: {e}，使用预过滤结果")
```

替换为：
```python
            # 步骤 2: LLM 批量审查（v5.0 — 按文件分组，减少 API 调用）
            llm_threshold = self._get_llm_review_threshold()
            if self.enable_llm_review and self.llm_reviewer and all_findings and llm_threshold != "NEVER":
                _p("\n🤖 v5.0 LLM 批量审查...")
                try:
                    filtered_findings, reviews = self.llm_reviewer.filter_findings_batch(
                        all_findings, str(target), threshold=llm_threshold
                    )
                    llm_review_summary = self.llm_reviewer.get_review_summary(reviews)
                    
                    llm_fp = llm_review_summary["by_verdict"].get("FP", 0)
                    llm_tp = llm_review_summary["by_verdict"].get("TP", 0)
                    llm_hr = llm_review_summary["by_verdict"].get("HUMAN_REVIEW", 0)
                    
                    _p(f"   LLM批量审查: {len(all_findings)} 条 → "
                       f"{llm_fp} 误报 | {llm_tp} 真实威胁 | {llm_hr} 需人工审查")
                    
                    all_findings = filtered_findings
                except Exception as e:
                    _p(f"   ⚠️  LLM 批量审查失败: {e}，使用预过滤结果")
```

### 1.5 添加跨层关联分析

在凭证窃取检测块之后、FP filter 之前（即 `# ─── v4.1: 误报预过滤 + LLM 二次审查` 注释之前），插入：

```python
        # ─── v5.0: 跨层关联分析 ──────────────────────────────
        correlation_result = None
        if all_findings:
            try:
                from correlation_engine import CorrelationEngine
                corr_engine = CorrelationEngine()
                correlation_result = corr_engine.analyze(all_findings)
                
                for cf in correlation_result.correlation_findings:
                    all_findings.append({
                        "rule_id": cf.rule_id,
                        "severity": cf.severity,
                        "category": f"correlation_{cf.chain_name}",
                        "title": cf.title,
                        "description": cf.description,
                        "file_path": str(target),
                        "remediation": "审查完整的攻击链模式",
                        "source": "correlation_engine",
                        "metadata": {
                            "chain_name": cf.chain_name,
                            "related_count": len(cf.related_findings),
                        },
                    })
                
                if correlation_result.attack_chains:
                    chain_names = [c.name for c in correlation_result.attack_chains]
                    _p(f"\n🔗 v5.0 关联分析: 检测到 {len(correlation_result.attack_chains)} 条攻击链: {', '.join(chain_names)}")
                else:
                    _p(f"\n🔗 v5.0 关联分析: 未检测到完整攻击链 (关联加成: +{correlation_result.correlation_score})")
            except ImportError:
                _p("\n⚠️  关联分析模块不可用，跳过")
            except Exception as e:
                _p(f"\n⚠️  关联分析失败: {e}")
```

### 1.6 更新 result dict

在 result = {...} 字典中，找到 `'skill_profile': asdict(self._skill_profile) if self._skill_profile else None,` 这一行，在它之后添加：

```python
            "correlation": {
                "chains_detected": len(correlation_result.attack_chains) if correlation_result else 0,
                "correlation_score": correlation_result.correlation_score if correlation_result else 0,
                "chain_names": [c.name for c in correlation_result.attack_chains] if correlation_result else [],
            } if correlation_result else None,
```

### 1.7 更新版本号

- 文件顶部 docstring: `X Skill Scanner v4.1.0` → `X Skill Scanner v5.0.0`
- 版本历史注释: 在 `- v4.1:` 行之后添加一行: `- v5.0: 画像驱动自适应扫描 + LLM 批量审查 + 跨层关联分析 + 风险评分升级`
- `'scanner_version': '4.1.0'` → `'scanner_version': '5.0.0'`

验证: `python3 -c "import py_compile; py_compile.compile('lib/scanner.py', doraise=True)"`

---

## Phase 2: lib/llm_reviewer.py — 批量审查引擎

### 2.1 添加 import

在文件顶部已有的 import 中添加：
```python
from collections import defaultdict
```

### 2.2 添加新方法

在 `LLMReviewer` 类中，在现有的 `review_findings` 方法之前，添加以下四个方法：

**方法 1: review_findings_batch**
```python
    def review_findings_batch(self, findings: List[Dict], target_path: str,
                               threshold: str = "MEDIUM") -> List[ReviewResult]:
        """
        批量审查 — 按文件分组，减少 LLM 调用次数
        
        Args:
            findings: 发现列表
            target_path: 扫描目标路径
            threshold: 审查阈值 ("ALL" | "MEDIUM" | "HIGH")
        """
        if not findings:
            return []
        
        target = Path(target_path)
        skill_info = self._extract_skill_info(target)
        file_tree = self._build_file_tree(target)
        
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        threshold_min = {"ALL": 0, "MEDIUM": 2, "HIGH": 3}.get(threshold, 2)
        
        eligible = [f for f in findings
                    if severity_order.get(f.get("severity", "LOW"), 0) >= threshold_min]
        
        groups = defaultdict(list)
        for finding in eligible:
            key = finding.get("file_path", "unknown")
            groups[key].append(finding)
        
        results = []
        for file_path, group_findings in groups.items():
            group_results = self._review_group(group_findings, skill_info, file_tree, target)
            results.extend(group_results)
        
        skipped = [f for f in findings
                   if severity_order.get(f.get("severity", "LOW"), 0) < threshold_min]
        for f in skipped:
            results.append(ReviewResult(
                original_finding=f,
                verdict="UNCERTAIN",
                confidence=0.3,
                reasoning=f"低于审查阈值 ({threshold})，跳过 LLM 审查",
                true_severity=None,
                summary="低风险发现，建议人工确认",
            ))
        
        return results
```

**方法 2: _review_group**
```python
    def _review_group(self, findings: List[Dict], skill_info: Dict,
                      file_tree: str, target: Path) -> List[ReviewResult]:
        """对同一文件的多个发现进行一次性 LLM 审查"""
        if len(findings) == 1:
            return [self._review_single(findings[0], skill_info, file_tree, target)]
        
        file_path = findings[0].get("file_path", "")
        line_num = findings[0].get("line_number", 0)
        code_context = self._get_code_context(file_path, line_num, context_lines=20)
        
        findings_list = "\n\n".join([
            f"### 发现 #{i+1}\n"
            f"- 规则 ID: {f.get('rule_id', 'N/A')}\n"
            f"- 标题: {f.get('title', '')}\n"
            f"- 原始严重度: {f.get('severity', 'MEDIUM')}\n"
            f"- 来源引擎: {f.get('source', 'unknown')}\n"
            f"- 描述: {f.get('description', '')[:300]}"
            for i, f in enumerate(findings)
        ])
        
        user_prompt = (
            f"## 技能基本信息\n"
            f"- 名称: {skill_info.get('name', 'unknown')}\n"
            f"- 作者: {skill_info.get('author', 'unknown')}\n"
            f"- 类型: {skill_info.get('type', 'unknown')}\n"
            f"- 文件数: {skill_info.get('file_count', 0)}\n\n"
            f"## 待审查文件\n{file_path}\n\n"
            f"## 文件代码上下文\n```\n{code_context}\n```\n\n"
            f"## 该文件的所有发现 ({len(findings)} 条)\n\n"
            f