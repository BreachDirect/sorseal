//! Static vulnerability analysis for Soroban contract source.
//!
//! `sorseal analyze` inspects the Rust source of a sealed artifact for
//! known-fragile Soroban patterns. It is deliberately lexical and
//! pattern-based (like `bandit` or `ruff`): it flags *suspicious* constructs
//! for a human reviewer, it does not attempt full semantic analysis of the
//! compiled WASM. No unsafe code, no external `syn`/`tree-sitter` dependency —
//! it only tokenizes the source by line and applies rule matchers.
//!
//! Every finding is assigned a stable rule id and a severity so reports can be
//! triaged, and the overall finding digest can be sealed into the provenance
//! record (see `Provenance.analysis`).

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

/// Stable identifiers for the analysis rules this crate knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleId {
    MissingAuth,
    Reentrancy,
    UncheckedArithmetic,
    PanicOnInput,
    UncheckedTransfer,
    MissingReentrancyGuard,
}

impl RuleId {
    /// Stable, human-readable id used in reports and SARIF.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleId::MissingAuth => "SORSEAL-101",
            RuleId::Reentrancy => "SORSEAL-102",
            RuleId::UncheckedArithmetic => "SORSEAL-103",
            RuleId::PanicOnInput => "SORSEAL-104",
            RuleId::UncheckedTransfer => "SORSEAL-105",
            RuleId::MissingReentrancyGuard => "SORSEAL-106",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            RuleId::MissingAuth => "missing-authorization",
            RuleId::Reentrancy => "reentrancy",
            RuleId::UncheckedArithmetic => "unchecked-arithmetic",
            RuleId::PanicOnInput => "panic-on-user-input",
            RuleId::UncheckedTransfer => "unchecked-transfer",
            RuleId::MissingReentrancyGuard => "missing-reentrancy-guard",
        }
    }
}

/// Severity ordering mirrors commonly that used by OWASP-style risk grading.
/// Declared least-to-most severe so the derived `Ord` (which follows variant
/// order) makes `Critical` greater than `High`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }

    /// SARIF `level` (code scanning only understands error/warning/note).
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        }
    }
}

/// A single static-analysis finding, tied to a source location.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: RuleId,
    pub severity: Severity,
    pub message: String,
    pub file: String,
    pub line: u32,
    pub remediation: &'static str,
}

/// The result of analyzing one artifact: whether analysis completed and the
/// findings that were produced.
#[derive(Debug, Clone, Default)]
pub struct Analysis {
    /// True when the source tree was walked without error.
    pub ok: bool,
    /// All findings, files in traversal order then line order.
    pub findings: Vec<Finding>,
}

impl Analysis {
    /// SHA-256 of a stable serialization of every finding. Sealing this into
    /// the provenance record makes an audit tamper-evident: any edit to a
    /// finding (or to a source file that reorders/changes findings) changes
    /// the digest.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        for f in &self.findings {
            h.update(f.rule.as_str().as_bytes());
            h.update([0]);
            h.update(f.severity.as_str().as_bytes());
            h.update([0]);
            h.update(f.file.as_bytes());
            h.update([0]);
            h.update(f.line.to_string().as_bytes());
            h.update([0]);
            h.update(f.message.as_bytes());
            h.update([0]);
        }
        hexify(&h.finalize())
    }

    /// Highest severity present, or `None` when there are no findings.
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max_by_key(|s| *s)
    }

    /// Number of findings at exactly the given severity (per-severity total).
    pub fn count_by_severity(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}

// ---------------------------------------------------------------------------
// Lexical helpers
// ---------------------------------------------------------------------------

/// Encode bytes as lowercase hex.
fn hexify(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Strip `//` and `/* */` comments and string/char literals from a line, so
/// rule matches do not fire on commented-out or illustrative code. This is a
/// best-effort lexical strip: it does not handle lifetime lifetimes / nested
/// string escapes perfectly, but is sufficient for flagging intent.
fn strip_comments_and_strings(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut in_char = false;
    while let Some(c) = chars.next() {
        if in_line_comment {
            continue;
        }
        if in_block_comment {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }
        if in_string {
            if c == '\\' {
                chars.next();
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            out.push(' ');
            continue;
        }
        if in_char {
            if c == '\\' {
                chars.next();
                continue;
            }
            if c == '\'' {
                in_char = false;
            }
            out.push(' ');
            continue;
        }
        match c {
            '/' if chars.peek() == Some(&'/') => {
                in_line_comment = true;
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                in_block_comment = true;
            }
            '"' => {
                in_string = true;
                out.push(' ');
            }
            '\'' => {
                in_char = true;
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Analysis entry point
// ---------------------------------------------------------------------------

/// Walk `source_root` and analyze every Rust source file it contains.
///
/// `ignore` is an optional set of path suffixes (e.g. `target/`) to skip so
/// analysis only judges the project source, never generated build output.
pub fn analyze_tree(source_root: &Path, ignore: &[&str]) -> Result<Analysis> {
    let mut analysis = Analysis {
        ok: true,
        findings: Vec::new(),
    };
    let mut walked_any = false;

    walk(
        source_root,
        source_root,
        ignore,
        &mut analysis,
        &mut walked_any,
    )?;
    // A directory with no Rust files means we either mis-scoped the artifact
    // or there is nothing to audit — surface it rather than reporting a clean
    // but meaningless "no findings".
    analysis.ok = walked_any;

    Ok(analysis)
}

fn walk(
    root: &Path,
    dir: &Path,
    ignore: &[&str],
    analysis: &mut Analysis,
    walked_any: &mut bool,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("failed to read source root {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if ignore.iter().any(|ig| name.ends_with(ig)) {
                continue;
            }
        }
        if path.is_dir() {
            walk(root, &path, ignore, analysis, walked_any)?;
        } else if is_rust_source(&path) {
            *walked_any = true;
            analyze_file(root, &path, analysis)?;
        }
    }
    Ok(())
}

fn is_rust_source(path: &Path) -> bool {
    matches!(path.extension().and_then(|e| e.to_str()), Some("rs"))
}

fn analyze_file(root: &Path, path: &Path, analysis: &mut Analysis) -> Result<()> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();

    // A coarse function-extent detector: we split the file into blocks
    // delimited by braces at the top level of each `fn`. For rules that need
    // to know whether a function performed auth or a state mutation, we
    // analyse per-function by scanning for a `fn` keyword on its own segment.
    let lines: Vec<&str> = contents.lines().collect();
    // Test modules are never deployed, so findings inside `#[cfg(test)]` /
    // `mod tests` blocks are noise. Compute those extents and skip any
    // function that starts within one.
    let test_ranges = test_block_ranges(&lines);
    let functions = split_functions(&lines);

    if functions.is_empty() {
        // No explicit fn blocks (e.g. a pure macro-heavy file): still run the
        // line-local rules across the whole file, but exclude test regions.
        run_line_rules(&lines, &rel, analysis, None);
        return Ok(());
    }

    for fun in &functions {
        let (start, end) = (fun.0, fun.1);
        if test_ranges.iter().any(|(s, e)| start >= *s && start < *e) {
            continue;
        }
        run_function_rules(
            &lines[start..end.min(lines.len())],
            &rel,
            start as u32 + 1,
            analysis,
        );
        run_line_rules(
            &lines[start..end.min(lines.len())],
            &rel,
            analysis,
            Some(&test_ranges),
        );
    }

    Ok(())
}

/// Index ranges (half-open) covering `#[cfg(test)]` module blocks, so rule
/// matches inside them can be suppressed. A block only "closes" once its
/// opening `{` has been seen and the brace depth returns to zero — the
/// `#[cfg(test)]` attribute line alone does not delimit anything.
fn test_block_ranges(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    let mut saw_open = false;
    let mut in_test = false;
    for (i, raw) in lines.iter().enumerate() {
        let line = strip_comments_and_strings(raw);
        if line.contains("#[cfg(test)]") {
            in_test = true;
        }
        if in_test {
            if start.is_none() {
                start = Some(i);
                depth = 0;
                saw_open = false;
            }
            let opens = line.matches('{').count();
            let closes = line.matches('}').count();
            if opens > 0 {
                saw_open = true;
            }
            depth += opens;
            depth = depth.saturating_sub(closes);
            if saw_open && depth == 0 {
                out.push((start.unwrap(), i + 1));
                start = None;
                saw_open = false;
                in_test = false;
            }
        }
    }
    out
}

/// A `(start, end)` index range into `lines` covering one top-level `fn`.
/// This is deliberately approximate: it counts braces starting from a line that
/// begins with `fn` (after lexing), giving us the function's extent. Nested
/// items (impls inside fns) are rare and acceptable to mishandle here.
fn split_functions(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    for (i, raw) in lines.iter().enumerate() {
        let line = strip_comments_and_strings(raw);
        if start.is_none() && is_fn_signature(&line) {
            start = Some(i);
            depth = 0;
        }
        if let Some(s) = start {
            depth += line.matches('{').count();
            let closes = line.matches('}').count();
            if closes > 0 && depth < closes {
                // Shouldn't happen with balanced input; bail this block.
                out.push((s, i + 1));
                start = None;
                continue;
            }
            depth = depth.saturating_sub(closes);
            if depth == 0 {
                out.push((s, i + 1));
                start = None;
            }
        }
    }
    out
}

/// Best-effort detection of a function signature line: it contains a `fn`
/// keyword token and a `(` (an argument list), and is not itself a `for`
/// loop or trait-`impl`-style noise. Comments/strings are already stripped by
/// the caller.
fn is_fn_signature(line: &str) -> bool {
    let trimmed = line.trim_start();
    if !trimmed.contains('(') {
        return false;
    }
    // Must contain a `fn` word boundary. `trimmed` is used so a nested `fn`
    // appearing without a leading `(` is not treated as a signature.
    trimmed
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w == "fn")
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// Run per-function rules (those needing function-level context).
#[allow(clippy::too_many_arguments)]
fn run_function_rules(fn_lines: &[&str], rel: &str, fn_start_1based: u32, analysis: &mut Analysis) {
    let mut has_auth = false;
    let mut mutates_state = false;
    let mut makes_external_call = false;

    for (li, raw) in fn_lines.iter().enumerate() {
        let line = strip_comments_and_strings(raw);
        let lineno = fn_start_1based + li as u32;

        // Authorization / reentrancy-guard detection.
        if line.contains("require_auth") || line.contains("require_auth_for_args") {
            has_auth = true;
        }

        // State mutation = writing a persistent value or transferring value.
        if line.contains("env.storage().persistent().set")
            || line.contains("env.storage().instance().set")
            || line.contains("transfer")
            || line.contains("try_into") && (line.contains("amount") || line.contains("balance"))
        {
            mutates_state = true;
        }

        // External calls: reentrancy-relevant.
        if line.contains("invoke_contract") || line.contains("call_contract") {
            makes_external_call = true;
        }

        // Rule: panic on user input (availability / poor validation).
        // Conservative: only flag an explicit `panic!(...)` with a string
        // argument, or `unwrap()`/`expect(` on a value-related line. This
        // avoids the noise of `?`, `unwrap_or`, and unrelated `.unwrap()` in
        // SDK glue or tests.
        let valueish = line.contains("amount")
            || line.contains("balance")
            || line.contains("transfer")
            || line.contains("withdraw")
            || line.contains("burn")
            || line.contains("mint");
        let has_panic = line.contains("panic!(") || line.contains("panic! (");
        let has_unwrap = (line.contains("unwrap()") || line.contains("expect(")) && valueish;
        if (has_panic || has_unwrap) && !line.contains("require_auth") {
            analysis.findings.push(Finding {
                rule: RuleId::PanicOnInput,
                severity: Severity::Low,
                message: "`panic!` or `unwrap()` on a code path that may be reachable from callers; prefer returning a Result and reverting with a clear error"
                    .to_string(),
                file: rel.to_string(),
                line: lineno,
                remediation: "Replace panics with `Result` and use `?`/`ensure!` so callers (and the front-end) can handle failures gracefully.",
            });
        }

        // Rule: unchecked arithmetic on value quantities. Only flag raw
        // `+`/`-`/`*` on lines that are not already using a checked_ helper.
        let uses_checked = line.contains("checked_");
        let value_like = line.contains("amount")
            || line.contains("balance")
            || line.contains("u128")
            || line.contains("i128")
            || line.contains("sabi")
            || line.contains("Token");
        if !uses_checked
            && value_like
            && (line.contains('+') || line.contains('-') || line.contains('*'))
        {
            analysis.findings.push(Finding {
                rule: RuleId::UncheckedArithmetic,
                severity: Severity::Medium,
                message: "unchecked arithmetic on a likely value quantity; consider `checked_add/sub/mul` to guard against overflow"
                    .to_string(),
                file: rel.to_string(),
                line: lineno,
                remediation: "Use `checked_add`, `checked_sub`, `checked_mul` on I128/amounts and handle `None` with a revert.",
            });
        }
    }

    // Rule: value-mutating path with no authorization.
    if mutates_state && !has_auth {
        analysis.findings.push(Finding {
            rule: RuleId::MissingAuth,
            severity: Severity::Critical,
            message: "function mutates contract state or moves value without `require_auth`; an unauthenticated caller may drive changes"
                .to_string(),
            file: rel.to_string(),
            line: fn_start_1based,
            remediation: "Call `env.current_contract_address().require_auth()` (or `require_auth_for_args`) before any state mutation that affects value.",
        });
    }

    // Rule: external call after state mutation with no authorization is a
    // classic reentrancy risk.
    if mutates_state && makes_external_call && !has_auth {
        analysis.findings.push(Finding {
            rule: RuleId::Reentrancy,
            severity: Severity::High,
            message: "possible reentrancy: the function mutates state and makes an external/invoke call without `require_auth`"
                .to_string(),
            file: rel.to_string(),
            line: fn_start_1based,
            remediation: "Apply a `non_reentrant` guard, move the external call after all state updates, or rely on `require_auth` of the target.",
        });
    }
}

/// Run line-local rules (those that do not need function context).
/// `test_ranges` suppresses findings inside `#[cfg(test)]` modules.
fn run_line_rules(
    lines: &[&str],
    rel: &str,
    analysis: &mut Analysis,
    test_ranges: Option<&[(usize, usize)]>,
) {
    for (i, raw) in lines.iter().enumerate() {
        let line = strip_comments_and_strings(raw);
        let lineno = i as u32 + 1;
        let in_test = test_ranges
            .map(|r| r.iter().any(|(s, e)| i >= *s && i < *e))
            .unwrap_or(false);
        if in_test {
            continue;
        }

        // Missing reentrancy guard on a storage-mutating fn is covered in the
        // function rule; here we flag the common `env.invoke_contract` call
        // without any guard attribute on the same line.
        if (line.contains("invoke_contract") || line.contains("call_contract"))
            && !line.contains("non_reentrant")
        {
            analysis.findings.push(Finding {
                rule: RuleId::MissingReentrancyGuard,
                severity: Severity::Medium,
                message: "external `invoke_contract`/`call_contract` call detected without an adjacent `non_reentrant` guard"
                    .to_string(),
                file: rel.to_string(),
                line: lineno,
                remediation: "Consider guarding the calling function with `#[non_reentrant]` to prevent reentrant entry.",
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Console rendering of an analysis result.
pub fn render_analysis(project: &str, artifact: &str, analysis: &Analysis) -> String {
    let mut lines = vec![
        format!("Sorseal — {project} analyze :: {artifact}"),
        String::new(),
    ];
    if !analysis.ok {
        lines.push("ERROR   no Rust source files found to analyze".to_string());
        lines.push(String::new());
        lines.push("checked: 0 source files".to_string());
        return lines.join("\n");
    }
    if analysis.findings.is_empty() {
        lines.push("CLEAN   no findings in source".to_string());
    } else {
        for f in &analysis.findings {
            lines.push(format!(
                "{}  {}  {}:{} — {}",
                f.severity.as_str(),
                f.rule.as_str(),
                f.file,
                f.line,
                f.message
            ));
        }
    }
    lines.push(String::new());
    lines.push(format!(
        "{} findings — Critical: {} · High: {} · Medium: {} · Low: {}",
        analysis.findings.len(),
        analysis.count_by_severity(Severity::Critical),
        analysis.count_by_severity(Severity::High),
        analysis.count_by_severity(Severity::Medium),
        analysis.count_by_severity(Severity::Low),
    ));
    lines.push(format!(
        "analysis digest sha256 {}",
        &analysis.digest()[..12]
    ));
    lines.join("\n")
}

/// Markdown rendering for an audit-trail deliverable.
pub fn render_markdown(project: &str, artifact: &str, analysis: &Analysis) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Analysis: {project} — {artifact}\n\n"));
    if !analysis.ok {
        out.push_str("_No Rust source files found to analyze._\n");
        return out;
    }
    out.push_str(&format!("- findings: {}\n", analysis.findings.len()));
    out.push_str(&format!("- digest: `{}`\n", analysis.digest()));
    out.push_str("\n| severity | rule | location | finding |\n|---|---|---|---|\n");
    for f in &analysis.findings {
        out.push_str(&format!(
            "| {} | `{}` | `{}:{}` | {} |\n",
            f.severity.as_str(),
            f.rule.as_str(),
            md_escape(&f.file),
            f.line,
            md_escape(&f.message)
        ));
    }
    out
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
}

/// Build a SARIF rules array covering every rule that produced findings.
pub fn sarif_rules(findings: &[Finding]) -> serde_json::Value {
    let mut seen: HashSet<&'static str> = HashSet::new();
    let mut rules = Vec::new();
    for f in findings {
        if seen.insert(f.rule.as_str()) {
            let severity = f.severity;
            let _ = severity;
            rules.push(serde_json::json!({
                "id": f.rule.as_str(),
                "name": f.rule.name(),
                "shortDescription": { "text": to_short_desc(f.rule) },
                "properties": { "tags": ["soroban", "security-audit"] }
            }));
        }
    }
    serde_json::Value::Array(rules)
}

/// Render findings as SARIF `results` entries.
pub fn sarif_results(findings: &[Finding]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.rule.as_str(),
                "level": f.severity.sarif_level(),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": { "startLine": f.line }
                    }
                }],
                "properties": {
                    "severity": f.severity.as_str(),
                    "remediation": f.remediation
                }
            })
        })
        .collect();
    serde_json::Value::Array(results)
}

fn to_short_desc(rule: RuleId) -> String {
    match rule {
        RuleId::MissingAuth => "State or value mutation without require_auth".into(),
        RuleId::Reentrancy => "Possible reentrancy (external call after state mutation)".into(),
        RuleId::UncheckedArithmetic => "Unchecked arithmetic on value quantities".into(),
        RuleId::PanicOnInput => "Panic/unwrap on user-reachable code path".into(),
        RuleId::UncheckedTransfer => "Value transfer without an apparent balance/auth check".into(),
        RuleId::MissingReentrancyGuard => "External call without a non_reentrant guard".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn analyze_source(src: &str) -> Analysis {
        let dir = tempdir().unwrap();
        let src_dir = dir.path().join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(src_dir.join("lib.rs"), src).unwrap();
        analyze_tree(dir.path(), &["target"]).unwrap()
    }

    #[test]
    fn detects_missing_auth_on_value_mutation() {
        let src = r#"
            pub fn withdraw(env: Env, to: Address, amount: i128) {
                env.storage().persistent().set(&KEY, &0i128);
                env.transfer(&to, &amount);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings.iter().any(|f| f.rule == RuleId::MissingAuth),
            "expected MissingAuth finding, got {:?}",
            a.findings
        );
    }

    #[test]
    fn no_missing_auth_when_require_auth_present() {
        let src = r#"
            pub fn withdraw(env: Env, to: Address, amount: i128) {
                to.require_auth();
                env.storage().persistent().set(&KEY, &0i128);
                env.transfer(&to, &amount);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            !a.findings.iter().any(|f| f.rule == RuleId::MissingAuth),
            "unexpected MissingAuth: {:?}",
            a.findings
        );
    }

    #[test]
    fn detects_panic_on_value_path() {
        let src = r#"
            pub fn withdraw(env: Env, amount: i128) {
                let _b = balance().unwrap();
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings.iter().any(|f| f.rule == RuleId::PanicOnInput),
            "expected PanicOnInput, got {:?}",
            a.findings
        );
    }

    #[test]
    fn ignores_commented_out_panic() {
        let src = r#"
            pub fn set(env: Env, amount: i128) {
                // panic!("this is commented out");
            }
        "#;
        let a = analyze_source(src);
        assert!(
            !a.findings.iter().any(|f| f.rule == RuleId::PanicOnInput),
            "commented panic should not match: {:?}",
            a.findings
        );
    }

    #[test]
    fn skips_findings_inside_cfg_test_module() {
        let src = r#"
            pub fn withdraw(env: Env, amount: i128) {
                env.storage().persistent().set(&KEY, &0i128);
            }
            #[cfg(test)]
            mod tests {
                pub fn helper() {
                    panic!("test only");
                }
            }
        "#;
        let a = analyze_source(src);
        // The only expected finding is MissingAuth from the withdraw fn; the
        // test-module panic must not produce a PanicOnInput finding.
        assert!(
            !a.findings.iter().any(|f| f.rule == RuleId::PanicOnInput),
            "test module leaked findings: {:?}",
            a.findings
        );
        assert!(
            a.findings.iter().any(|f| f.rule == RuleId::MissingAuth),
            "missing expected MissingAuth: {:?}",
            a.findings
        );
    }

    #[test]
    fn no_rust_files_marks_not_ok() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs/readme.txt"), "hi").unwrap();
        let a = analyze_tree(dir.path(), &[]).unwrap();
        assert!(!a.ok);
    }

    #[test]
    fn digest_is_stable_hex() {
        let src = "pub fn f(env: Env) { panic!(); }";
        let a1 = analyze_source(src);
        let a2 = analyze_source(src);
        assert_eq!(a1.digest(), a2.digest());
        assert_eq!(a1.digest().len(), 64);
        assert!(a1.digest().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn severity_roundtrip_and_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert_eq!(Severity::High.sarif_level(), "error");
        assert_eq!(Severity::Medium.sarif_level(), "warning");
        assert_eq!(Severity::Low.sarif_level(), "note");
    }

    #[test]
    fn html_rules_are_sarif_serializable() {
        let a = analyze_source("pub fn f(env: Env) { panic!(); }");
        let rules = sarif_rules(&a.findings);
        assert!(rules.is_array());
        let results = sarif_results(&a.findings);
        assert!(results.is_array());
    }
}
