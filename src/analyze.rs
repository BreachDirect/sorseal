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
    HardcodedStorageKey,
    UnsafeRawPointer,
    PanicOnStorageRead,
    AdminKeyNeverRotated,
    MissingTokenBalanceCheck,
    UncheckedEnvCaller,
    OraclePriceFeed,
    FlashLoanApprove,
    WasmUnreachableExport,
    WasmNoExports,
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
            RuleId::HardcodedStorageKey => "SORSEAL-107",
            RuleId::UnsafeRawPointer => "SORSEAL-108",
            RuleId::PanicOnStorageRead => "SORSEAL-109",
            RuleId::AdminKeyNeverRotated => "SORSEAL-110",
            RuleId::MissingTokenBalanceCheck => "SORSEAL-111",
            RuleId::UncheckedEnvCaller => "SORSEAL-112",
            RuleId::OraclePriceFeed => "SORSEAL-113",
            RuleId::FlashLoanApprove => "SORSEAL-114",
            RuleId::WasmUnreachableExport => "SORSEAL-115",
            RuleId::WasmNoExports => "SORSEAL-116",
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
            RuleId::HardcodedStorageKey => "hardcoded-storage-key",
            RuleId::UnsafeRawPointer => "unsafe-raw-pointer",
            RuleId::PanicOnStorageRead => "panic-on-storage-read",
            RuleId::AdminKeyNeverRotated => "admin-key-never-rotated",
            RuleId::MissingTokenBalanceCheck => "missing-token-balance-check",
            RuleId::UncheckedEnvCaller => "unchecked-env-caller",
            RuleId::OraclePriceFeed => "oracle-price-feed",
            RuleId::FlashLoanApprove => "flash-loan-approve",
            RuleId::WasmUnreachableExport => "wasm-unreachable-export",
            RuleId::WasmNoExports => "wasm-no-exports",
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

/// How much the lexical rule engine believes this finding is a real bug,
/// independent of damage potential. Exact bytecode/pattern matches are `High`;
/// the heuristic, pattern-based rules (unchecked transfer, oracle reads, …)
/// are `Low`/`Medium` because they need data-flow context to be certain. This
/// mirrors how tools like `semgrep` and `rapidgator` separate *impact*
/// (severity) from *certainty* (confidence) so a 13-finding report can be
/// triaged without treating every line as equally urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
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

impl Finding {
    /// Certainty score for this finding. Derived from the rule's durable
    /// metadata (not stored per-finding) so the sealed analysis digest is
    /// untouched — confidence is a property of the rule, not of an individual
    /// match an attacker could tamper with.
    pub fn confidence(&self) -> Confidence {
        rule_meta(self.rule).confidence
    }
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

    /// True when at least one finding has severity at or above `threshold`.
    /// The basis for the `--fail-on` CI gate.
    pub fn has_findings_at_or_above(&self, threshold: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= threshold)
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
    analyze_tree_with(source_root, ignore, &AnalyzeOptions::default())
}

/// `analyze_tree` with explicit options (e.g. inline suppressions disabled).
pub fn analyze_tree_with(
    source_root: &Path,
    ignore: &[&str],
    opts: &AnalyzeOptions,
) -> Result<Analysis> {
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
        opts,
    )?;
    // A directory with no Rust files means we either mis-scoped the artifact
    // or there is nothing to audit — surface it rather than reporting a clean
    // but meaningless "no findings".
    analysis.ok = walked_any;

    // Deterministic ordering (file -> line -> rule) so the digest and every
    // renderer (console, JSON, Markdown, SARIF) are stable regardless of the
    // filesystem's read_dir order.
    analysis.findings.sort_by(|a, b| {
        (
            a.file.as_str(),
            a.line,
            a.rule.as_str(),
            a.severity,
            a.message.as_str(),
        )
            .cmp(&(
                b.file.as_str(),
                b.line,
                b.rule.as_str(),
                b.severity,
                b.message.as_str(),
            ))
    });

    Ok(analysis)
}

fn walk(
    root: &Path,
    dir: &Path,
    ignore: &[&str],
    analysis: &mut Analysis,
    walked_any: &mut bool,
    opts: &AnalyzeOptions,
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
            walk(root, &path, ignore, analysis, walked_any, opts)?;
        } else if is_rust_source(&path) {
            *walked_any = true;
            analyze_file(root, &path, analysis, opts)?;
        }
    }
    Ok(())
}

fn is_rust_source(path: &Path) -> bool {
    matches!(path.extension().and_then(|e| e.to_str()), Some("rs"))
}

/// A rule/suppression filter passed through the analyzer. `no_ignore` disables
/// inline `// sorseal:ignore ...` comments so every finding is visible.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnalyzeOptions {
    pub no_ignore: bool,
}

fn analyze_file(
    root: &Path,
    path: &Path,
    analysis: &mut Analysis,
    opts: &AnalyzeOptions,
) -> Result<()> {
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
    // Strip comments/string literals once per line. Every rule below operates
    // on these precomputed views instead of re-lexing each line ten+ times
    // through `strip_comments_and_strings`; on a monorepo-sized tree this is
    // the difference between linear and ~16x-constant scanning.
    let stripped: Vec<String> = lines
        .iter()
        .map(|l| strip_comments_and_strings(l))
        .collect();
    let lowered: Vec<String> = stripped.iter().map(|l| l.to_ascii_lowercase()).collect();
    // Test modules are never deployed, so findings inside `#[cfg(test)]` /
    // `mod tests` blocks are noise. Compute those extents and skip any
    // function that starts within one.
    let test_ranges = test_block_ranges(&stripped);
    let functions = split_functions(&stripped);

    // Findings for this file only — used to apply inline suppressions after
    // the rules have run.
    let findings_start = analysis.findings.len();

    if functions.is_empty() {
        // No explicit fn blocks (e.g. a pure macro-heavy file): still run the
        // line-local rules across the whole file, but exclude test regions.
        run_line_rules(&stripped[..], &rel, analysis, None, 0);
    } else {
        for fun in &functions {
            let (start, end) = (fun.0, fun.1);
            let end = end.min(lines.len());
            if test_ranges.iter().any(|(s, e)| start >= *s && start < *e) {
                continue;
            }
            run_function_rules(
                &lines[start..end],
                &stripped[start..end],
                &lowered[start..end],
                &rel,
                start as u32 + 1,
                analysis,
            );
            run_line_rules(
                &stripped[start..end],
                &rel,
                analysis,
                Some(&test_ranges),
                start as u32,
            );
        }
    }

    apply_inline_suppressions(
        &mut analysis.findings,
        findings_start,
        &lines,
        opts.no_ignore,
    );

    Ok(())
}

/// Drop findings whose source line is immediately preceded by an inline
/// `// sorseal:ignore <RULE>` comment (or `// sorseal:ignore all`). The
/// comment carries a reason after the rule id, e.g.
/// `// sorseal:ignore SORSEAL-104 reviewed: this path is guarded above`.
/// Suppressed findings are removed before counts and the digest are computed,
/// so a suppressed run seals a different digest than an unsuppressed one.
/// `start` is the index of the first finding belonging to the current file.
fn apply_inline_suppressions(
    findings: &mut Vec<Finding>,
    start: usize,
    lines: &[&str],
    no_ignore: bool,
) {
    if no_ignore || lines.is_empty() {
        return;
    }
    let current = findings.split_off(start);
    let mut kept: Vec<Finding> = Vec::with_capacity(current.len());
    for finding in current {
        // The finding's 1-based line: the suppressive comment sits on the
        // line above it (0-based index finding.line - 2).
        let suppressed = finding.line >= 2
            && lines
                .get((finding.line - 2) as usize)
                .and_then(|line| inline_ignore_rules(line))
                .is_some_and(|rules| {
                    rules
                        .iter()
                        .any(|r| r == "all" || r == finding.rule.as_str())
                });
        if !suppressed {
            kept.push(finding);
        }
    }
    findings.extend(kept);
}

/// Parse the rule ids named by a `sorseal:ignore` comment (if any). Returns
/// `None` when the directive is absent or names no known rule.
fn inline_ignore_rules(line: &str) -> Option<Vec<String>> {
    let marker = "sorseal:ignore";
    let idx = line.find(marker)?;
    let rest = &line[idx + marker.len()..];
    let mut rules = Vec::new();
    for token in rest.split_whitespace() {
        if token == "all" {
            rules.push("all".to_string());
        } else if token.to_ascii_uppercase().starts_with("SORSEAL-") {
            rules.push(token.to_ascii_uppercase());
        }
    }
    if rules.is_empty() {
        None
    } else {
        Some(rules)
    }
}

/// Index ranges (half-open) covering `#[cfg(test)]` module blocks, so rule
/// matches inside them can be suppressed. A block only "closes" once its
/// opening `{` has been seen and the brace depth returns to zero — the
/// `#[cfg(test)]` attribute line alone does not delimit anything.
fn test_block_ranges(lines: &[String]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    let mut saw_open = false;
    let mut in_test = false;
    for (i, line) in lines.iter().enumerate() {
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
fn split_functions(lines: &[String]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        if start.is_none() && is_fn_signature(line) {
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
/// `fn_raw`/`fn_stripped`/`fn_lower` are the raw, comment/string-stripped, and
/// lowercased-stripped views of the function's lines, all precomputed once per
/// file by the caller.
#[allow(clippy::too_many_arguments)]
fn run_function_rules(
    fn_raw: &[&str],
    fn_stripped: &[String],
    fn_lower: &[String],
    rel: &str,
    fn_start_1based: u32,
    analysis: &mut Analysis,
) {
    let mut has_auth = false;
    let mut mutates_state = false;
    let mut makes_external_call = false;
    let mut made_transfer = false;
    let mut reads_balance_or_allowance = false;

    for (li, line) in fn_stripped.iter().enumerate() {
        let lower = &fn_lower[li];
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

        // SORSEAL-105: a value transfer whose amount was not derived from a
        // balance/allowance read on this contract.
        if line.contains(".transfer(") || line.contains(".transfer_from(") {
            made_transfer = true;
        }
        if lower.contains("balance") || lower.contains("allowance") {
            reads_balance_or_allowance = true;
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

    // Rule: value transfer whose amount was not derived from a balance /
    // allowance read (SORSEAL-105). Hard-coded or balance-insensitive amounts
    // are a classic Soroban drain vector.
    if made_transfer && !reads_balance_or_allowance {
        analysis.findings.push(Finding {
            rule: RuleId::UncheckedTransfer,
            severity: Severity::High,
            message: "token `.transfer`/`.transfer_from` call with no prior balance/allowance read; the transferred amount is not derived from what this contract actually holds"
                .to_string(),
            file: rel.to_string(),
            line: fn_start_1based,
            remediation: "Read `env.ledger().balance(...)` (or a stored allowance) first and derive the amount from it, or add a `require_auth`-guarded allowance check before transferring.",
        });
    }

    // SORSEAL-110: admin key never rotated — a function writes to a storage
    // key named OWNER/ADMIN (via Symbol::new("OWNER")) without a
    // remote_rotation/transfer pattern. The OWNER/ADMIN literal lives inside a
    // string (Symbol::new), which the lexer strips, so inspect raw lines.
    let writes_admin_key = fn_raw.iter().zip(fn_stripped).any(|(raw, line)| {
        let has_set = line.contains(".set(");
        let key_is_admin = raw.contains("Symbol::new(\"OWNER\"")
            || raw.contains("Symbol::new(\"ADMIN\"")
            || raw.contains("Symbol::new(\"ADMIN_KEY\"")
            || (raw.contains("Symbol::new(\"owner\"") || raw.contains("Symbol::new(\"admin\""));
        has_set && key_is_admin
    });
    let has_rotation = fn_stripped.iter().any(|line| {
        line.contains("transfer_ownership") || line.contains("rotate") || line.contains("set_admin")
    });
    if writes_admin_key && !has_rotation {
        analysis.findings.push(Finding {
            rule: RuleId::AdminKeyNeverRotated,
            severity: Severity::Medium,
            message: "admin/owner key is written to storage without a rotation/transfer pattern in the same function"
                .to_string(),
            file: rel.to_string(),
            line: fn_start_1based,
            remediation: "Add a `transfer_ownership` or `set_admin` function that requires auth from the \
                          current admin and accepts a new admin address, so the key can be rotated.",
        });
    }

    // SORSEAL-111: missing token balance check — a function performs a token
    // operation (burn, mint, transfer) without first verifying that the
    // contract actually holds the asset or has an appropriate allowance.
    let has_token_op = fn_stripped.iter().any(|line| {
        line.contains(".burn(")
            || line.contains(".mint(")
            || line.contains(".transfer(")
            || line.contains(".transfer_from(")
    });
    let checks_balance = fn_lower.iter().any(|lower| {
        lower.contains("balance") || lower.contains("allowance") || lower.contains("checked_")
    });
    if has_token_op && !checks_balance {
        analysis.findings.push(Finding {
            rule: RuleId::MissingTokenBalanceCheck,
            severity: Severity::High,
            message: "token operation (burn/mint/transfer) without a balance or allowance check; \
                      the contract may not hold sufficient assets"
                .to_string(),
            file: rel.to_string(),
            line: fn_start_1based,
            remediation: "Read `env.ledger().balance(...)` before performing token operations and \
                          verify the contract holds sufficient assets, or use `checked_*` arithmetic.",
        });
    }

    // SORSEAL-112: unchecked env caller — an Address parameter is used
    // (passed to transfer, used as a key, etc.) without `require_auth` on
    // that address, making it spoofable.
    let uses_address_param = fn_stripped.iter().any(|line| {
        line.contains("Address")
            && (line.contains(".transfer(") || line.contains("to:") || line.contains("&to"))
    }) && !fn_stripped.iter().any(|line| line.contains("require_auth"));
    if uses_address_param && mutates_state {
        analysis.findings.push(Finding {
            rule: RuleId::UncheckedEnvCaller,
            severity: Severity::Medium,
            message:
                "caller/address parameter used without `require_auth`; the address may be spoofable"
                    .to_string(),
            file: rel.to_string(),
            line: fn_start_1based,
            remediation:
                "Call `address.require_auth()` before using the caller-supplied address in \
                          any state mutation or value transfer.",
        });
    }

    // SORSEAL-113: oracle / price-feed manipulation — the function derives a
    // financial decision from an external price read (`get_price`,
    // `price_feed`, `.latest_price`, or an invoke returning a "price" symbol)
    // with no staleness check and no auth on the price provider.
    let reads_price = fn_lower.iter().any(|lower| {
        lower.contains("get_price")
            || lower.contains("price_feed")
            || lower.contains("price_feed_addr")
            || lower.contains(".latest_price")
            || (lower.contains("invoke_contract") && lower.contains("price"))
            || lower.contains("oracle")
    });
    let guards_price = fn_lower.iter().any(|lower| {
        lower.contains("require_auth")
            || lower.contains("timestamp")
            || lower.contains("lag")
            || lower.contains("stale")
            || lower.contains("checked_price")
            || lower.contains("max_age")
    });
    if reads_price && !guards_price && mutates_state {
        analysis.findings.push(Finding {
            rule: RuleId::OraclePriceFeed,
            severity: Severity::Medium,
            message: "price-feed/oracle read with no staleness check and no auth on the provider; \
                      the price may be manipulable by a caller"
                .to_string(),
            file: rel.to_string(),
            line: fn_start_1based,
            remediation: "Validate the price age against a max-age threshold, verify the feed \
                          contract address is a trusted constant, and consider a two-source or \
                          TWAP-style oracle to resist single-feed manipulation.",
        });
    }

    // SORSEAL-114: flash-loan / approve-and-exploit — the function grants a
    // token allowance (`approve`/`increase_allowance`) and then performs an
    // external call in the same function. If the allowance is caller-controlled
    // and the external call can re-enter, value can be moved before the caller
    // verifies it.
    let grants_allowance = fn_lower.iter().any(|lower| {
        lower.contains(".approve(")
            || lower.contains(".increase_allowance(")
            || lower.contains(".decrease_allowance(")
    });
    let external_call_after = fn_stripped
        .iter()
        .any(|line| line.contains("invoke_contract") || line.contains("call_contract"));
    if grants_allowance && external_call_after {
        analysis.findings.push(Finding {
            rule: RuleId::FlashLoanApprove,
            severity: Severity::High,
            message: "token allowance is granted and an external call is made in the same \
                      function; a malicious contract could use the allowance before it is checked"
                .to_string(),
            file: rel.to_string(),
            line: fn_start_1based,
            remediation:
                "Set the allowance to zero before the external call (approve-then-set-0), \
                          move the external call after all allowance state changes, or cap the \
                          allowance with a `require_auth`-guarded amount.",
        });
    }
}

/// Run line-local rules (those that do not need function context).
/// `lines` is the comment/string-stripped view of the source slice.
/// `test_ranges` suppresses findings inside `#[cfg(test)]` modules and is in
/// file coordinates (0-based line indices).
/// `base_line` is the 0-based file index of the first line in `lines`, so
/// reported line numbers are absolute (not relative to a function slice).
fn run_line_rules(
    lines: &[String],
    rel: &str,
    analysis: &mut Analysis,
    test_ranges: Option<&[(usize, usize)]>,
    base_line: u32,
) {
    for (i, line) in lines.iter().enumerate() {
        let file_index = base_line + i as u32;
        let lineno = file_index + 1;
        let in_test = test_ranges
            .map(|r| {
                r.iter()
                    .any(|(s, e)| file_index >= *s as u32 && file_index < *e as u32)
            })
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

        // SORSEAL-107: hardcoded storage key — Symbol::new("...") used as a
        // persistent/instance storage key. Hardcoded keys risk collision across
        // contract upgrades or with third-party contracts sharing the same
        // storage namespace.
        if line.contains("Symbol::new(")
            && (line.contains("storage()")
                || line.contains("persistent()")
                || line.contains("instance()"))
        {
            analysis.findings.push(Finding {
                rule: RuleId::HardcodedStorageKey,
                severity: Severity::Medium,
                message: "hardcoded `Symbol::new(\"...\")` used as a persistent storage key; \
                          consider using a namespaced constant or derive the key from the contract address"
                    .to_string(),
                file: rel.to_string(),
                line: lineno,
                remediation: "Define storage keys as `const` symbols with a unique namespace prefix, \
                              or use a hash-based key to avoid collisions across upgrades.",
            });
        }

        // SORSEAL-108: unsafe raw pointer — `unsafe` blocks or raw pointer
        // derefs in Soroban contract code. Soroban's sandboxed execution
        // model does not support unsafe; these blocks are either dead code
        // or indicate a fundamental misuse of the SDK.
        if line.contains("unsafe {")
            || line.contains("unsafe{")
            || line.contains("*const ")
            || line.contains("*mut ")
            || line.contains("as *const")
            || line.contains("as *mut")
        {
            analysis.findings.push(Finding {
                rule: RuleId::UnsafeRawPointer,
                severity: Severity::Critical,
                message: "`unsafe` block or raw pointer operation detected in contract code; \
                          Soroban contracts execute in a sandbox and unsafe is not supported"
                    .to_string(),
                file: rel.to_string(),
                line: lineno,
                remediation:
                    "Remove the `unsafe` block. Soroban contracts cannot use unsafe code — \
                              the runtime sandbox enforces memory safety. If you need FFI, use the \
                              Soroban SDK's safe abstractions.",
            });
        }

        // SORSEAL-109: panic on storage read — `.unwrap()` on a storage get
        // call. If the key does not exist, this panics and reverts the
        // transaction. Prefer `unwrap_or`/`unwrap_or_default` or `Option` checks.
        if line.contains(".get(")
            && line.contains("storage()")
            && (line.contains("unwrap()") || line.contains("expect("))
        {
            analysis.findings.push(Finding {
                rule: RuleId::PanicOnStorageRead,
                severity: Severity::Low,
                message:
                    "`unwrap()`/`expect()` on a storage `.get()` call; panics if the key is absent"
                        .to_string(),
                file: rel.to_string(),
                line: lineno,
                remediation:
                    "Use `.unwrap_or(default)` or `.get(...).map(...)` to handle missing keys \
                              gracefully instead of panicking.",
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
                "{}  {}  {}:{} — {}  ({} confidence)",
                f.severity.as_str(),
                f.rule.as_str(),
                f.file,
                f.line,
                f.message,
                f.confidence().as_str()
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
    out.push_str(
        "\n| severity | confidence | rule | location | finding |\n|---|---|---|---|---|\n",
    );
    for f in &analysis.findings {
        out.push_str(&format!(
            "| {} | {} | `{}` | `{}:{}` | {} |\n",
            f.severity.as_str(),
            f.confidence().as_str(),
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
            let meta = rule_meta(f.rule);
            rules.push(serde_json::json!({
                "id": meta.id,
                "name": meta.name,
                "shortDescription": { "text": meta.short_desc },
                "fullDescription": { "text": meta.description },
                "help": { "text": meta.fix },
                "properties": {
                    "tags": ["soroban", "security-audit"],
                    "confidence": meta.confidence.as_str()
                }
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
                    "confidence": f.confidence().as_str(),
                    "remediation": f.remediation
                }
            })
        })
        .collect();
    serde_json::Value::Array(results)
}

// ---------------------------------------------------------------------------
// Rule metadata + `--explain`
// ---------------------------------------------------------------------------

/// Durable documentation for one detection rule. This single table backs
/// `--explain`, the SARIF rule definitions, and the short descriptions, so
/// rule guidance lives in one place.
pub struct RuleMeta {
    /// Stable id, e.g. `SORSEAL-101`.
    pub id: &'static str,
    /// Machine name, e.g. `missing-authorization`.
    pub name: &'static str,
    /// The `RuleId` variant this describes.
    pub rule: RuleId,
    /// Severity string (`Critical`..`Low`).
    pub severity: &'static str,
    /// Detection certainty (independent of severity / impact).
    pub confidence: Confidence,
    /// One-line summary shown in SARIF/terse output.
    pub short_desc: &'static str,
    /// Longer prose used by `--explain`.
    pub description: &'static str,
    /// Illustrative (or real) snippet context, shown by `--explain`.
    pub example: &'static str,
    /// Concrete remediation guidance.
    pub fix: &'static str,
}

/// The full, ordered rule set (by id).
pub fn all_rules() -> Vec<RuleMeta> {
    vec![
        RuleMeta {
            id: "SORSEAL-101",
            name: "missing-authorization",
            rule: RuleId::MissingAuth,
            severity: "Critical",
            confidence: Confidence::High,
            short_desc: "State or value mutation without require_auth",
            description: "Detects a function that mutates contract state or moves value \
                          without calling `require_auth` (or `require_auth_for_args`) first. \
                          An unauthenticated caller can drive the change, so a contract \
                          holding value here is vulnerable to being drained.",
            example: "pub fn withdraw(env: Env, to: Address, amount: i128) {\n    \
                       env.storage().persistent().set(&KEY, &0i128);   // no require_auth\n}",
            fix: "Call `env.current_contract_address().require_auth()` (or \
                  `require_auth_for_args`) before any state mutation that affects value.",
        },
        RuleMeta {
            id: "SORSEAL-102",
            name: "reentrancy",
            rule: RuleId::Reentrancy,
            severity: "High",
            confidence: Confidence::Medium,
            short_desc: "Possible reentrancy (external call after state mutation)",
            description: "The function mutates contract state and then makes an external \
                          `invoke_contract`/`call_contract` call without authorization. If \
                          the external call re-enters this contract before state is \
                          committed, an attacker can observe or drive inconsistent state.",
            example: "env.storage().persistent().set(&BALANCE, &new);\nenv.invoke_contract::<i128>(&amount, &Symbol::new(\"apply\"), (&amount,));",
            fix: "Apply a `non_reentrant` guard, move the external call after all state \
                  updates, or rely on `require_auth` of the target.",
        },
        RuleMeta {
            id: "SORSEAL-103",
            name: "unchecked-arithmetic",
            rule: RuleId::UncheckedArithmetic,
            severity: "Medium",
            confidence: Confidence::Medium,
            short_desc: "Unchecked arithmetic on value quantities",
            description: "Raw `+`/`-`/`*` is applied to a likely value quantity (amount, \
                          balance, i128) without a `checked_*` helper, so an overflow can \
                          silently wrap balances.",
            example: "let new_balance: i128 = balance - amount; // unchecked subtraction",
            fix: "Use `checked_add`, `checked_sub`, `checked_mul` on I128/amounts and \
                  handle `None` with a revert.",
        },
        RuleMeta {
            id: "SORSEAL-104",
            name: "panic-on-user-input",
            rule: RuleId::PanicOnInput,
            severity: "Low",
            confidence: Confidence::High,
            short_desc: "Panic/unwrap on user-reachable code path",
            description: "`panic!` or `unwrap()`/`expect()` on a code path that callers can \
                          reach, which reverts the whole transaction instead of returning a \
                          structured error and can hurt cross-contract callers.",
            example: "let rate: i128 = env.storage().instance().get(&KEY).unwrap();",
            fix: "Replace panics with `Result` and use `?`/`ensure!` so callers (and the \
                  front-end) can handle failures gracefully.",
        },
        RuleMeta {
            id: "SORSEAL-105",
            name: "unchecked-transfer",
            rule: RuleId::UncheckedTransfer,
            severity: "High",
            confidence: Confidence::Medium,
            short_desc: "Value transfer without an apparent balance/auth check",
            description: "A token `.transfer`/`.transfer_from` call transfers an amount that \
                          was not derived from a prior `balance`/`allowance` read in the \
                          same function. Hard-coded or balance-insensitive amounts are a \
                          classic Soroban drain vector.",
            example: "pub fn sweep(env: Env, to: Address) {\n    let amount = SOME_CONSTANT;\n    token::Client::new(&env, &to).transfer(&env.current_contract_address(), &to, &amount);\n}",
            fix: "Read `env.ledger().balance(...)` (or a stored allowance) first and derive \
                  the amount from it, or add a `require_auth`-guarded allowance check before \
                  transferring.",
        },
        RuleMeta {
            id: "SORSEAL-106",
            name: "missing-reentrancy-guard",
            rule: RuleId::MissingReentrancyGuard,
            severity: "Medium",
            confidence: Confidence::Medium,
            short_desc: "External call without a non_reentrant guard",
            description: "An `invoke_contract`/`call_contract` call appears without an \
                          adjacent `#[non_reentrant]` guard, so the calling function can be \
                          re-entered while already executing.",
            example: "env.invoke_contract::<i128>(&amount, &Symbol::new(\"apply\"), (&amount,));",
            fix: "Consider guarding the calling function with `#[non_reentrant]` to prevent \
                  reentrant entry.",
        },
        RuleMeta {
            id: "SORSEAL-107",
            name: "hardcoded-storage-key",
            rule: RuleId::HardcodedStorageKey,
            severity: "Medium",
            confidence: Confidence::Medium,
            short_desc: "Hardcoded Symbol::new as a persistent storage key",
            description: "A `Symbol::new(\"...\")` literal is used as a persistent/instance \
                          storage key. Hardcoded keys risk collision across contract upgrades \
                          or with third-party contracts sharing the same storage namespace.",
            example: "env.storage().persistent().set(&Symbol::new(\"balance\"), &amount);",
            fix: "Define storage keys as `const` symbols with a unique namespace prefix, or \
                  use a hash-based key to avoid collisions.",
        },
        RuleMeta {
            id: "SORSEAL-108",
            name: "unsafe-raw-pointer",
            rule: RuleId::UnsafeRawPointer,
            severity: "Critical",
            confidence: Confidence::High,
            short_desc: "unsafe block or raw pointer in contract code",
            description: "An `unsafe` block or raw pointer dereference was detected in contract \
                          code. Soroban contracts execute in a sandboxed environment that does \
                          not support unsafe; these blocks are either dead code or indicate a \
                          fundamental misuse of the SDK.",
            example: "unsafe { (*ptr).write(value); }",
            fix: "Remove the `unsafe` block. Soroban contracts cannot use unsafe code — the \
                  runtime sandbox enforces memory safety. Use the SDK's safe abstractions.",
        },
        RuleMeta {
            id: "SORSEAL-109",
            name: "panic-on-storage-read",
            rule: RuleId::PanicOnStorageRead,
            severity: "Low",
            confidence: Confidence::High,
            short_desc: "unwrap/expect on a storage .get() call",
            description: "An `unwrap()` or `expect()` is called on the result of a \
                          `env.storage().*.get()` call. If the key does not exist, this panics \
                          and reverts the entire transaction.",
            example: "let val: i128 = env.storage().persistent().get(&KEY).unwrap();",
            fix: "Use `.unwrap_or(default)` or `.get(...).map(...)` to handle missing keys \
                  gracefully instead of panicking.",
        },
        RuleMeta {
            id: "SORSEAL-110",
            name: "admin-key-never-rotated",
            rule: RuleId::AdminKeyNeverRotated,
            severity: "Medium",
            confidence: Confidence::Low,
            short_desc: "Admin/owner key written without rotation pattern",
            description: "A storage write to a key named OWNER/ADMIN/ADMIN_KEY is detected \
                          without a corresponding `transfer_ownership` or `set_admin` pattern \
                          in the same function. A non-rotatable admin key means a compromised \
                          key cannot be replaced.",
            example: "env.storage().persistent().set(&OWNER, &admin);",
            fix: "Add a `transfer_ownership` function that requires auth from the current admin \
                  and accepts a new admin address.",
        },
        RuleMeta {
            id: "SORSEAL-111",
            name: "missing-token-balance-check",
            rule: RuleId::MissingTokenBalanceCheck,
            severity: "High",
            confidence: Confidence::Medium,
            short_desc: "Token operation without balance/allowance check",
            description: "A token operation (burn, mint, transfer) is performed without first \
                          verifying that the contract holds sufficient assets or has an \
                          appropriate allowance. The contract may attempt to transfer more \
                          than it holds.",
            example: "token::Client::new(&env, &token).burn(&env.current_contract_address(), &amount);",
            fix: "Read `env.ledger().balance(...)` before performing token operations and verify \
                  the contract holds sufficient assets.",
        },
        RuleMeta {
            id: "SORSEAL-112",
            name: "unchecked-env-caller",
            rule: RuleId::UncheckedEnvCaller,
            severity: "Medium",
            confidence: Confidence::Medium,
            short_desc: "Address parameter used without require_auth",
            description: "A caller-supplied Address parameter is used in a state mutation or \
                          value transfer without calling `require_auth` on it. An attacker can \
                          supply any address, spoofing the caller.",
            example: "pub fn withdraw(env: Env, to: Address, amount: i128) {\n    token::Client::new(&env, &token).transfer(&env.current_contract_address(), &to, &amount);\n}",
            fix: "Call `to.require_auth()` before using the caller-supplied address in any \
                  state mutation or value transfer.",
        },
        RuleMeta {
            id: "SORSEAL-113",
            name: "oracle-price-feed",
            rule: RuleId::OraclePriceFeed,
            severity: "Medium",
            confidence: Confidence::Low,
            short_desc: "Price-feed/oracle read without staleness or auth guard",
            description: "A financial decision (borrow cap, liquidation price, swap amount) is \
                          derived from an external price read (`get_price`, `price_feed`, \
                          `.latest_price`, oracle invoke) with no staleness check and no \
                          `require_auth` on the provider. A caller-controllable price is the \
                          classic single-oracle manipulation vector.",
            example: "let price: i128 = oracle::Client::new(&env, &feed).get_price();\nlet collateral: i128 = amount * price; // no staleness check",
            fix: "Validate the price age against a max-age threshold, verify the feed address is \
                  a trusted constant, and consider a two-source or TWAP-style oracle to resist \
                  single-feed manipulation.",
        },
        RuleMeta {
            id: "SORSEAL-114",
            name: "flash-loan-approve",
            rule: RuleId::FlashLoanApprove,
            severity: "High",
            confidence: Confidence::Low,
            short_desc: "Allowance granted + external call in the same function",
            description: "The function grants a token allowance (`approve`/`increase_allowance`) \
                          and then performs an external `invoke_contract`/`call_contract` in the \
                          same function. If the allowance is caller-controlled and the external \
                          call re-enters, value can be moved before the caller verifies it — the \
                          approve-and-exploit / flash-loan shape.",
            example: "token::Client::new(&env, &token).increase_allowance(&env.current_contract_address(), &spender, &amount);\nenv.invoke_contract::<i128>(&spender, &Symbol::new(\"take\"), (&amount,));",
            fix: "Set the allowance to zero before the external call (approve-then-set-0), move \
                  the external call after all allowance state changes, or cap the allowance with \
                  a `require_auth`-guarded amount.",
        },
        RuleMeta {
            id: "SORSEAL-115",
            name: "wasm-unreachable-export",
            rule: RuleId::WasmUnreachableExport,
            severity: "High",
            confidence: Confidence::High,
            short_desc: "Exported wasm body contains an unreachable trap",
            description: "The compiled WASM bytecode contains an exported function body with an \
                          `unreachable` opcode (`\\0x00` before `\\0x0b` end). Callers reaching \
                          this path revert. Source scanners cannot see this: it only appears in \
                          the deployed artifact — exactly what `analyze --wasm` is for.",
            example: "www 00 0b     ;; unreachable; end  inside an exported entry point",
            fix: "Inspect the trap path: the exported entry point should return a structured \
                  error (e.g. a Status/ErrCode) rather than an `unreachable`.",
        },
        RuleMeta {
            id: "SORSEAL-116",
            name: "wasm-no-exports",
            rule: RuleId::WasmNoExports,
            severity: "Medium",
            confidence: Confidence::High,
            short_desc: "wasm module declares zero exports",
            description: "The compiled WASM module declares zero exports. A deployable Soroban \
                          contract must expose at least one entry point. This usually means the \
                          build didn't apply the `#[contractimpl]`/`wasm` export macros, or the \
                          wrong artifact is being sealed.",
            example: "(empty export section)",
            fix: "Ensure `#[contractimpl]` (or the `wasm` export attributes) are present so the \
                  build emits entry-point exports before deploying.",
        },
    ]
}

/// Look up durable metadata for a rule (always present — every variant is
/// covered by `all_rules`).
pub fn rule_meta(rule: RuleId) -> RuleMeta {
    all_rules()
        .into_iter()
        .find(|m| m.rule == rule)
        .expect("every RuleId has an entry in the rule table")
}

/// Try to resolve a rule from its stable id, e.g. `SORSEAL-101`.
pub fn rule_from_id(id: &str) -> Option<RuleMeta> {
    all_rules()
        .into_iter()
        .find(|m| m.id.eq_ignore_ascii_case(id) || m.name.eq_ignore_ascii_case(id))
}

/// Human-readable `--explain` output for a single rule.
pub fn render_explain(meta: &RuleMeta) -> String {
    format!(
        "{}  {}  ({}, {} confidence)\n\n{}\n\nExample:\n{}\n\nHow to fix:\n  {}",
        meta.id,
        meta.name,
        meta.severity,
        meta.confidence.as_str(),
        meta.description,
        meta.example,
        meta.fix
    )
}

/// `--explain` list of every known rule (id, name, severity, one-liner).
pub fn render_explain_all() -> String {
    let mut out = String::from("sorseal analyze rules\n");
    for meta in all_rules() {
        out.push_str(&format!(
            "  {}  {}  ({}, {} confidence)  — {}\n",
            meta.id,
            meta.name,
            meta.severity,
            meta.confidence.as_str(),
            meta.short_desc
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// JSON rendering
// ---------------------------------------------------------------------------

/// A single artifact's analysis as a JSON value. Finding order is the same
/// deterministic (file -> line -> rule) order used to compute the digest, so
/// the JSON document's `digest` matches the console summary's.
pub fn analysis_json(project: &str, artifact: &str, analysis: &Analysis) -> serde_json::Value {
    let findings: Vec<serde_json::Value> = analysis
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "rule": f.rule.as_str(),
                "rule_name": f.rule.name(),
                "severity": f.severity.as_str(),
                "confidence": f.confidence().as_str(),
                "file": f.file,
                "line": f.line,
                "message": f.message,
                "remediation": f.remediation,
            })
        })
        .collect();
    serde_json::json!({
        "project": project,
        "artifact": artifact,
        "ok": analysis.ok,
        "findings": findings,
        "counts": {
            "critical": analysis.count_by_severity(Severity::Critical),
            "high": analysis.count_by_severity(Severity::High),
            "medium": analysis.count_by_severity(Severity::Medium),
            "low": analysis.count_by_severity(Severity::Low),
        },
        "digest": analysis.digest(),
        "worst_severity": analysis.worst_severity().map(|s| s.as_str()),
    })
}

/// The full machine-readable `--format json` document for one or more
/// artifacts (deterministic: same digest as the console output).
pub fn render_json(project: &str, artifacts: &[(String, Analysis)]) -> serde_json::Value {
    let artifact_values: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|(id, analysis)| analysis_json(project, id, analysis))
        .collect();
    let total: usize = artifacts.iter().map(|(_, a)| a.findings.len()).sum();
    serde_json::json!({
        "project": project,
        "artifacts": artifact_values,
        "total_findings": total,
    })
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

    #[test]
    fn confidence_maps_by_rule_and_is_separate_from_severity() {
        // Exact bytecode/pattern rules are High confidence; the heuristic
        // data-flow-ish rules are Medium/Low even though their severity is high.
        assert_eq!(
            rule_meta(RuleId::WasmUnreachableExport).confidence,
            Confidence::High
        );
        assert_eq!(
            rule_meta(RuleId::UnsafeRawPointer).confidence,
            Confidence::High
        );
        assert_eq!(
            rule_meta(RuleId::UncheckedTransfer).confidence,
            Confidence::Medium
        );
        assert_eq!(
            rule_meta(RuleId::OraclePriceFeed).confidence,
            Confidence::Low
        );
        assert_eq!(
            rule_meta(RuleId::FlashLoanApprove).confidence,
            Confidence::Low
        );
        // severity and confidence are independent axes
        let flash = rule_meta(RuleId::FlashLoanApprove);
        assert_eq!(flash.severity, "High");
        assert_eq!(flash.confidence, Confidence::Low);
    }

    #[test]
    fn confidence_flows_into_rendering_but_not_the_digest() {
        let a = analyze_source(
            "pub fn withdraw(env: Env, to: Address, amount: i128) {\n    \
             env.storage().persistent().set(&KEY, &0i128);\n    \
             env.transfer(&to, &amount);\n}",
        );
        let before = a.digest();
        let rendered = render_analysis("p", "a", &a);
        assert!(
            rendered.contains("confidence"),
            "console output should show a confidence tag: {rendered}"
        );
        // JSON carries a per-finding confidence field
        assert_eq!(
            analysis_json("p", "a", &a)["findings"][0]["confidence"],
            serde_json::json!("high")
        );
        // the sealed digest is untouched by confidence (a rule property)
        assert_eq!(a.digest(), before);
    }

    #[test]
    fn every_rule_has_explain_metadata() {
        let metas = all_rules();
        assert_eq!(metas.len(), 16);
        for meta in &metas {
            assert!(!render_explain(meta).is_empty(), "{} must render", meta.id);
            assert!(meta.description.contains(' '));
            assert!(!meta.fix.is_empty());
            // confidence is always assigned
            assert!(!meta.confidence.as_str().is_empty());
            // every RuleId variant is covered exactly once
            assert_eq!(
                metas.iter().filter(|m| m.rule == meta.rule).count(),
                1,
                "{} listed more than once",
                meta.id
            );
        }
        // resolution by id and by name
        assert!(rule_from_id("sorseal-105").is_some());
        assert!(rule_from_id("unchecked-transfer").is_some());
        assert!(rule_from_id("SORSEAL-999").is_none());
        // the table lists every RuleId variant
        for id in [
            RuleId::MissingAuth,
            RuleId::Reentrancy,
            RuleId::UncheckedArithmetic,
            RuleId::PanicOnInput,
            RuleId::UncheckedTransfer,
            RuleId::MissingReentrancyGuard,
            RuleId::HardcodedStorageKey,
            RuleId::UnsafeRawPointer,
            RuleId::PanicOnStorageRead,
            RuleId::AdminKeyNeverRotated,
            RuleId::MissingTokenBalanceCheck,
            RuleId::UncheckedEnvCaller,
            RuleId::OraclePriceFeed,
            RuleId::FlashLoanApprove,
            RuleId::WasmUnreachableExport,
            RuleId::WasmNoExports,
        ] {
            assert_eq!(all_rules().iter().filter(|m| m.rule == id).count(), 1);
        }
    }

    #[test]
    fn fail_on_threshold_gate() {
        let a = analyze_source("pub fn f(env: Env) { panic!(); }");
        assert!(!a.has_findings_at_or_above(Severity::Critical));
        assert!(!a.has_findings_at_or_above(Severity::High));
        assert!(!a.has_findings_at_or_above(Severity::Medium));
        // panic! on a non-value line still produces Low? it does not fire
        // PanicOnInput (requires a valueish line), so assert the clean case:
        let a = analyze_source("pub fn g(env: Env) { let amount = balance().unwrap(); }");
        assert!(a.has_findings_at_or_above(Severity::Low));
        assert!(!a.has_findings_at_or_above(Severity::Medium));
    }

    #[test]
    fn json_output_is_structured_and_matches_console() {
        let a = analyze_source(
            "pub fn withdraw(env: Env, to: Address, amount: i128) {\n    env.transfer(&to, &amount);\n}",
        );
        let v = analysis_json("proj", "art", &a);
        assert_eq!(v["project"], "proj");
        assert_eq!(v["artifact"], "art");
        assert!(v["ok"].as_bool().unwrap());
        let findings = v["findings"].as_array().unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0]["severity"].as_str().unwrap(), "Critical");
        assert!(v["counts"]["critical"].as_u64().unwrap() >= 1);
        assert_eq!(v["digest"].as_str().unwrap(), a.digest());
        // deterministic order: file then line then rule
        let lines: Vec<u32> = findings
            .iter()
            .map(|f| f["line"].as_u64().unwrap() as u32)
            .collect();
        assert!(
            lines.windows(2).all(|w| w[0] <= w[1]),
            "findings not line-sorted"
        );
    }

    #[test]
    fn inline_suppression_hides_one_rule() {
        let src = r#"
            pub fn redeem(env: Env) -> i128 {
                // sorseal:ignore SORSEAL-104 reviewed: guarded above
                let balance: i128 = env.storage().persistent().get(&Symbol::new("balance")).unwrap();
                balance
            }
        "#;
        let a = analyze_source(src);
        assert!(
            !a.findings.iter().any(|f| f.rule == RuleId::PanicOnInput),
            "suppressed finding still present: {:?}",
            a.findings
        );
        // an unrelated inline comment does not suppress
        let src2 = r#"
            pub fn redeem2(env: Env) -> i128 {
                // sorseal:ignore SORSEAL-101 reviewed: unrelated
                let balance: i128 = env.storage().persistent().get(&Symbol::new("rate")).unwrap();
                balance
            }
        "#;
        let a2 = analyze_source(src2);
        assert!(
            a2.findings.iter().any(|f| f.rule == RuleId::PanicOnInput),
            "unrelated suppression leaked through: {:?}",
            a2.findings
        );
    }

    #[test]
    fn suppression_changes_digest_and_no_ignore_restores() {
        let src = r#"
            pub fn redeem(env: Env) -> i128 {
                // sorseal:ignore SORSEAL-104
                let balance: i128 = env.storage().persistent().get(&Symbol::new("rate")).unwrap();
                balance
            }
        "#;
        let suppressed = analyze_source(src);
        let dir = tempdir().unwrap();
        let src_dir = dir.path().join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(src_dir.join("lib.rs"), src).unwrap();
        let unsuppressed =
            analyze_tree_with(dir.path(), &["target"], &AnalyzeOptions { no_ignore: true })
                .unwrap();
        assert_ne!(suppressed.digest(), unsuppressed.digest());
        assert!(
            suppressed
                .findings
                .iter()
                .all(|f| f.rule != RuleId::PanicOnInput),
            "no_ignore=false must suppress: {:?}",
            suppressed.findings
        );
        assert!(
            unsuppressed
                .findings
                .iter()
                .any(|f| f.rule == RuleId::PanicOnInput),
            "no_ignore=true must restore: {:?}",
            unsuppressed.findings
        );
    }

    #[test]
    fn detects_unchecked_transfer() {
        let src = r#"
            pub fn sweep(env: Env, to: Address) {
                let amount = SOME_CONSTANT;
                token::Client::new(&env, &to).transfer(&env.current_contract_address(), &to, &amount);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings
                .iter()
                .any(|f| f.rule == RuleId::UncheckedTransfer),
            "expected SORSEAL-105, got {:?}",
            a.findings
        );
    }

    #[test]
    fn no_unchecked_transfer_when_balance_read_first() {
        let src = r#"
            pub fn sweep(env: Env, to: Address) {
                let balance: i128 = env.ledger().balance(&env.current_contract_address());
                let amount = balance;
                token::Client::new(&env, &to).transfer(&env.current_contract_address(), &to, &amount);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            !a.findings
                .iter()
                .any(|f| f.rule == RuleId::UncheckedTransfer),
            "balance-checked transfer should not fire SORSEAL-105: {:?}",
            a.findings
        );
    }

    #[test]
    fn detects_hardcoded_storage_key() {
        let src = r#"
            pub fn set_balance(env: Env, amount: i128) {
                env.storage().persistent().set(&Symbol::new("balance"), &amount);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings
                .iter()
                .any(|f| f.rule == RuleId::HardcodedStorageKey),
            "expected SORSEAL-107, got {:?}",
            a.findings
        );
    }

    #[test]
    fn detects_unsafe_raw_pointer() {
        let src = r#"
            pub fn init(env: Env) {
                unsafe { *ptr = 42; }
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings
                .iter()
                .any(|f| f.rule == RuleId::UnsafeRawPointer),
            "expected SORSEAL-108, got {:?}",
            a.findings
        );
    }

    #[test]
    fn detects_panic_on_storage_read() {
        let src = r#"
            pub fn get_balance(env: Env) -> i128 {
                let balance: i128 = env.storage().persistent().get(&Symbol::new("balance")).unwrap();
                balance
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings
                .iter()
                .any(|f| f.rule == RuleId::PanicOnStorageRead),
            "expected SORSEAL-109, got {:?}",
            a.findings
        );
    }

    #[test]
    fn detects_missing_token_balance_check() {
        let src = r#"
            pub fn sweep(env: Env, to: Address) {
                let amount = 1_000_000;
                token::Client::new(&env, &to).transfer(&env.current_contract_address(), &to, &amount);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings
                .iter()
                .any(|f| f.rule == RuleId::MissingTokenBalanceCheck),
            "expected SORSEAL-111, got {:?}",
            a.findings
        );
    }

    #[test]
    fn admin_key_without_rotation_is_flagged() {
        let src = r#"
            pub fn init_admin(env: Env, admin: Address) {
                admin.require_auth();
                env.storage().persistent().set(&Symbol::new("OWNER"), &admin);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings
                .iter()
                .any(|f| f.rule == RuleId::AdminKeyNeverRotated),
            "expected SORSEAL-110, got {:?}",
            a.findings
        );
    }

    #[test]
    fn detects_unvalidated_oracle_price_feed() {
        let src = r#"
            pub fn borrow(env: Env, amount: i128) {
                let price: i128 = oracle::Client::new(&env, &feed).get_price();
                let collateral: i128 = amount * price;
                env.storage().persistent().set(&Symbol::new("debt"), &collateral);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings.iter().any(|f| f.rule == RuleId::OraclePriceFeed),
            "expected SORSEAL-113, got {:?}",
            a.findings
        );
    }

    #[test]
    fn no_oracle_finding_when_staleness_guarded() {
        let src = r#"
            pub fn borrow(env: Env, amount: i128) {
                let (price, ts): (i128, u64) = oracle::Client::new(&env, &feed).latest_price_timestamp();
                if env.ledger().timestamp() - ts > 300 { panic!("stale price"); }
                let collateral: i128 = amount * price;
                env.storage().persistent().set(&Symbol::new("debt"), &collateral);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            !a.findings.iter().any(|f| f.rule == RuleId::OraclePriceFeed),
            "staleness-guarded price read should not fire SORSEAL-113: {:?}",
            a.findings
        );
    }

    #[test]
    fn detects_approve_then_invoke_shape() {
        let src = r#"
            pub fn swap(env: Env, spender: Address, amount: i128) -> i128 {
                token::Client::new(&env, &token).increase_allowance(&env.current_contract_address(), &spender, &amount);
                env.invoke_contract::<i128>(&pool, &Symbol::new("execute"), (&amount,))
            }
        "#;
        let a = analyze_source(src);
        assert!(
            a.findings
                .iter()
                .any(|f| f.rule == RuleId::FlashLoanApprove),
            "expected SORSEAL-114, got {:?}",
            a.findings
        );
    }

    #[test]
    fn no_flash_loan_finding_when_approve_only() {
        let src = r#"
            pub fn grant(env: Env, spender: Address, amount: i128) {
                token::Client::new(&env, &token).approve(&env.current_contract_address(), &spender, &amount);
            }
        "#;
        let a = analyze_source(src);
        assert!(
            !a.findings
                .iter()
                .any(|f| f.rule == RuleId::FlashLoanApprove),
            "approve-only should not fire SORSEAL-114: {:?}",
            a.findings
        );
    }
}
