//! Console, JSON, and Markdown rendering.

use crate::drift;
use crate::provenance::Provenance;
use crate::runner::{short, Check, Outcome};

/// Render the `verify` output in a pytest-style summary.
pub fn render_verify(project: &str, checks: &[Check]) -> String {
    let mut lines = vec![format!("Sorseal — {project} verify"), String::new()];
    for c in checks {
        lines.push(format!(
            "{}  {} :: {} — {}",
            c.outcome.label(),
            c.artifact,
            c.check,
            c.detail
        ));
    }
    lines.push(String::new());
    let passed = checks.iter().filter(|c| c.outcome == Outcome::Pass).count();
    let failed = checks.iter().filter(|c| c.outcome == Outcome::Fail).count();
    let errored = checks
        .iter()
        .filter(|c| c.outcome == Outcome::Error)
        .count();
    lines.push(format!(
        "{} checks: {passed} passed, {failed} failed, {errored} errored",
        checks.len()
    ));
    lines.join("\n")
}

/// Render the sealed digests (used by `record` and `report --format console`).
pub fn render_sealed(project: &str, p: &Provenance) -> String {
    let mut lines = vec![format!("Sorseal — {project}"), String::new()];
    for a in &p.artifacts {
        lines.push(format!(
            "sealed  {} :: wasm  sha256 {} ({} bytes)",
            a.id,
            short(&a.wasm_sha256),
            a.wasm_size
        ));
        lines.push(format!(
            "sealed  {} :: source sha256 {}",
            a.id,
            short(&a.source_sha256)
        ));
    }
    lines.push(String::new());
    let git = if p.git.present {
        if p.git.clean {
            format!("git commit {} (clean)", short(&p.git.commit))
        } else {
            format!("git commit {} (dirty)", short(&p.git.commit))
        }
    } else {
        "not a git repository".to_string()
    };
    lines.push(format!("toolchain {} · {git}", p.toolchain));
    lines.join("\n")
}

/// Render a drift comparison as a pytest-style summary, matching the
/// `verify` output shape: header, per-difference lines, blank, totals.
pub fn render_drift(r: &drift::DriftReport) -> String {
    let mut lines = vec![
        format!("Sorseal — {} drift", r.project),
        String::new(),
        format!("  left   {}", r.left),
        format!("  right  {}", r.right),
        String::new(),
    ];

    for c in &r.context {
        lines.push(format!("CONTEXT  {}  {} → {}", c.field, c.left, c.right));
    }
    if !r.context.is_empty() {
        lines.push(String::new());
    }

    for e in &r.entries {
        let label = match e.status {
            drift::Status::Added => "ADDED  ",
            drift::Status::Removed => "REMOVED",
            drift::Status::Changed => "CHANGED",
        };
        lines.push(format!("{label}  {}", e.id));
        for f in &e.fields {
            lines.push(format!("         {}  {} → {}", f.field, f.left, f.right));
        }
    }

    lines.push(String::new());
    if r.identical {
        lines.push("NO DRIFT — the two records match".to_string());
    } else {
        let total = r.counts.added + r.counts.removed + r.counts.changed + r.counts.context;
        let noun = if total == 1 {
            "difference"
        } else {
            "differences"
        };
        lines.push(format!(
            "{total} {noun} — added: {} · removed: {} · changed: {} · context: {}",
            r.counts.added, r.counts.removed, r.counts.changed, r.counts.context
        ));
        lines.push("DRIFT DETECTED".to_string());
    }
    lines.join("\n")
}

/// Markdown report for the Wave deliverable / audit trail.
pub fn render_markdown(p: &Provenance) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Provenance: {}\n\n", md_escape(&p.project)));
    out.push_str(&format!("- toolchain: `{}`\n", p.toolchain));
    if p.git.present {
        out.push_str(&format!(
            "- git commit: `{}` (clean: {})\n",
            p.git.commit, p.git.clean
        ));
    } else {
        out.push_str("- git commit: _not a git repository_\n");
    }
    out.push_str("- format: `sorseal-provenance` v1\n");
    out.push_str("\n| artifact | wasm sha256 | size | source sha256 |\n|---|---|---|---|\n");
    for a in &p.artifacts {
        out.push_str(&format!(
            "| {} | `{}` | {} | `{}` |\n",
            md_escape(&a.id),
            a.wasm_sha256,
            a.wasm_size,
            a.source_sha256
        ));
    }
    out
}

/// Escape a user-controlled string for use inside a markdown table cell.
///
/// The following characters are neutralised so that a single cell can never
/// span multiple lines or inject code spans:
///
/// - `|`       → `\|`  (prevents a premature column separator)
/// - backtick  → `\``  (prevents an unintended code span)
/// - `\n`/`\r` → `↵`    (prevents a line break that would split the table row)
fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('`', "\\`")
        .replace(['\n', '\r'], "↵")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{ArtifactProvenance, GitState};
    use crate::runner::Check;

    fn check(outcome: Outcome, detail: &str) -> Check {
        Check {
            artifact: "echo.wasm".into(),
            check: "wasm_hash".into(),
            outcome,
            detail: detail.into(),
        }
    }

    fn provenance() -> Provenance {
        Provenance {
            format: crate::provenance::FORMAT.to_string(),
            version: 1,
            project: "demo|project".into(),
            toolchain: "rustc 1.95.0".into(),
            git: GitState {
                present: true,
                commit: "a".repeat(40),
                clean: true,
            },
            artifacts: vec![ArtifactProvenance {
                id: "echo".into(),
                command: "cargo build".into(),
                wasm_path: "x.wasm".into(),
                wasm_sha256: "f".repeat(64),
                wasm_size: 42,
                source_root: ".".into(),
                source_sha256: "e".repeat(64),
                built_at: "2026-01-01T00:00:00Z".into(),
            }],
            analysis: Vec::new(),
        }
    }

    #[test]
    fn render_verify_summarizes_outcomes() {
        let checks = vec![
            check(Outcome::Pass, "match"),
            check(Outcome::Fail, "mismatch"),
            check(Outcome::Error, "timeout"),
        ];
        let out = render_verify("demo", &checks);
        assert!(out.starts_with("Sorseal — demo verify"));
        assert!(out.contains("PASSED  echo.wasm :: wasm_hash — match"));
        assert!(out.contains("FAILED  echo.wasm :: wasm_hash — mismatch"));
        assert!(out.contains("ERROR   echo.wasm :: wasm_hash — timeout"));
        assert!(out.contains("3 checks: 1 passed, 1 failed, 1 errored"));
    }

    #[test]
    fn render_verify_zero_checks() {
        assert!(render_verify("demo", &[]).contains("0 checks: 0 passed, 0 failed, 0 errored"));
    }

    #[test]
    fn render_sealed_shows_short_digests_and_git_state() {
        let out = render_sealed("demo", &provenance());
        assert!(out.starts_with("Sorseal — demo"));
        assert!(out.contains("sealed  echo :: wasm  sha256 ffffffffffff (42 bytes)"));
        assert!(out.contains(&format!("git commit {} (clean)", "a".repeat(12))));
    }

    #[test]
    fn render_sealed_notes_missing_git() {
        let mut p = provenance();
        p.git.present = false;
        assert!(render_sealed("demo", &p).contains("not a git repository"));
    }

    #[test]
    fn render_markdown_escapes_pipes_in_user_input() {
        let out = render_markdown(&provenance());
        assert!(out.starts_with("# Provenance: demo\\|project"));
        assert!(out.contains("| echo | `"));
        assert!(out
            .contains("`ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | 42 |"));
    }

    #[test]
    fn render_markdown_without_git() {
        let mut p = provenance();
        p.git.present = false;
        assert!(render_markdown(&p).contains("git commit: _not a git repository_"));
    }

    #[test]
    fn render_drift_identical_says_no_drift() {
        let r = drift::compare(
            &subject(provenance()),
            &subject(provenance()),
            "a.json",
            "b.json",
        );
        let out = render_drift(&r);
        assert!(out.starts_with("Sorseal — demo|project drift"));
        assert!(out.contains("NO DRIFT"));
        assert!(!out.contains("DRIFT DETECTED"));
        assert!(out.contains("  left   a.json"));
        assert!(out.contains("  right  b.json"));
    }

    #[test]
    fn render_drift_sums_and_labels_a_change() {
        let mut b = provenance();
        b.artifacts[0].wasm_sha256 = "0".repeat(64);
        b.toolchain = "rustc 1.96.0".into();
        let r = drift::compare(&subject(provenance()), &subject(b), "a", "b");
        let out = render_drift(&r);
        assert!(out.contains("CHANGED  echo"));
        assert!(out.contains("wasm_sha256  "));
        assert!(out.contains("CONTEXT  toolchain  rustc 1.95.0 → rustc 1.96.0"));
        assert!(out.contains("DRIFT DETECTED"));
        // One changed entry plus one context difference = two differences.
        assert!(out.contains("2 differences — added: 0 · removed: 0 · changed: 1 · context: 1"));
    }

    #[test]
    fn render_drift_pluralises_totals() {
        // A single difference is singular.
        let mut one = provenance();
        one.artifacts[0].wasm_sha256 = "0".repeat(64);
        let out = render_drift(&drift::compare(
            &subject(provenance()),
            &subject(one),
            "a",
            "b",
        ));
        assert!(out.contains("1 difference — added: 0 · removed: 0 · changed: 1 · context: 0"));

        // Two changed artifacts are plural.
        let mut two = provenance();
        two.artifacts[0].wasm_sha256 = "0".repeat(64);
        let mut extra = two.artifacts[0].clone();
        extra.id = "second".into();
        extra.wasm_sha256 = "1".repeat(64);
        two.artifacts.push(extra);
        let out2 = render_drift(&drift::compare(
            &subject(provenance()),
            &subject(two),
            "a",
            "b",
        ));
        assert!(out2.contains("2 differences — added: 1 · removed: 0 · changed: 1 · context: 0"));
    }

    #[test]
    fn render_drift_marks_added_and_removed() {
        let mut with_extra = provenance();
        let mut second = with_extra.artifacts[0].clone();
        second.id = "second".into();
        with_extra.artifacts.push(second);
        let r = drift::compare(
            &subject(provenance()),
            &subject(with_extra.clone()),
            "a",
            "b",
        );
        let out = render_drift(&r);
        assert!(out.contains("ADDED    second"));
        assert!(out.contains("(absent) → "));

        let r2 = drift::compare(&subject(with_extra), &subject(provenance()), "a", "b");
        assert!(render_drift(&r2).contains("REMOVED  second"));
    }

    fn subject(p: Provenance) -> drift::Subject {
        drift::Subject::Provenance(p)
    }

    #[test]
    fn md_escape_escapes_pipes() {
        assert_eq!(md_escape("a|b"), "a\\|b");
        assert_eq!(md_escape("plain"), "plain");
        assert_eq!(md_escape("|||"), "\\|\\|\\|");
    }

    #[test]
    fn md_escape_escapes_backticks() {
        assert_eq!(md_escape("a`b"), "a\\`b");
        assert_eq!(md_escape("`code`"), "\\`code\\`");
    }

    #[test]
    fn md_escape_neutralises_newlines() {
        assert_eq!(md_escape("a\nb"), "a↵b");
        assert_eq!(md_escape("a\rb"), "a↵b");
        assert_eq!(md_escape("a\r\nb"), "a↵↵b");
    }

    #[test]
    fn md_escape_handles_combined_threats() {
        // A project name that would break the table: pipe, newline, backtick
        let evil = "evil|project\n`rm -rf`";
        let escaped = md_escape(evil);
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
        assert_eq!(escaped, "evil\\|project↵\\`rm -rf\\`");
    }

    #[test]
    fn render_markdown_newline_project_stays_single_row() {
        let mut p = provenance();
        p.project = "evil\nproject".into();
        let out = render_markdown(&p);
        // The header line must contain the placeholder, not a raw newline
        assert!(out.starts_with("# Provenance: evil↵project"));
        // No line in the output should be just "project" (injected row)
        for line in out.lines() {
            assert!(!line.starts_with("project|"));
        }
    }
}
