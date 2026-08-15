//! Console, JSON, and Markdown rendering.

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
