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
fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
}
