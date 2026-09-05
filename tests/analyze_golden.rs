//! Golden-file test for `sorseal analyze` on the bundled vulnerable contract.
//!
//! The finding set and analysis digest for `examples/vulnerable-contract` are
//! locked to a checked-in golden JSON. Any rule change that alters which
//! findings are reported (or the digest) fails this test, protecting the
//! stable/tamper-evident digest guarantee.
//!
//! Regenerate the golden deliberately with:
//!
//!     SORSEAL_UPDATE_GOLDEN=1 cargo test --test analyze_golden

use std::process::Command;

const GOLDEN_REL: &str = "tests/fixtures/analyze/vulnerable-contract.golden.json";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sorseal")
}

fn repo_root() -> std::path::PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

use std::path::PathBuf;

/// Canonical, diff-friendly repr of a finding: `RULE Severity file:line`.
fn line(f: &serde_json::Value) -> String {
    format!(
        "{} {} {}:{}",
        f["rule"].as_str().unwrap_or("?"),
        f["severity"].as_str().unwrap_or("?"),
        f["file"].as_str().unwrap_or("?"),
        f["line"].as_u64().unwrap_or(0)
    )
}

#[test]
fn analyze_matches_golden_findings_and_digest() {
    let fixture = repo_root().join("examples/vulnerable-contract");
    let out = Command::new(bin())
        .args(["analyze", "--format", "json", "--ignore", "target"])
        .current_dir(&fixture)
        .output()
        .expect("failed to run sorseal analyze");
    assert!(
        out.status.success(),
        "analyze unexpectedly failed:\n{}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let actual: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("analyze --format json output is valid JSON");
    let golden_path = repo_root().join(GOLDEN_REL);

    if std::env::var_os("SORSEAL_UPDATE_GOLDEN").is_some() {
        std::fs::write(&golden_path, format!("{actual}\n")).expect("failed to write golden file");
        eprintln!("golden updated: {}", golden_path.display());
        return;
    }

    let golden_text =
        std::fs::read_to_string(&golden_path).expect("golden file should exist in the repo");
    let golden: serde_json::Value =
        serde_json::from_str(&golden_text).expect("golden file should be valid JSON");

    let actual_findings = &actual["artifacts"][0]["findings"];
    let golden_findings = &golden["artifacts"][0]["findings"];

    let actual_lines: Vec<String> = actual_findings
        .as_array()
        .map(|arr| arr.iter().map(line).collect())
        .unwrap_or_default();
    let golden_lines: Vec<String> = golden_findings
        .as_array()
        .map(|arr| arr.iter().map(line).collect())
        .unwrap_or_default();

    let actual_digest = actual["artifacts"][0]["digest"]
        .as_str()
        .unwrap_or("<missing>");
    let golden_digest = golden["artifacts"][0]["digest"]
        .as_str()
        .unwrap_or("<missing>");

    let findings_match = actual_lines == golden_lines;
    let digest_match = actual_digest == golden_digest;

    if !findings_match || !digest_match {
        eprintln!(
            "analyze output no longer matches the golden file ({}).",
            golden_path.display()
        );
        if !findings_match {
            eprintln!("\n--- expected findings ---");
            for l in &golden_lines {
                eprintln!("  {l}");
            }
            eprintln!("--- actual findings ---");
            for l in &actual_lines {
                eprintln!("  {l}");
            }
        }
        if !digest_match {
            eprintln!("\ndigest expected: {golden_digest}");
            eprintln!("digest actual:   {actual_digest}");
        }
        eprintln!(
            "\nIf the change is intentional, regenerate with:\n  \
             SORSEAL_UPDATE_GOLDEN=1 cargo test --test analyze_golden"
        );
        panic!("analyze findings/digest drifted from golden");
    }
}
