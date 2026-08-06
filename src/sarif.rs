//! SARIF 2.1.0 rendering of `verify` results for GitHub code scanning.

use crate::runner::{Check, Outcome};
use serde_json::{json, Value};

pub const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const INFORMATION_URI: &str = "https://github.com/BreachDirect/sorseal";

/// Render `verify` checks as a SARIF 2.1.0 report. Passed checks are omitted;
/// failed checks become `error` results and errored checks `warning`, so a
/// clean verification yields an empty results array (the correct signal for
/// code scanning: no findings).
pub fn render_sarif(project: &str, checks: &[Check]) -> String {
    let results: Vec<Value> = checks
        .iter()
        .filter(|c| c.outcome != Outcome::Pass)
        .map(|c| {
            let level = match c.outcome {
                Outcome::Error => "warning",
                _ => "error",
            };
            json!({
                "ruleId": "SORSEAL/verify",
                "level": level,
                "message": {
                    "text": format!("{} :: {} — {}", c.artifact, c.check, c.detail)
                },
                "properties": {
                    "artifact": c.artifact,
                    "check": c.check,
                    "outcome": c.outcome.label().trim()
                }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sorseal",
                    "fullName": "sorseal — provenance for Soroban/WASM artifacts",
                    "informationUri": INFORMATION_URI,
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": [{
                        "id": "SORSEAL/verify",
                        "name": "provenance-verify",
                        "shortDescription": {
                            "text": "Checks that rebuilt artifacts reproduce the sealed provenance record"
                        },
                        "fullDescription": {
                            "text": format!("Verify results for {project}: rebuilt WASM and source digests must match the sealed sorseal provenance record. Any mismatch or error is reported as a finding.")
                        },
                        "helpUri": format!("{INFORMATION_URI}#provenance-verify"),
                        "properties": {
                            "tags": ["provenance", "reproducible-builds", "soroban"]
                        }
                    }]
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).expect("SARIF is serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{Check, Outcome};

    fn checks() -> Vec<Check> {
        vec![
            Check {
                artifact: "echo".into(),
                check: "wasm".into(),
                outcome: Outcome::Pass,
                detail: "sha256 matches sealed digest abcdef012345".into(),
            },
            Check {
                artifact: "echo".into(),
                check: "wasm".into(),
                outcome: Outcome::Fail,
                detail: "sha256 mismatch: rebuilt 111111111111, sealed 222222222222".into(),
            },
            Check {
                artifact: "escrow".into(),
                check: "build".into(),
                outcome: Outcome::Error,
                detail: "rebuild failed: cargo exited with 101".into(),
            },
        ]
    }

    #[test]
    fn sarif_omits_passes_and_sets_levels() {
        let v: Value = serde_json::from_str(&render_sarif("demo", &checks())).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[0]["ruleId"], "SORSEAL/verify");
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["version"],
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn sarif_clean_verify_has_no_results() {
        let clean: Vec<Check> = vec![Check {
            artifact: "echo".into(),
            check: "wasm".into(),
            outcome: Outcome::Pass,
            detail: "sha256 matches".into(),
        }];
        let v: Value = serde_json::from_str(&render_sarif("demo", &clean)).unwrap();
        assert!(v["runs"][0]["results"].as_array().unwrap().is_empty());
    }
}
