//! `record` and `verify` — build artifacts, hash them, and compare against a
//! sealed provenance record.

use crate::clock;
use crate::digest;
use crate::git;
use crate::manifest::Manifest;
use crate::provenance::{ArtifactProvenance, Provenance};
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    Error,
}

impl Outcome {
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Pass => "PASSED",
            Outcome::Fail => "FAILED",
            Outcome::Error => "ERROR ",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub artifact: String,
    pub check: String,
    pub outcome: Outcome,
    pub detail: String,
}

/// The compiler toolchain, for the provenance record.
pub fn toolchain() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn run_build(base: &Path, command: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(base)
        .status()
        .with_context(|| format!("failed to spawn build command: {command}"))?;
    if !status.success() {
        bail!("build command exited with {status}: {command}");
    }
    Ok(())
}

/// Builds every artifact and returns a fresh provenance record.
///
/// Refuses to seal a dirty working tree unless `allow_dirty` is set — a record
/// is only meaningful if it describes the exact committed source.
pub fn record(manifest: &Manifest, base: &Path, allow_dirty: bool) -> Result<Provenance> {
    let gs = git::git_state(base)?;
    if gs.present && !gs.clean && !allow_dirty {
        bail!(
            "working tree has uncommitted changes; commit first or pass --allow-dirty \
             (a sealed record must describe the exact committed source)"
        );
    }

    let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
    for a in &manifest.artifacts {
        run_build(base, &a.build_command)
            .with_context(|| format!("artifact '{}': build failed", a.id))?;

        let wasm_abs = base.join(&a.wasm_path);
        if !wasm_abs.exists() {
            bail!(
                "artifact '{}': wasm file not found after build: {}",
                a.id,
                a.wasm_path.display()
            );
        }
        let wasm_sha256 = digest::file_sha256(&wasm_abs).with_context(|| {
            format!(
                "artifact '{}': failed to hash {}",
                a.id,
                a.wasm_path.display()
            )
        })?;
        let wasm_size = std::fs::metadata(&wasm_abs)?.len();

        let source_abs = base.join(&a.source_root);
        if !source_abs.is_dir() {
            bail!(
                "artifact '{}': source_root is not a directory: {}",
                a.id,
                a.source_root.display()
            );
        }
        let source_sha256 = digest::tree_sha256(&source_abs)
            .with_context(|| format!("artifact '{}': failed to hash source tree", a.id))?;

        artifacts.push(ArtifactProvenance {
            id: a.id.clone(),
            command: a.build_command.clone(),
            wasm_path: a.wasm_path.display().to_string(),
            wasm_sha256,
            wasm_size,
            source_root: a.source_root.display().to_string(),
            source_sha256,
            built_at: clock::now_rfc3339_utc(),
        });
    }

    Ok(Provenance {
        format: crate::provenance::FORMAT.to_string(),
        version: crate::provenance::VERSION,
        project: manifest.project.name.clone(),
        toolchain: toolchain(),
        git: gs,
        artifacts,
    })
}

/// Rebuilds every artifact and checks it against the sealed provenance.
/// Returns the checks plus whether all of them passed.
pub fn verify(
    manifest: &Manifest,
    provenance: &Provenance,
    base: &Path,
) -> Result<(Vec<Check>, bool)> {
    let mut checks = Vec::new();

    if provenance.project != manifest.project.name {
        checks.push(Check {
            artifact: "project".into(),
            check: "name".into(),
            outcome: Outcome::Fail,
            detail: format!(
                "manifest project '{}' does not match sealed provenance project '{}'",
                manifest.project.name, provenance.project
            ),
        });
    } else {
        checks.push(Check {
            artifact: "project".into(),
            check: "name".into(),
            outcome: Outcome::Pass,
            detail: format!(
                "manifest project '{}' matches sealed provenance",
                manifest.project.name
            ),
        });
    }

    // git: the sealed commit must be reachable from the current checkout. The
    // sealed commit is captured before the provenance file exists, so after
    // recording and committing the seal the HEAD will have moved on; the check
    // therefore requires the sealed commit to be an ancestor of (or equal to)
    // HEAD. Byte-level source equality is enforced separately by the source
    // tree digest.
    if provenance.git.present {
        let gs = git::git_state(base)?;
        let ok = gs.present && git::contains(base, &provenance.git.commit).unwrap_or(false);
        let detail = if !gs.present {
            format!(
                "provenance was sealed at commit {} but this tree is not a git repository",
                short(&provenance.git.commit)
            )
        } else if gs.commit == provenance.git.commit {
            format!(
                "HEAD matches sealed commit {}",
                short(&provenance.git.commit)
            )
        } else if ok {
            format!(
                "sealed commit {} is reachable from HEAD {}",
                short(&provenance.git.commit),
                short(&gs.commit)
            )
        } else {
            format!(
                "sealed commit {} is not reachable from current HEAD {}",
                short(&provenance.git.commit),
                short(&gs.commit)
            )
        };
        checks.push(Check {
            artifact: "git".into(),
            check: "commit".into(),
            outcome: if ok { Outcome::Pass } else { Outcome::Fail },
            detail,
        });
    }

    // Any artifact the manifest declares but the seal does not cover is a gap:
    // it would be built and released without provenance. Fail rather than
    // silently verifying only the subset that was recorded.
    let sealed_ids: std::collections::HashSet<&str> =
        provenance.artifacts.iter().map(|a| a.id.as_str()).collect();
    for ma in &manifest.artifacts {
        if !sealed_ids.contains(ma.id.as_str()) {
            checks.push(Check {
                artifact: ma.id.clone(),
                check: "sealed".into(),
                outcome: Outcome::Error,
                detail: format!(
                    "manifest artifact '{}' has no entry in the sealed provenance; run `sorseal record` to seal it",
                    ma.id
                ),
            });
        }
    }

    for art in &provenance.artifacts {
        let Some(ma) = manifest.artifacts.iter().find(|m| m.id == art.id) else {
            checks.push(Check {
                artifact: art.id.clone(),
                check: "manifest".into(),
                outcome: Outcome::Error,
                detail: "sealed artifact has no matching [[artifacts]] entry in sorseal.toml"
                    .into(),
            });
            continue;
        };

        // The seal is only truthful if the build still uses the command that
        // produced it. A changed build_command would make the record describe
        // a different build, even when the bytecode happens to be identical.
        if ma.build_command != art.command {
            checks.push(Check {
                artifact: art.id.clone(),
                check: "command".into(),
                outcome: Outcome::Fail,
                detail: format!(
                    "manifest build_command '{}' no longer matches sealed command '{}'; re-run `sorseal record` to re-seal",
                    ma.build_command, art.command
                ),
            });
        }

        if let Err(e) = run_build(base, &ma.build_command) {
            checks.push(Check {
                artifact: art.id.clone(),
                check: "build".into(),
                outcome: Outcome::Error,
                detail: format!("rebuild failed: {e:#}"),
            });
            continue;
        }

        let wasm_abs = base.join(&ma.wasm_path);
        if !wasm_abs.exists() {
            checks.push(Check {
                artifact: art.id.clone(),
                check: "wasm".into(),
                outcome: Outcome::Error,
                detail: format!(
                    "wasm file not found after rebuild: {}",
                    ma.wasm_path.display()
                ),
            });
            continue;
        }
        let rebuilt = digest::file_sha256(&wasm_abs)?;
        if rebuilt == art.wasm_sha256 {
            checks.push(Check {
                artifact: art.id.clone(),
                check: "wasm".into(),
                outcome: Outcome::Pass,
                detail: format!("sha256 matches sealed digest {}", short(&art.wasm_sha256)),
            });
        } else {
            checks.push(Check {
                artifact: art.id.clone(),
                check: "wasm".into(),
                outcome: Outcome::Fail,
                detail: format!(
                    "sha256 mismatch: rebuilt {}, sealed {}",
                    short(&rebuilt),
                    short(&art.wasm_sha256)
                ),
            });
        }

        let source_abs = base.join(&ma.source_root);
        let rebuilt_src = digest::tree_sha256(&source_abs)?;
        if rebuilt_src == art.source_sha256 {
            checks.push(Check {
                artifact: art.id.clone(),
                check: "source".into(),
                outcome: Outcome::Pass,
                detail: format!(
                    "source tree matches sealed digest {}",
                    short(&art.source_sha256)
                ),
            });
        } else {
            checks.push(Check {
                artifact: art.id.clone(),
                check: "source".into(),
                outcome: Outcome::Fail,
                detail: format!(
                    "source tree digest mismatch: rebuilt {}, sealed {}",
                    short(&rebuilt_src),
                    short(&art.source_sha256)
                ),
            });
        }
    }

    let all_pass = checks.iter().all(|c| c.outcome == Outcome::Pass);
    Ok((checks, all_pass))
}

/// First 12 hex chars of a digest, for readable output.
pub fn short(hex: &str) -> String {
    if hex.len() > 12 {
        hex[..12].to_string()
    } else {
        hex.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_truncates() {
        assert_eq!(short("abcdef0123456789"), "abcdef012345");
        assert_eq!(short("abc"), "abc");
    }

    #[test]
    fn outcome_labels() {
        assert_eq!(Outcome::Pass.label(), "PASSED");
        assert_eq!(Outcome::Fail.label(), "FAILED");
        assert_eq!(Outcome::Error.label(), "ERROR ");
    }
}
