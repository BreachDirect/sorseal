//! Read-only helpers for the enclosing git repository (if any).

use crate::provenance::GitState;
use anyhow::{anyhow, bail, Result};
use std::path::Path;
use std::process::Command;

fn git_output(cwd: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git").args(args).current_dir(cwd).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(anyhow!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Capture the current commit and cleanliness. Non-repositories yield
/// `present: false` so git checks are skipped cleanly. A `.git` marker with a
/// failing git command is an error: sealing without commit/cleanliness
/// information would silently downgrade the record's integrity.
pub fn git_state(cwd: &Path) -> Result<GitState> {
    let marker = cwd.join(".git");
    match git_output(cwd, &["rev-parse", "HEAD"]) {
        Ok(commit) => {
            let commit = commit.trim().to_string();
            let clean = git_output(cwd, &["status", "--porcelain"])?
                .trim()
                .is_empty();
            Ok(GitState {
                present: true,
                commit,
                clean,
            })
        }
        Err(e) if marker.exists() => bail!(
            "git repository detected ({} exists) but `git rev-parse HEAD` failed: {e:#}",
            marker.display()
        ),
        Err(_) => Ok(GitState {
            present: false,
            commit: String::new(),
            clean: false,
        }),
    }
}

/// Whether `commit` is reachable from (or equal to) the current HEAD.
/// Returns `false` if the commit object is missing; errors only if git itself
/// cannot be spawned.
pub fn contains(cwd: &Path, commit: &str) -> Result<bool> {
    let out = Command::new("git")
        .args(["merge-base", "--is-ancestor", commit, "HEAD"])
        .current_dir(cwd)
        .output()?;
    Ok(out.status.success())
}
