//! Read-only helpers for the enclosing git repository (if any).

use crate::provenance::GitState;
use std::path::Path;
use std::process::Command;

fn git_output(cwd: &Path, args: &[&str]) -> Result<String, std::io::Error> {
    let out = Command::new("git").args(args).current_dir(cwd).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(std::io::Error::other("git command failed"))
    }
}

/// Capture the current commit and cleanliness, if the project is a git repo.
/// Non-repositories yield `present: false` so git checks are skipped cleanly.
pub fn git_state(cwd: &Path) -> GitState {
    match git_output(cwd, &["rev-parse", "HEAD"]) {
        Ok(commit) => {
            let commit = commit.trim().to_string();
            let clean = git_output(cwd, &["status", "--porcelain"])
                .map(|s| s.trim().is_empty())
                .unwrap_or(false);
            GitState {
                present: true,
                commit,
                clean,
            }
        }
        Err(_) => GitState {
            present: false,
            commit: String::new(),
            clean: false,
        },
    }
}

/// Whether `commit` is reachable from (or equal to) the current HEAD.
/// Returns `Err` only if git itself fails; a missing commit object is `false`.
pub fn contains(cwd: &Path, commit: &str) -> Result<bool, std::io::Error> {
    let out = Command::new("git")
        .args(["merge-base", "--is-ancestor", commit, "HEAD"])
        .current_dir(cwd)
        .output()?;
    Ok(out.status.success())
}
