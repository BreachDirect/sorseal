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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A temp-dir that is itself a fresh git repo.
    fn git_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let status = Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .arg("init")
            .output()
            .unwrap()
            .status;
        assert!(status.success(), "git init failed in {:?}", dir.path());
        dir
    }

    /// Commit a file so HEAD exists; returns the commit hex.
    fn initial_commit(dir: &std::path::Path, name: &str) -> String {
        std::fs::write(dir.join(name), name).unwrap();
        let ok = Command::new("git")
            .current_dir(dir)
            .args(["add", name])
            .output()
            .unwrap();
        assert!(ok.status.success());
        let ok = Command::new("git")
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .args(["commit", "-m", "initial"])
            .output()
            .unwrap();
        assert!(ok.status.success(), "commit failed");
        String::from_utf8_lossy(
            &Command::new("git")
                .current_dir(dir)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .trim()
        .to_string()
    }

    #[test]
    fn git_state_present_in_clean_repo() {
        let dir = git_tempdir();
        initial_commit(dir.path(), "a.txt");
        let state = git_state(dir.path()).unwrap();
        assert!(state.present);
        assert!(!state.commit.is_empty());
        assert!(state.clean);
    }

    #[test]
    fn git_state_reports_dirty_tree() {
        let dir = git_tempdir();
        initial_commit(dir.path(), "a.txt");
        std::fs::write(dir.path().join("a.txt"), "changed").unwrap();
        let state = git_state(dir.path()).unwrap();
        assert!(state.present);
        assert!(!state.clean);
    }

    #[test]
    fn git_state_absent_outside_repo() {
        let dir = tempfile::tempdir().unwrap();
        let state = git_state(dir.path()).unwrap();
        assert!(!state.present);
        assert!(state.commit.is_empty());
        assert!(!state.clean);
    }

    #[test]
    fn contains_true_for_reachable_commit() {
        let dir = git_tempdir();
        let head = initial_commit(dir.path(), "a.txt");
        assert!(contains(dir.path(), &head).unwrap());
    }

    #[test]
    fn contains_false_for_unknown_commit() {
        let dir = git_tempdir();
        initial_commit(dir.path(), "a.txt");
        assert!(!contains(dir.path(), "0000000000000000000000000000000000000000").unwrap());
    }

    #[test]
    fn contains_false_and_reports_error_outside_repo() {
        let dir = tempfile::tempdir().unwrap();
        // Outside a repo git errors on stderr; contains maps that to Ok(false).
        assert!(!contains(dir.path(), "abc").unwrap());
    }
}
