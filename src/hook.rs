//! Pre-commit hook installation — `sorseal hook install|uninstall|status`.
//!
//! Writes a `.git/hooks/pre-commit` script that runs `sorseal verify` and
//! `sorseal analyze --fail-on` before every commit, so provenance and
//! vulnerability drift is caught at the moment a developer tries to commit —
//! not later in CI.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Path (relative to the repo root) for the git pre-commit hook.
pub const PRE_COMMIT_REL: &str = ".git/hooks/pre-commit";

const HOOK_BODY: &str = r#"#!/bin/sh
# sorseal pre-commit hook — auto-installed by `sorseal hook install`.
# Runs `sorseal verify` (provenance) and `sorseal analyze --fail-on High`
# before commit. Set SORSEAL_SKIP_HOOK=1 to bypass temporarily.
set -e

if [ -n "$SORSEAL_SKIP_HOOK" ]; then
  echo "sorseal: SORSEAL_SKIP_HOOK set — skipping checks"
  exit 0
fi

if ! command -v sorseal >/dev/null 2>&1; then
  echo "sorseal: not installed — skipping (cargo install sorseal)"
  exit 0
fi

if [ -f sorseal.toml ] && [ -f sorseal.provenance.json ]; then
  if ! sorseal verify; then
    echo "sorseal: provenance verification failed — re-run \`sorseal record\` if the build changed"
    exit 1
  fi
  if ! sorseal analyze --fail-on High; then
    echo "sorseal: static analysis found Critical/High issues — fix them before committing"
    exit 1
  fi
fi

exit 0
"#;

/// Locate the enclosing git repository root (the directory containing `.git`).
fn git_root(cwd: &Path) -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(cwd)
        .output()
        .map_err(|e| anyhow!("failed to run `git rev-parse` (is git installed?): {e}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "not a git repository (or git unavailable): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(PathBuf::from(root))
}

/// Whether a sorseal pre-commit hook is currently installed at `root`.
pub fn is_installed(root: &Path) -> bool {
    let hook = root.join(PRE_COMMIT_REL);
    hook.exists()
        && std::fs::read_to_string(&hook)
            .map(|s| s.contains("sorseal hook") || s.contains("# sorseal pre-commit hook"))
            .unwrap_or(false)
}

/// Install the pre-commit hook into the current repository.
pub fn install(cwd: &Path) -> Result<PathBuf> {
    let root = git_root(cwd)?;
    let hook = root.join(PRE_COMMIT_REL);
    if is_installed(&root) {
        return Err(anyhow!(
            "a sorseal pre-commit hook is already installed at {}",
            hook.display()
        ));
    }
    if hook.exists() {
        return Err(anyhow!(
            "existing non-sorseal hook at {} — refusing to overwrite (back it up first)",
            hook.display()
        ));
    }
    if let Some(parent) = hook.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&hook, HOOK_BODY)
        .with_context(|| format!("failed to write {}", hook.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to make {} executable", hook.display()))?;
    }
    Ok(hook)
}

/// Remove the sorseal pre-commit hook (no-op when absent).
pub fn uninstall(cwd: &Path) -> Result<()> {
    let root = git_root(cwd)?;
    let hook = root.join(PRE_COMMIT_REL);
    if !is_installed(&root) {
        return Ok(());
    }
    std::fs::remove_file(&hook).with_context(|| format!("failed to remove {}", hook.display()))?;
    Ok(())
}

/// Human-readable status for `sorseal hook status`.
pub fn render_status(cwd: &Path) -> Result<String> {
    let root = git_root(cwd)?;
    let installed = is_installed(&root);
    let hook = root.join(PRE_COMMIT_REL);
    Ok(format!(
        "sorseal pre-commit hook: {}\n  {}",
        if installed {
            "installed"
        } else {
            "not installed"
        },
        hook.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A temp-dir whose *root* is a git repository (so `.git` sits right there).
    fn git_tempdir() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let ok = Command::new("git")
            .arg("init")
            .arg(dir.path())
            .output()
            .unwrap();
        assert!(
            ok.status.success(),
            "git init failed: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
        dir
    }

    #[test]
    fn install_writes_executable_hook() {
        let dir = git_tempdir();
        let path = install(dir.path()).unwrap();
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("sorseal verify"));
        assert!(body.contains("sorseal analyze --fail-on High"));
    }

    #[test]
    fn install_refuses_to_overwrite_existing_hook() {
        let dir = git_tempdir();
        let hook = dir.path().join(PRE_COMMIT_REL);
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(&hook, "#!/bin/sh\necho custom\n").unwrap();
        let err = install(dir.path()).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"));
    }

    #[test]
    fn uninstall_removes_only_sorseal_hooks() {
        let dir = git_tempdir();
        install(dir.path()).unwrap();
        assert!(is_installed(dir.path()));
        uninstall(dir.path()).unwrap();
        assert!(!is_installed(dir.path()));
        // uninstalling again is a clean no-op
        uninstall(dir.path()).unwrap();
    }

    #[test]
    fn not_a_git_repo_is_an_error() {
        let dir = tempdir().unwrap();
        let err = install(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("not a git repository"),
            "unexpected error: {err}"
        );
    }
}
