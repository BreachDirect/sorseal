# good-first-issue: `sorseal hook` edge-case coverage

## Goal

`src/hook.rs` (the new `sorseal hook install/uninstall/status` pre-commit
integration) has happy-path tests but is missing edge cases:

- Install when `.git/hooks` does not exist yet (fresh `git init` does create
  it, but a bare/odd repo may not)
- Install on a **bare** repo (`git init --bare`) → should error cleanly
- Install when the existing hook already contains `# sorseal pre-commit hook`
  → should report "already installed" without error
- Uninstall when only a *non*-sorseal hook exists → no-op, not an error
- `render_status` output for both installed/uninstalled states
- Hook body executes correctly against the repo fixture (run the installed
  hook with a temp `sorseal.toml` + `sorseal.provenance.json` and assert
  exit code semantics — including `SORSEAL_SKIP_HOOK=1` bypass)

## Why

The hook is a trust-critical "runs before every commit" path. If it silently
misfires on a contributor's machine, they stop trusting the tool. These tests
are small, isolated, and don't need a Rust toolchain installed.

## Success criteria

- [ ] `cargo test --lib hook` covers all cases above
- [ ] A bare-repo install returns a clear error message
- [ ] Double-install is idempotent and non-destructive
- [ ] Hook script itself is exercised end-to-end on a fixture repo

## Out of scope

Windows hook support; hoist/shared global hooks (`core.hooksPath`);
installing a `post-commit` verification hook.