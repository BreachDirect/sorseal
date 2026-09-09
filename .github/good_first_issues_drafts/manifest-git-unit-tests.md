# good-first-issue: unit tests for manifest + git validation

## Goal

`manifest.rs` and `git.rs` currently have **no direct unit tests** — their
validation logic (path-traversal blocking, duplicate artifact ids, empty
fields, git error handling) is only covered indirectly through e2e. Add focused
unit tests for both modules.

## Scope

### `src/manifest.rs`
- Reject absolute `wasm_path` / `source_root`
- Reject `..` components (path traversal)
- Reject empty `project.name`, empty `id`, empty `build_command`
- Reject duplicate artifact ids
- Accept a valid manifest (load from a temp TOML string)
- Accept `was32v1-none`-style source roots and relative wasm paths

### `src/git.rs`
- `git_state` in a temp `git init` repo → `present: true`
- `git_state` with a dirty worktree → `clean: false`
- `git_state` outside any repo → `present: false`
- `contains` for a reachable HEAD commit → `true`; unknown commit → `false`
- `.git` marker present but git command failing → error (bail)

## Why

These are the validation hooks that stop manifest-based attacks and seal
silently-wrong records. Direct tests document the contract and prevent
regressions, and they're trivially scoped for a first PR.

## Success criteria

- [ ] `cargo test --lib manifest` and `cargo test --lib git` pass
- [ ] Every rule above has a test
- [ ] No production code changes required (unless a test uncovers a bug)

## Out of scope

Refactoring `validate_tree_path`; changing error messages/exit codes;
on-chain XDR coverage.