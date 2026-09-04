## Goal
Add a bundled **golden-file test harness** for `sorseal analyze` so rule changes
can't silently alter which findings are reported or break the sealed digest.

A golden file records the full expected finding set (rule, severity, file, line)
for the bundled `examples/vulnerable-contract`. Running `sorseal analyze` must
reproduce exactly that set and the same digest, or the test fails.

## Scope
- Add an integration test (in `tests/`) that runs `sorseal analyze` against
  `examples/vulnerable-contract` and compares the finding set + analysis digest
  to a checked-in golden JSON (e.g. `tests/fixtures/analyze/vulnerable-contract.json`).
- Provide a `--update-golden` style helper (or an env flag) that regenerates the
  golden file when a rule change *intentionally* alters output, so updating is
  a deliberate, reviewed step rather than an automatic fix.
- Test failure output should show the diff between expected and actual findings.
- Wire the test into `cargo test` so it runs in CI.

## Why
`analyze` claims a *stable, tamper-evident* digest, and the finding set must stay
deterministic across rule iterations (`SORSEAL-105` activation, suppressions, and
new rules all risk drifting). Golden tests lock the contract, and they are a
perfect, low-risk first contribution that protects the audit guarantee.

## Success criteria
- The golden test passes on an unmodified tree.
- Editing `examples/vulnerable-contract` (e.g. adding a finding) makes the test
  fail with a clear diff; regenerating with the helper and re-running passes.
- `cargo test --locked`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` pass.
