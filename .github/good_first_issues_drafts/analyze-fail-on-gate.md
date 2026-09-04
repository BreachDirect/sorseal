## Goal
Let teams run `sorseal analyze` in CI as a real gate by failing on findings at
or above a chosen severity, e.g. `--fail-on Critical` or `--fail-on High`.

Today the command always reports findings but does not exit non-zero based on
severity, so a repo can't turn "no Criticals" into a CI failure.

## Scope
- Add `--fail-on <Critical|High|Medium|Low>` to the `analyze` subcommand in `src/main.rs`.
- If any finding has severity >= the threshold, exit with a non-zero status
  (use the existing exit-code convention for "checks failed"). Otherwise exit 0.
- When `--fail-on` is not supplied, keep the current behavior (report only).
- Print a clear summary line when the gate trips, e.g.
  `FAIL: 3 findings at or above High severity`.
- Wire the threshold comparison into an `Analysis` helper (e.g. reuse
  `count_by_severity` / severity ordering in `src/analyze.rs`) and unit-test it.

## Why
Static analysis is only useful in an audit workflow if it can block bad builds.
This makes `sorseal analyze` immediately usable as a pre-merge gate in the
GitHub Action (`action.yml`) and standalone CI, and pairs naturally with the
`--json` output.

## Success criteria
- `sorseal analyze --fail-on High` on `examples/vulnerable-contract` exits non-zero.
- `sorseal analyze --fail-on Critical` still exits non-zero there; `--fail-on Low` does too.
- `sorseal analyze` with no `--fail-on` exits 0 even when findings exist.
- Tests, fmt, and clippy stay green.
