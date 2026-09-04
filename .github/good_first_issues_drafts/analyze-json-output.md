## Goal
Add a machine-readable JSON output mode to `sorseal analyze` (mirroring the
existing `verify --json` pattern) so findings can be consumed by scripts, CI
gates, dashboards, and other tooling.

`--json` should emit a single JSON document to stdout describing the analysis:
project, artifact, the rule set, every finding (rule id, severity, file, line,
message, remediation), the per-severity counts, and the analysis digest.

## Scope
- Add `-f json` / `--format json` support to the `analyze` subcommand in `src/main.rs`.
- Emit a deterministic document: order findings by rule → file → line (the same
  order used to compute the digest in `src/analyze.rs`) so output is stable.
- Fields should round-trip cleanly; reuse `Severity` and `RuleId` display names.
- Add a unit test in `src/analyze.rs` asserting the JSON structure and that the
  digest matches the one produced by the console summary.

## Why
`analyze` produces human output today. Teams want to gate CI on findings (see
the `--fail-on` issue) and slice findings by severity/file in scripts. JSON is
the lowest-common-denominator format for that.

## Success criteria
- `sorseal analyze --format json` prints a valid JSON document (all severities present).
- Running on the bundled `examples/vulnerable-contract` yields the same findings/digest as the console output.
- `cargo test --locked`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` all pass.
