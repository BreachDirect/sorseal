# good-first-issue: user-extensible rules via config

## Goal

Let teams add their own detection patterns without forking sorseal. Introduce a
`[rules.custom]` section in `sorseal.toml` (or a dedicated `sorseal.rules.toml`)
where users declare custom matchers against the existing line tokenization:

```toml
[[rules.custom]]
id = "TEAM-1"
name = "no-console-log"
severity = "Low"
confidence = "High"
match = "contract.log("
message = "Don't log sensitive state; emit structured events instead."
remediation = "Prefer env.events().publish() with structured subjects."
```

## Scope

- A `CustomRule` type: id (must not collide with `SORSEAL-*`), name, severity,
  confidence, a substring/regex matcher applied to the precomputed
  comment/string-stripped line views (reuse the memoization in `src/analyze.rs`),
  message, remediation.
- Loading + validation in `src/manifest.rs`; errors on reserved id prefix
  (`SORSEAL-`) or unknown severity/confidence.
- Custom findings flow through the exact same Finding shape → console/JSON/
  Markdown/SARIF/digest/`--fail-on`/`--seal` unchanged.
- Docs: `--explain` lists custom rules; add a section to `RULES.md`.

## Why

Turning sorseal from a fixed 16-rule tool into a platform — teams adopt the
workflow for *their* contract conventions, not just the shipped set — is a
force multiplier for the project.

## Success criteria

- [ ] `sorseal analyze --config <file>` (or `sorseal.toml` `[rules.custom]`)
      emits a custom-rule finding with correct severity/confidence rendering
- [ ] Reserved id collision (`SORSEAL-*`) rejected with a clear error
- [ ] Custom findings are included in the digest and `--seal`
- [ ] Unit + golden coverage; `cargo clippy -- -D warnings` green

## Out of scope

Multi-line / function context matchers (those need the taint pass first);
node/function-level custom rules; running arbitrary code (no WASM plugin host).