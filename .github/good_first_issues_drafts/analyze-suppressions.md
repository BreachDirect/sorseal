## Goal
Let teams suppress findings they have reviewed as acceptable, instead of
blocking on them forever. Add a per-rule allowlist / inline suppression so a
specific rule at a specific line can be silenced with a clear reason.

Two clean surfaces (pick one or both; an issue should first implement inline
`// sorseal:ignore <RULE>` comments):

- Inline: `// sorseal:ignore SORSEAL-104 reviewed: panic unreachable` on the
  line above a finding suppresses that one.
- Config: an optional `[analysis.ignore]` table in `sorseal.toml` listing
  `"rule": ["file:line"]` or `"rule"` (whole file) entries.

## Scope
- Parse inline `// sorseal:ignore <RULE>` comments during the per-line scan in
  `src/analyze.rs` and drop matching findings.
- Respect a `--no-ignore` flag that temporarily ignores suppressions (useful to
  see everything).
- Since suppressions affect the finding set, the analysis digest (`Analysis::digest`
  in `src/analyze.rs`) must reflect suppressed findings removed, so a suppressed run
  seals a different digest than an unsuppressed one.
- Add tests: a suppressed finding disappears, an unrelated-inline comment does not
  suppress, and removing the suppression changes the digest.

## Why
Real audit workflows involve noise. False positives (or accepted risks with a
written reason) currently force teams to either block forever or route around
the tool. Inline, reason-carrying suppressions are the standard pattern (c.f.
`clippy::allow`, Rustc `#[allow]`) and keep the audit trail honest by making the
decision explicit and reviewable.

## Success criteria
- A line tagged `// sorseal:ignore SORSEAL-104` produces no SORSEAL-104 finding.
- `--no-ignore` restores it.
- Suppressed findings are excluded from counts and from the sealed digest.
- Tests, fmt, and clippy stay green.
