## Goal
Add a `--explain <RULE>` flag to `sorseal analyze` that prints human-readable
guidance for a detection rule without running an analysis — what it covers, why
it matters for Soroban contracts, and how to fix it.

Example:
```text
$ sorseal analyze --explain SORSEAL-101
SORSEAL-101  missing-authorization   (Critical)

Detects a function that mutates contract state or moves value without calling
`require_auth` first ...

Example fix:
  ...use `env.current_contract_address` / `require_auth`...
```

## Scope
- Add `--explain` handling in `src/main.rs` (print and exit; no scan).
- Define a durable description + remediation text per rule. The remediation is
  already a field on `Finding`; promote a static rule-metadata table in
  `src/analyze.rs` (id → name, severity, long description, example, how-to-fix)
  and have both `--explain` and the SARIF rule definitions (`src/sarif.rs`)
  read from it, so descriptions stay in one place.
- List all rules when `--explain` is given without a value, or with `--explain all`.
- Unit-test that every known `RuleId` has an entry in the table.

## Why
Repos that adopt an analyzer gate need to teach contributors *why* a finding is
flagged and *how* to fix it. A self-contained `--explain` turns the CLI into its
own documentation and keeps the rule set approachable for newcomers — good for
adoption and for `good-first-issue` contributors.

## Success criteria
- `sorseal analyze --explain SORSEAL-101` prints a non-empty, useful description + fix for every defined rule.
- `--explain` with no rule prints the full rule list.
- No source scan runs when `--explain` is used.
- Tests, fmt, and clippy stay green.
