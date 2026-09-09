# good-first-issue: `analyze` rule — flash-loan / approve-and-exploit (SORSEAL-114)

## Goal

Add a static rule that flags the **approve-then-manipulate** shape: a function
grants a token allowance (`approve`/`increase_allowance`) on a
caller-controlled amount and then makes an external call in the same function —
the classic flash-loan / approve-and-exploit vector.

## Scope

- New `RuleId::FlashLoanApprove` variant in `src/analyze.rs` mapping to
  `SORSEAL-114`, High severity.
- Lemmas: `.approve(`, `.increase_allowance(`, `.decrease_allowance(`
  together with `invoke_contract`/`call_contract` in the **same function**.
- Needs *function-level* context, so implement in `run_function_rules` only.
- Add `RuleMeta` for `--explain`/SARIF/`--explain-all` completeness.
- Unit tests: positive (approve + invoke) and negative (approve only; approve
  + invoke but external call target is the same trusted address).

## Why

Flash-loan-free manipulate-and-drain exploits are a Soroban-specific bounty
category. `SORSEAL-114` gives the analyzer a second High/Critical-class
finding that is easy to demo ("the tool caught an approve-and-exploit shape in
10 seconds").

## Success criteria

- [ ] `SORSEAL-114` listed by `sorseal analyze --explain`
- [ ] Approve + external-call fn fires; approve-only does not
- [ ] Renders correctly in console, JSON, Markdown, SARIF
- [ ] Stable digest changes only when the finding set changes

## Out of scope

Simulating actual token flows; flagging every `approve` (some are the
defined, auth-guarded API); contract-trust analysis.