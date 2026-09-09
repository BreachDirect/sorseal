# good-first-issue: `analyze` rule — oracle / price-feed manipulation (SORSEAL-113)

## Goal

Add a static detection rule that flags **unvalidated oracle/price-feed reads** —
Debt-to-price style manipulation where a contract derives financial decisions
from a value that any caller can influence (e.g. a `get_price` external call
with no staleness check, or a price stored by an unauthenticated writer).

## Scope

- New `RuleId::OraclePriceFeed` variant in `src/analyze.rs` mapping to
  `SORSEAL-113`, Medium severity.
- Lemmas to match on: `get_price`, `price_feed`, `oracle`, `.latest_price`,
  `env.invoke_contract` returning a price symbol (`Symbol::new("price")`).
- Wire into `run_line_rules` and `run_function_rules` (either/both as
  appropriate); fetch uses should only flag when a price symbol is involved.
- Add `RuleMeta` in `all_rules()` with a short_desc / description / example /
  fix.
- Unit tests (positive + negative paths) following the pattern in
  `analyze::tests`.

## Why

Oracle manipulation is one of the most expensive Soroban/LoS exploit classes.
A rule that flags price reads with no staleness/auth branch is high-visibility
Wave evidence and closes a real gap in the current 12-rule set.

## Success criteria

- [ ] `sorseal analyze --explain SORSEAL-113` documents the rule
- [ ] A fictional vulnerable fn (`get_price` + no check) fires SORSEAL-113
- [ ] A guarded fn (staleness compare or `require_auth` before price read) does not
- [ ] SARIF, JSON, Markdown, and the analysis digest all include the new rule
- [ ] Golden-file fixtures unaffected unless `SORSEAL_UPDATE_GOLDEN=1`

## Out of scope

Semantic analysis of where the oracle value ends up; fresh-answer verification
in prod; cross-contract trust graph.