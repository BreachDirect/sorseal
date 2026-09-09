# good-first-issue: taint / data-flow pass to raise heuristic-rule confidence

## Goal

`sorseal analyze` marks `SORSEAL-105` (unchecked-transfer), `SORSEAL-112`
(unchecked-env-caller), `SORSEAL-113` (oracle-price-feed), and `SORSEAL-114`
(flash-loan-approve) as `medium`/`low` confidence because their activation is
only *pattern*-shaped. Add a lightweight **local data-flow / taint pass** —
per function, tracking which variables derive from a `require_auth`'d
address, a balance/allowance read, a price read, or caller-supplied input —
and use it to **promote** those findings to `high` confidence when the flow is
actually present.

## Scope

- A per-function, single-use-definition taint model: variables assigned from
  `env.ledger().balance(...)`/`.allowance` are "trusted-amount"; values read
  from a price feed (see `SORSEAL-113`) are "price-driven"; parameters are
  "caller-supplied". Track what flows into a `.transfer()` amount, an
  `approve` allowance, and arithmetic operands.
- When the tainted flow confirms the rule's precondition, emit the finding at
  `Confidence::High` instead of `low`/`medium`.
- Wire confidence into the existing per-rule confidence lookup — do **not**
  change severity, ids, or the sealed digest semantics.
- Keep it lexically-scoped and O(n) per function; it must stay fast enough that
  `tests/perf.rs` still passes.

## Why

This is the single highest-leverage analyzer improvement: it converts the tool's
known false-positive class ("I saw the shape, I couldn't prove the flow") into
hardened, higher-precision findings without a full AST dependency.

## Success criteria

- [ ] `SORSEAL-105/112/113/114` unit tests demonstrate the promoted
      (`high`) vs. unpromoted (`low`/`medium`) confidence paths
- [ ] Existing golden fixture digest unchanged for findings that stay
      unpromoted; new promotion cases covered in `tests/fixtures/analyze`
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` green
- [ ] `tests/perf.rs` still passes (the precomputed stripped/lowered views must
      be reused, not re-lexed)

## Out of scope

Cross-function/cross-module data flow; a real SSA/interprocedural analysis;
WASM-level flow recovery.