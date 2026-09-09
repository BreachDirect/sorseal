# Sorseal detection rules

This document explains **why each rule exists**, how confident the scanner is in
each match, and how the rule set has changed over time. Rule ids are stable:
`SORSEAL-105` means the same thing in the 0.1 vintage as it does today, so a CI
`--fail-on` gate that passed last quarter still means the same thing this
quarter.

See also the machine-readable source of truth — `src/analyze.rs::all_rules()` — and
`README.md` for the quick table.

## Confidence vs severity

- **Severity** = how much damage an exploit of this finding could do.
- **Confidence** = how sure the scanner is that the flagged line is actually the
  vulnerable thing, given only lexical evidence.

They are independent axes (`SORSEAL-105` is High severity but Medium confidence).
A finding with *high severity + low confidence* is a "look here first, but
verify" signal; one with *medium severity + high confidence* is a "this is
definitely wrong" signal. This is the same split `semgrep`/CodeQL use so a
13-finding report doesn't put every line on equal footing.

## Why these checks and not others

The analyzer is deliberately **lexical** (bandit/ruff-style): it tokenizes each
line and applies pattern matchers. It does not parse the AST, and it has **no
build-time dependencies** (`syn`/`tree-sitter`/`cargo` subprocess). That buys
two properties worth more than perfect recall here:

1. **It never fails to scan.** A contract that doesn't compile, or an exotic
   macro layer, still gets scanned. Rules that need ASTs silently skip files.
2. **It's fast enough to run on every PR.** `cargo test --test perf` keeps a
   ~200k-line tree under budget; in release it scans ~200k lines in well under
   a second.

The cost is that rules needing *data-flow* (is this amount derived from a
balance read? is this price caller-supplied?) are heuristic, so the tool
defaults to **Medium/Low confidence** on those instead of silent. The chart
below is the honest statement of what each rule is and isn't.

| Rule | Why it exists | Confidence | Known limit |
|---|---|---|---|
| `SORSEAL-101` missing-`require_auth` | The #1 Soroban drain: a value- or state-relevant `fn` that never authenticates | high | Requires a state mutation to be present; pure read paths are correctly skipped |
| `SORSEAL-102` reentrancy | State mutated, then an external call, no auth — classic re-entry window | medium | If `require_auth` is present but the guard targets the wrong actor, this misses it |
| `SORSEAL-103` unchecked-arithmetic | Overflow-prone raw `+`/`-`/`*` on amount/balance lines | medium | Flags loop counters next to amount math (false positive); needs data-flow to be sure |
| `SORSEAL-104` panic-on-user-input | A panic reverts for the *caller*, bricks cross-contract flows | high | Only fires on explicit `panic!`/value `unwrap()`/`expect(` |
| `SORSEAL-105` unchecked-transfer | Transferring an amount not derived from a balance/allowance read | medium | Needs data-flow to confirm the amount's origin; heuristics today |
| `SORSEAL-106` missing-reentrancy-guard | `invoke_contract` without `non_reentrant` | medium | The guard may live several lines above the call |
| `SORSEAL-107` hardcoded-storage-key | `Symbol::new()` keys collide across upgrades/namespaces | medium | Impact depends on the deployment/upgrade model |
| `SORSEAL-108` unsafe-raw-pointer | Soroban's sandbox forbids `unsafe`; presence signals a real problem | high | Exact match — no known false-positive class |
| `SORSEAL-109` panic-on-storage-read | `.unwrap()` on `.get()` reverts when the key is absent | high | Exact pattern; misses `?`-propagated `None` (by design — those return errors, never panic) |
| `SORSEAL-110` admin-key-never-rotated | `OWNER`/`ADMIN` key written with no rotate/transfer-ownership | low | Rotation may live in another function; heuristic, verify by hand |
| `SORSEAL-111` missing-token-balance-check | burn/mint/transfer without first reading what the contract holds | medium | Doesn't prove a drain, just that the check is absent here |
| `SORSEAL-112` unchecked-env-caller | Address param used in a mutation without `require_auth` on it | medium | The auth might happen through indirection the lexer can't see |
| `SORSEAL-113` oracle-price-feed | Price read with no staleness/auth guard — single-oracle manipulation | low | Confidence will rise once data-flow can confirm the price drives a decision |
| `SORSEAL-114` flash-loan-approve | Allowance granted + external call in one function | low | Shape is distinctive but can be benign; verify the spender/amount |
| `SORSEAL-115` wasm-unreachable-export | Deployed WASM traps on entry; invisible in source, only in the artifact | high | `--wasm` only; scans code bodies for `unreachable; end` |
| `SORSEAL-116` wasm-no-exports | Not a real contract; the wrong artifact is being sealed | high | `--wasm` only |

### The confidence ladder (why "low" is a feature, not a bug)

A rule marked `low` confidence is the engine honestly saying *"I saw the shape;
I cannot prove the flow; a human should confirm."* That is strictly better than
either silence or a 100% recall race, and it is exactly the slot the roadmap's
**data-flow / taint-tracking** pass will fill: the same rule, re-scored `high`
when a price actually reaches a subtraction.

## Changelog

Rule ids are stable forever. Content changes are listed by id so historical CI
gates stay interpretable.

### v0.2.0 (draft, unreleased)

- **New:** `SORSEAL-113` oracle-price-feed, `SORSEAL-114` flash-loan-approve,
  `SORSEAL-115` wasm-unreachable-export, `SORSEAL-116` wasm-no-exports.
- **New:** per-finding `confidence` (low/medium/high) in console, JSON, Markdown,
  and SARIF; derived from rule metadata so the sealed digest is unchanged.
- **Changed:** analyzer hot path — source lines are lexed (comment/string
  stripped) exactly once per file instead of ~16×; ~2–3× faster, behavior and
  digest identical (golden-locked).
- **Removed/changed:** none of the pre-existing `SORSEAL-101..112` behavior or
  digests changed.

### v0.1.x (initial)

- Shipped `SORSEAL-101` missing-authorization through `SORSEAL-112`
  unchecked-env-caller.
- First digest-sealing + SARIF + GitHub Action + `--fail-on` baseline.