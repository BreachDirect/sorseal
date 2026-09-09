# good-first-issue: performance smoke test on large codebases

## Goal

Add a repeatable performance smoke test that runs `sorseal analyze` (and
`record`/`verify` hashing) against a **large synthetic source tree** and
asserts it completes under a generous time budget — guarding against
accidental quadratic blowups in the lexical scanner.

## Scope

- A new `tests/perf.rs` (or a `--perf` hidden flag) that generates, say,
  2,000 Rust files × 200 lines each in a temp dir (a stand-in for a monorepo).
- Assert `analyze_tree` finishes in < `N` seconds (generous CI-safe budget,
  e.g. 10s) and returns a sane finding count.
- Measure `digest::hash_directory` throughput on the same tree.
- Keep it **opt-in/skipped by default** if it takes too long on CI, or make
  the budget generous enough to be stable on shared runners.

## Why

`src/analyze.rs` is line-by-line lexical with O(files×lines) rule scanning and
a `strip_comments_and_strings` pass per line. Forked/converted projects can be
10–100× the size of the bundled examples. A regression here makes `analyze`
impractical as a CI gate — directly counter to the tool's purpose.

## Success criteria

- [ ] `cargo test --test perf --ignored` passes on a typical laptop
- [ ] The scale is documented (files/lines/bytes) so budget changes are informed
- [ ] No production behavior changes

## Out of scope

Vectorized/parallel scanning; `rayon` (dependency-light policy);
algorithmic redesign of `split_functions`/`test_block_ranges`.