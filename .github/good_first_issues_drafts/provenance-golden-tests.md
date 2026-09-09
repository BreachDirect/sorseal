# good-first-issue: golden regression tests for the provenance path

## Goal

`tests/analyze_golden.rs` locks the analyzer to a checked-in golden JSON and is
a huge win for catching behavior drift. Extend the same golden-diff discipline
to the **provenance** path (`record`/`verify`/`sign`) so regressions in
sealing, digesting, or signing get caught the same way.

## Scope

- A fixture tree (tests/fixtures/golden-manifest) whose `record` output is
  stored as a golden artifact (structure + a few stable digests), independent
  of `tempfile`-based Cargo.toml hashing variance.
- When the provenance file structure or a serialization detail changes, the
  golden test forces a deliberate, reviewed regeneration (env-var like
  `SORSEAL_UPDATE_GOLDEN`) rather than silent breakage.
- Capture: manifest validation output, `record` provenance JSON shape, `sign`
  DSSE envelope shape (with a fixed test key burned into the test), and the
  `verify` / `verify-attestation` decision outputs.
- Keep digests that depend on timestamps/toolchain out of the golden (assert
  *shape* + stable fields there).

## Why

Provenance is the product's trust core; the same regression discipline the
analyzer already enjoys should cover it. Cheap to add, and it makes the "sealed
record is tamper-evident" claim testable-by-construction.

## Success criteria

- [ ] `SORSEAL_UPDATE_GOLDEN=1 cargo test --test provenance_golden` docs + works
- [ ] Tampering with the provenance serialization or a signature fails the test
- [ ] Timestamp/toolchain fields validated for *format*, not for value
- [ ] CI runs the golden tests on the OS matrix without flushing

## Out of scope

On-chain/network goldens (covered by `simulate-onchain` fixtures); refactoring
the hashing code itself.