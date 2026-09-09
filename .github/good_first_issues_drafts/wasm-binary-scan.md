# good-first-issue: WASM binary-level scanning (`analyze --wasm`)

## Goal

Add a `sorseal analyze --wasm` mode that scans the **compiled `.wasm` artifact**
(not just Rust source) for high-signal binary features: exported `""` entry
points that are reachable without auth, unused `memory.grow`, `unreachable`
traps in public exports, and oversized `data`/`func` sections that suggest
bloated or obfuscated logic.

## Scope

- New `--wasm` flag on `sorseal analyze` in `src/main.rs`.
- A small `wasm_scan` module that parses the WASM binary format (magic
  `\0asm`, the section table, and function/export/memory/data sections)
  without pulling in a wasm crate — matches the repo's no-heavy-deps rule.
- Emit findings (may reuse existing `RuleId` for panic/trap and add one for
  "unauthenticated export") so they flow through existing renderers + digest.
- Unit tests parsing tiny, hand-rolled WASM fixtures (a 12-byte stub is enough).

## Why

Source scanning misses what happens *after* build. `--wasm` verifies the
sealed artifact itself, which is exactly what the provenance story promises —
"the deployed bytecode matches the scanned source."

## Success criteria

- [ ] `sorseal analyze --wasm` on a stub wasm reports export/segment features
- [ ] Runs without network and with no wasm-parser crate dependency
- [ ] SARIF/JSON output includes wasm-layer findings
- [ ] Digests remain stable and golden tests unaffected (fixture is separate)

## Out of scope

Full wasm semantic analysis / CFG reconstruction; sandbox escape detection;
symbolic execution.