# sorseal

**Provenance for Soroban/WASM artifacts — prove deployed bytecode matches source.**

![CI](https://github.com/BreachDirect/sorseal/actions/workflows/ci.yml/badge.svg)
![Security](https://github.com/BreachDirect/sorseal/actions/workflows/security.yml/badge.svg)
![Release](https://github.com/BreachDirect/sorseal/actions/workflows/release.yml/badge.svg)
![Rust](https://img.shields.io/badge/rust-1.85+-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

When a Stellar contract goes live on mainnet, can you *prove* the deployed WASM
was built from the exact source in your repo? sorseal closes that gap. It
**seals the build**: it records a manifest of SHA-256 digests for your contract
artifacts — WASM + source tree + toolchain + git commit — then **verifies** at
any time that a clean rebuild reproduces those exact digests.

It is a fully **standalone** tool: it works on any Rust/Soroban project and has
no dependency on other tools in the Stellar Wave toolchain.

## Why

- **Reproducible builds.** Bit-for-bit rebuild verification catches anything
  that makes your build non-reproducible (unpinned dependencies, timestamps in
  output, host-dependent codegen) before it ships.
- **Supply-chain audit trail.** The committed provenance file is a machine-
  readable answer to "what source, toolchain, and commit produced this bytecode?"
- **CI-friendly.** `sorseal verify` exits non-zero on any mismatch — drop it into
  a release pipeline to gate deploys on reproducible, source-matching bytecode.

## Quick start

```bash
# 1. Scaffold a manifest (auto-discovers cdylib contract crates in the Cargo workspace)
sorseal init

# 2. Build and seal the digests into sorseal.provenance.json
sorseal record

# 3. Commit the provenance alongside your release
git add sorseal.provenance.json && git commit -m "release: seal contract builds"

# 4. Any time later: rebuild from a clean tree and prove it matches
sorseal verify
```

`verify` rebuilds each artifact from source and compares:

```
Sorseal — echo verify

PASSED  project :: name — manifest project 'echo' matches sealed provenance
PASSED  git :: commit — sealed commit 46b5abe0a814 is reachable from HEAD 4c5a699b4af2
PASSED  echo :: wasm — sha256 matches sealed digest c3231bfcaaa2
PASSED  echo :: source — source tree matches sealed digest fd9764f8b778

4 checks: 4 passed, 0 failed, 0 errored
```

Exit code is `0` when every check passes, `1` on any mismatch, `2` on a usage or
config error.

## How it works

A `sorseal.toml` declares which artifacts to build and hash:

```toml
[project]
name = "escrow"

[[artifacts]]
id = "escrow"
build_command = "cargo build --release --target wasm32-unknown-unknown -p escrow"
wasm_path = "target/wasm32-unknown-unknown/release/escrow.wasm"
source_root = "."
```

`record` runs each `build_command`, then captures per artifact:

- **`wasm_sha256`** — SHA-256 of the built artifact (e.g. the contract WASM)
- **`source_sha256`** — SHA-256 of the source tree (`source_root`), keyed on
  relative path + file bytes, sorted for determinism, excluding `.git/`,
  `target/`, and the provenance file itself
- **toolchain** — `rustc --version` of the compiler used
- **git state** — the current commit and cleanliness, when in a git repo

`verify` reruns every `build_command` in the current tree and compares each
digest against the sealed record. It also confirms the sealed commit is
reachable from the current `HEAD`.

### Why both a WASM *and* a source digest?

The WASM digest is the ground truth that deployed bytecode matches; the source
digest is defense in depth — it catches source drift even when the compiled
artifact is byte-identical (e.g. a comment-only change), so an attacker or a
careless edit can't silently diverge the source from what was shipped.

## Commands

```
sorseal init                    Scaffold a sorseal.toml manifest
sorseal record [--allow-dirty]  Build artifacts and write sorseal.provenance.json
sorseal verify                  Rebuild and verify against the sealed provenance
sorseal report [--format console|json|markdown]
                                Render the provenance as a deliverable report
```

`record` refuses to seal a **dirty working tree** unless `--allow-dirty` is
passed — a seal is only meaningful if it describes exactly the committed source.

`report --format markdown` emits a table suitable for a release deliverable or
audit appendix.

## Project docs

- [`PRD.md`](./PRD.md) — problem statement, scope, and success criteria.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — module layout and design rationale.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to build, test, and contribute.

## Roadmap

Phase 1 (this release) ships the core CLI: init, record, verify, and report.
Planned phases — a reusable GitHub Action and SARIF output, signed provenance
(Ed25519), and SLSA-style attestation metadata — are tracked as issues in this
repo.

## Wave alignment

Built for **Stellar Wave 8** as a standalone, reusable open-source dependency —
not tied to any single org's private codebase — so any Wave-funded backend can
adopt it to prove that deployed contracts match their source.

## License

MIT
