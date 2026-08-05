# sorseal — Product Requirements Document

## Problem statement

Stellar Wave backends deploy Soroban contracts to testnet and mainnet. Once a
`.wasm` is on-chain, the only thing linking it to a repo is process: a README
saying "this came from commit X". There is no automated, tamper-evident record
that:

1. the deployed bytecode is the exact output of the committed source, and
2. a rebuild at any later time reproduces that bytecode bit-for-bit.

Non-reproducible builds and unverifiable deploys are a real risk class for
teams that hold or move value: a compromised or drifted source tree, a
manually-patched binary, or a "works on my machine" build can silently diverge
from what was audited.

## Audience

Soroban contract teams on Stellar (Wave-funded and otherwise) who need a cheap,
CI-friendly way to prove deployed bytecode matches source.

## Goals (Phase 1)

- **Seal** — produce a machine-readable provenance record (SHA-256 digests for
  WASM + source tree + toolchain + git commit) for every declared artifact.
- **Verify** — rebuild from a clean tree and prove the digests still match;
  exit non-zero on any drift so the check can gate CI/release.
- **Report** — render the provenance as console, JSON, or Markdown for
  deliverables and audit trails.
- **Zero dependency on sibling tools** — sorseal must make sense and function
  on its own for any Rust/Soroban project.

## Non-goals (Phase 1)

- Signing/notary-style attestations (Phase 3).
- SLSA full attestation metadata (Phase 4).
- A web dashboard or drift history (Phase 5).
- Language support beyond Rust/Cargo-built artifacts.

## Success criteria

1. `sorseal record` then `sorseal verify` (after wiping build output) exits 0.
2. Any source change, corrupted provenance, or moved-away git history fails
   `verify` with exit 1 and a clear message.
3. `cargo fmt`, `cargo clippy -D warnings`, and `cargo test` all green in CI.
4. The e2e fixture (`tests/fixtures/echo`) builds bit-reproducibly on CI.
5. Standalone: `sorseal init` scaffolds a working manifest for a fresh project
   with no input from other Wave tools.

## Out of scope

Anything that requires network access at runtime (all hashing is local and
offline). The tool must not make assumptions about how the user deploys — it
only asserts reproducibility of the declared artifacts.
