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

## Goals (Phase 2 — shipped)

- **GitHub Action** — a reusable composite action that runs `verify` in any
  repository and surfaces failures in CI (optional SARIF upload to code
  scanning).
- **SARIF output** — `verify --sarif` emits a SARIF 2.1.0 report mapping each
  check to a scan result.
- **Signed attestations** — Ed25519-signed in-toto Statements (SLSA v1.0
  predicate, DSSE envelope) so releases can be authenticated by public key
  alone.
- **On-chain verification** — prove a deployed contract's ledger WASM hash
  matches the sealed provenance by querying Soroban RPC directly.
- **On-chain audit** — reconstruct a contract's full upgrade lineage from
  ledger `executable_update` events and cross-check every deployed version
  against the sealed provenance (catches unsealed versions and drift over time,
  not just the current hash).

## Non-goals

- OIDC-based CI signing (no trusted third party at runtime).
- A web dashboard or drift history.
- Language support beyond Rust/Cargo-built artifacts.

## Success criteria

1. `sorseal record` then `sorseal verify` (after wiping build output) exits 0.
2. Any source change, corrupted provenance, or moved-away git history fails
   `verify` with exit 1 and a clear message.
3. `cargo fmt`, `cargo clippy -D warnings`, and `cargo test` all green in CI on
   stable and MSRV 1.85.
4. The e2e fixture (`tests/fixtures/echo`) builds bit-reproducibly on CI.
5. Standalone: `sorseal init` scaffolds a working manifest for a fresh project
   with no input from other Wave tools.
6. `keygen` → `sign` → `verify-attestation` round-trips; a tampered attestation
   or provenance fails verification.
7. `onchain-verify` fetches and decodes a live contract instance and matches
   the sealed wasm hash (verified against a real testnet deployment in tests).
8. `onchain-audit` reconstructs the upgrade lineage of a live contract that has
   been upgraded multiple times, collapses no-op upgrades, and flags an
   unsealed current deployment with exit 1.

## Out of scope

Anything that requires network access at runtime for the core path (all hashing
is local and offline; the only networked command is the explicitly on-chain
`onchain-verify`). The tool must not make assumptions about how the user deploys
— it only asserts reproducibility of the declared artifacts and, on request,
equivalence with what is actually deployed.
