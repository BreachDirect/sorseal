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
- **Reusable GitHub Action.** A composite action wraps `sorseal verify` with
  SARIF output for GitHub code scanning, so the gate is one `uses:` away.
- **Signed supply-chain records.** Attestations are signed with Ed25519 as
  in-toto Statements (SLSA v1.0 predicate, DSSE envelope) — a public key is all
  a verifier needs to trust a release.
- **On-chain verification.** `onchain-verify` reads the deployed contract's WASM
  hash straight off Stellar's ledger (mainnet or testnet) via Soroban RPC and
  proves it matches your sealed provenance. No gateway or dashboard is involved
  — the only trust point is the RPC endpoint itself, so you can point it at your
  own node.

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
build_command = "cargo build --release --target wasm32v1-none -p escrow"
wasm_path = "target/wasm32v1-none/release/escrow.wasm"
source_root = "."
```

`record` runs each `build_command`, then captures per artifact:

- **`wasm_sha256`** — SHA-256 of the built artifact (e.g. the contract WASM)
- **`source_sha256`** — SHA-256 of the source tree (`source_root`), keyed on
  relative path + file bytes, sorted for determinism, excluding `.git/`,
  `target/`, and sorseal's own generated outputs (the provenance file, signed
  attestation, key files, and any `.sarif` report) — so a seal never depends on
  its own outputs
- **toolchain** — `rustc --version` of the compiler used
- **git state** — the current commit and cleanliness, when in a git repo

`verify` reruns every `build_command` in the current tree and compares each
digest against the sealed record. It also confirms the sealed commit is
reachable from the current `HEAD`, and that each manifest `build_command` still
matches the command the seal was produced with (so a changed build config can't
silently describe a different build).

### Why both a WASM *and* a source digest?

The WASM digest is the ground truth that deployed bytecode matches; the source
digest is defense in depth — it catches source drift even when the compiled
artifact is byte-identical (e.g. a comment-only change), so an attacker or a
careless edit can't silently diverge the source from what was shipped.

## Commands

```
sorseal init                    Scaffold a sorseal.toml manifest
sorseal record [--allow-dirty]  Build artifacts and write sorseal.provenance.json
sorseal verify [--sarif FILE]   Rebuild and verify against the sealed provenance
sorseal report [--format console|json|markdown]
                                Render the provenance as a deliverable report
sorseal keygen                  Generate an Ed25519 keypair for signing attestations
sorseal sign --key KEY          Sign the provenance as an in-toto/SLSA attestation
sorseal verify-attestation --public-key KEY
                                Verify an attestation signature (and subjects)
sorseal onchain-verify --contract-id C...
                                Compare the deployed on-chain wasm hash to provenance
sorseal onchain-audit --contract-id C... [--rpc URL] [--start-ledger L] [--end-ledger L] [--provenance FILE]
                                Reconstruct a contract's upgrade lineage from ledger events
                                and cross-check each version against sealed provenance
```

`record` refuses to seal a **dirty working tree** unless `--allow-dirty` is
passed — a seal is only meaningful if it describes exactly the committed source.

`report --format markdown` emits a table suitable for a release deliverable or
audit appendix.

## Supply-chain attestations

The provenance alone proves a rebuild matches a seal; an attacker who can edit
the repo can re-seal. Signing closes that: a release is only trustworthy if it
was sealed under a key the release authority controls.

```bash
# Generate a keypair (private key stays local; share only the public key)
sorseal keygen --key release.key --public-key release.pub

# After `sorseal record`, sign the provenance:
sorseal sign --key release.key

# A verifier with only the public key can check the signature:
sorseal verify-attestation --public-key release.pub
# PASSED  attestation :: signature — Ed25519 signature valid for release.pub
# PASSED  attestation :: subjects — subject digests match sorseal.provenance.json
```

Attestations are written as [DSSE envelopes](https://github.com/secure-systems-lab/dsse)
wrapping an [in-toto Statement](https://github.com/in-toto/attestation) with an
SLSA v1.0 predicate, so they are interoperable with standard supply-chain
tooling. `verify-attestation` exits non-zero on a bad signature or — when the
provenance is given — on any subject mismatch.

## On-chain verification

`onchain-verify` queries the Stellar ledger directly (no trusted gateway) for
the WASM hash currently deployed at a contract address and compares it to the
hash sealed in the provenance:

```bash
# Mainnet (default) or testnet, by C... strkey or 64-char hex:
sorseal onchain-verify --contract-id C... --rpc https://soroban-testnet.stellar.org

# PASSED  contract :: wasm hash — deployed bytecode matches sealed provenance
#         deployed sha256 ccedd7ac...e430
#         sealed   sha256 ccedd7ac...e430
```

It reads the contract's `SCV_LEDGER_KEY_CONTRACT_INSTANCE` ledger entry via the
Soroban RPC `getLedgerEntries` method and decodes the embedded
`ContractExecutable` WASM hash — the same primitive a client downloads to
invoke the contract. Exit codes follow the `verify` convention (0 pass / 1
mismatch / 2 error).

## On-chain audit

`onchain-audit` goes beyond the current hash: it reconstructs a contract's
**entire upgrade history** from `executable_update` system events on the
ledger, and cross-checks every deployed version against the sealed provenance.

```bash
# Defaults to mainnet; point --rpc at any Soroban RPC node (e.g. testnet)
sorseal onchain-audit --contract-id C... --rpc https://soroban-testnet.stellar.org
```

```
Sorseal — on-chain audit

contract    2b8fdc2b74100c53c4854961c7a9c858a017d12e25ca0e20ad78d548dc262847
rpc         https://soroban-testnet.stellar.org
scan window ledgers 3887209..4008168 — 3 upgrade event(s) found
lineage     consistent

version wasm sha256  live from                live until               attested upgrade tx
─────── ──────────── ──────────────────────── ──────────────────────── ──────── ────────────
v0      eb4c26caa846 <deployment>             2026-08-03T19:22:54Z     NONE     —
v1      920800d410a3 2026-08-03T19:22:54Z     2026-08-03T19:23:54Z     NONE     79e8fe597fa4
v2*     eb4c26caa846 2026-08-03T19:23:54Z     now                      NONE     d87c846937ef

FAILED   current deployment has NO sealed provenance
```

How it works:

- **Event scan.** It pages `getEvents` for `system` `executable_update` events
  (cursor-based, so it never double-counts), deduplicates, and keeps only the
  events for the target contract. Each event carries the wasm hash that was
  live *before* and *after* the upgrade, so adjacent events chain together into
  a version lineage.
- **Window discovery.** The retention window is discovered by probing an
  out-of-range `startLedger` and reading the range from the RPC error, so the
  scan always covers exactly what the node can serve.
- **Lineage.** A version list runs from `<deployment>` (the hash live before
  the first upgrade) to the current on-chain hash. No-op upgrades (old == new)
  are collapsed. If the newest upgrade's `new` hash doesn't match the hash read
  directly from the contract instance, the lineage is flagged inconsistent — a
  gap (e.g. an upgrade that fell outside the retention window) you should
  investigate.
- **Attestation cross-check.** Each version's wasm hash is matched against the
  `wasm_sha256` digests in `sorseal.provenance.json` (auto-loaded, or
  `--provenance`). Versions with a matching sealed artifact are `sealed`;
  anything else produces a warning.
- **Exit codes.** `0` if the current deployment is sealed by provenance, `1`
  if it is not (or the lineage is inconsistent), `2` on usage/RPC errors. With
  no provenance supplied it audits history only and warns on every unsealed
  version.

The scan window can be narrowed with `--start-ledger` / `--end-ledger`
(automatically clamped to what the node retains), which is useful for auditing
a known deployment window.

## End-to-end demo

`examples/demo-contract` is a real (soroban-sdk) contract whose only change
between "releases" is a constant — each bump produces a distinct wasm, which is
exactly what the audit needs to show a lineage. `scripts/demo.sh` drives the
whole story against testnet:

```bash
rustup target add wasm32v1-none
cargo install soroban-cli --version 27.1.0 --locked   # provides the `stellar` CLI
cargo build --release                                  # build the sorseal binary
scripts/demo.sh                                        # seal -> deploy -> 2 upgrades -> audit
```

The script:

1. **Seals v1** with `sorseal record`, **deploys** it, and proves it on-chain
   with `sorseal onchain-verify`.
2. **Upgrades twice without re-sealing** — the unsealed releases a real team
   would want to catch.
3. **Audits**: `sorseal onchain-audit` reconstructs the full lineage and exits
   `1` because the current deployment (v3) has no sealed provenance.
4. **Seals v3** and re-audits — the same command now exits `0` with the current
   deployment sealed, while the earlier unsealed versions are still flagged.

It can be driven with your own testnet key (`SOURCE_KEY=... scripts/demo.sh`)
or lets the script generate and friendbot-fund one automatically.

## GitHub Action

A reusable composite action wraps `sorseal verify` so any repository can gate
its release pipeline on provenance in one step:

```yaml
- name: Verify sealed provenance
  uses: BreachDirect/sorseal@v1
  with:
    working-directory: contracts/escrow
    sarif-file: sorseal.sarif
```

- Inputs: `working-directory`, `manifest`, `provenance`, `sarif-file`, `toolchain`.
- Outputs: `passed` (`true`/`false`).
- When `sarif-file` is set, the results are uploaded to **GitHub code scanning**
  via `github/codeql-action/upload-sarif@v3`, so non-reproducible builds surface
  as security alerts.

## Project docs

- [`PRD.md`](./PRD.md) — problem statement, scope, and success criteria.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — module layout and design rationale.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to build, test, and contribute.

## Roadmap

Phase 1 (core CLI: init, record, verify, report) and Phase 2 (GitHub Action +
SARIF, Ed25519/DSSE signed attestations, on-chain WASM verification, and
on-chain upgrade-lineage audits) are shipped. Planned follow-ups — CI
provenance signing from OIDC identities, multi-signer rotation, and a
verification API — are tracked as issues in this repo.

## Wave alignment

Built for **Stellar Wave 8** as a standalone, reusable open-source dependency —
not tied to any single org's private codebase — so any Wave-funded backend can
adopt it to prove that deployed contracts match their source.

## License

MIT
