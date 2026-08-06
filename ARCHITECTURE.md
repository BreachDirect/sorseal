# sorseal — Architecture

## Overview

sorseal is a single Rust crate (library + thin CLI binary). It is deliberately
small and offline: every digest is computed locally, and the only subprocesses
it spawns are the user's `build_command` (via `sh -c`) and read-only `git`
queries.

```
sorseal init|record|verify|report|keygen|sign|verify-attestation|onchain-verify
        │
        ├─ src/main.rs     clap CLI, command dispatch, exit codes
        ├─ src/lib.rs      module root
        ├─ src/scaffold.rs sorseal.toml generation (cdylib discovery)
        ├─ src/manifest.rs sorseal.toml types + validation
        ├─ src/digest.rs   SHA-256 for files and directory trees
        ├─ src/provenance.rs  sorseal.provenance.json types + load/save
        ├─ src/runner.rs   record + verify orchestration
        ├─ src/report.rs   console / JSON / Markdown rendering
        ├─ src/sarif.rs    SARIF 2.1.0 rendering of verify results
        ├─ src/sign.rs     Ed25519 keygen + DSSE/in-toto/SLSA signing & verification
        ├─ src/onchain.rs  Soroban RPC on-chain wasm hash verification
        ├─ src/git.rs      read-only git helpers (commit, clean, ancestor)
        └─ src/clock.rs    RFC 3339 UTC formatting (no date-time dependency)
```

## Data flow

### record

1. Read and validate `sorseal.toml`.
2. Capture git state; refuse to seal a dirty tree unless `--allow-dirty`.
3. For each artifact: run `build_command`, hash the produced WASM, hash the
   `source_root` tree, capture toolchain + timestamp.
4. Write `sorseal.provenance.json` (pretty-printed, `format = "sorseal-provenance"`,
   `version = 1`).

### verify

1. Read `sorseal.toml` and the provenance file.
2. Check project name consistency.
3. If the seal captured git state, require the sealed commit to be reachable
   from (or equal to) current `HEAD`.
4. For each sealed artifact: rebuild, compare `wasm_sha256`, then compare
   `source_sha256`. A missing manifest entry or build failure is an ERROR.
5. Render the checks; with `--sarif`, also write a SARIF 2.1.0 report (one
   `result` per check, `SARIF` `artifact` for the provenance) for GitHub code
   scanning. Exit `0` if all PASS, `1` if any FAIL/ERROR, `2` on
   usage/config errors.

### keygen / sign / verify-attestation

1. `keygen` writes an Ed25519 private key (`sorseal.key`) and derived public
   key (`sorseal.pub`), both lowercase hex, 0600-permissioned.
2. `sign` builds an **in-toto Statement** (subject = provenance wasm digest,
   predicateType = `https://slsa.dev/provenance/v1`) wrapped in a **DSSE**
   envelope with an Ed25519 signature over `PAYLOAD_TYPE || payload`.
3. `verify-attestation` recomputes the envelope signature with the public key
   and, when the provenance is supplied, cross-checks the statement subjects
   against its artifact digests.

### onchain-verify

1. Normalize the contract id (`C...` strkey or 64-char hex) to 32 bytes.
2. Build the 48-byte `LedgerKeyContractData` XDR for the contract's
   `SCV_LEDGER_KEY_CONTRACT_INSTANCE` entry (persistent durability) and call
   Soroban RPC `getLedgerEntries`.
3. Decode the returned `LedgerEntry` XDR (a hand-rolled, defensive reader for
   just this path) to the `ContractExecutable` wasm hash; a Stellar Asset
   Contract has none, so that is reported as an error.
4. Compare the deployed hash to the sealed artifact's `wasm_sha256`; exit `0`
   on match, `1` on mismatch, `2` on any RPC/XDR/config error.

## Digest design

- **File digest**: streaming SHA-256 over raw bytes.
- **Tree digest**: depth-first walk collecting relative paths; paths sorted
  lexicographically before hashing so the digest is order-independent. Each
  entry is hashed as `relative-path\n<bytes>\n`.
- **Exclusions**: `.git/`, `target/`, and the provenance file itself (so a seal
  never hashes its own previous value). The manifest `sorseal.toml` *is*
  included — it is part of the build configuration and belongs in the source
  fingerprint.

## Reproducibility

The e2e fixture (`tests/fixtures/echo`) is a dependency-free `cdylib` built with
`opt-level = "z"`, `lto`, `codegen-units = 1`, `panic = "abort"`, and `strip` —
a configuration that is bit-reproducible on a fixed toolchain. The e2e test
wipes `target/` between `record` and `verify` to prove the rebuild is real.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | all checks passed / command succeeded |
| 1 | verify found a FAIL or ERROR |
| 2 | usage or configuration error |

## Dependencies

Runtime deps are kept minimal and offline-friendly: `clap` (CLI), `serde` /
`serde_json` (provenance), `toml` (manifest), `sha2` (hashing), `anyhow`
(errors), `base64` (DSSE encoding), `ed25519-dalek` + `getrandom` (signing),
`stellar-strkey` (contract id decoding), and `ureq` (Soroban RPC HTTP; used
only by `onchain-verify`). No date-time or git libraries — date formatting and
git queries are implemented directly. The on-chain XDR path deliberately does
not pull the full `stellar-xdr` crate: it encodes the one fixed-size
`LedgerKeyContractData` it needs and decodes only the fields it reads, which
keeps the dependency surface and MSRV footprint small.
