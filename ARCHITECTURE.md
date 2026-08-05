# sorseal — Architecture

## Overview

sorseal is a single Rust crate (library + thin CLI binary). It is deliberately
small and offline: every digest is computed locally, and the only subprocesses
it spawns are the user's `build_command` (via `sh -c`) and read-only `git`
queries.

```
sorseal init|record|verify|report
        │
        ├─ src/main.rs     clap CLI, command dispatch, exit codes
        ├─ src/lib.rs      module root
        ├─ src/scaffold.rs sorseal.toml generation (cdylib discovery)
        ├─ src/manifest.rs sorseal.toml types + validation
        ├─ src/digest.rs   SHA-256 for files and directory trees
        ├─ src/provenance.rs  sorseal.provenance.json types + load/save
        ├─ src/runner.rs   record + verify orchestration
        ├─ src/report.rs   console / JSON / Markdown rendering
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
5. Render the checks; exit `0` if all PASS, `1` if any FAIL/ERROR, `2` on
   usage/config errors.

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
(errors). No network, no TLS, no date-time or git libraries — date formatting
and git queries are implemented directly.
