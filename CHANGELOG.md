# Changelog

All notable changes to this project are documented here. Per-release detail in
[RELEASES.md](./RELEASES.md).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-11-08

### Added

- **`sorseal drift <left> <right>`** — compare two sealed records and report
  exactly what moved. Accepts two provenance files, two manifests, or one of
  each (so a manifest can be checked against the seal it produced). Reports
  `ADDED` / `REMOVED` / `CHANGED` per artifact plus top-level `CONTEXT`
  differences (project, toolchain, git), in console or `--format json`.
  Seal timestamps (`built_at`, `analyzed_at`) are excluded, so two seals of an
  unchanged tree report `NO DRIFT`. Exits `1` on any difference so it can gate
  CI. See the "Comparing sealed records" section of the README for the JSON
  field reference.

### Fixed

- `cargo audit` and `cargo deny` are green again. Seven RustSec advisories in
  the `rustls` stack pulled in via `ureq` (RUSTSEC-2026-0285, -0346, -0348,
  -0349, -0381, -0382) are cleared by a lockfile refresh: `rustls` 0.23.46,
  `rustls-webpki` 0.103.16, `webpki-roots` 1.0.11, `ureq` 3.5.1. `sha2` stays
  pinned at 0.11.0 and `stellar-strkey` at 0.0.16 — both newer lines declare
  `rust-version` above the project's MSRV of 1.85.

## [0.2.1] - 2026-09-12

### Fixed

- Project paths (artifacts, build commands, provenance, SARIF) now resolve
  relative to the manifest file instead of the process CWD, so
  `sorseal analyze --manifest path/to/sorseal.toml` works from any directory.
- `record`/`verify` build commands run via `cmd /C` on Windows (`sh` is not a
  native Windows command).
- `watch` webhook delivery is capped at 15s per attempt so a silent endpoint
  cannot stall the monitor loop indefinitely.

## [0.2.0] - 2026-09-11

### Added

- Four new analyzer rules (16 total): `SORSEAL-113` oracle-price-feed,
  `SORSEAL-114` flash-loan-approve, `SORSEAL-115` wasm-unreachable-export,
  `SORSEAL-116` wasm-no-exports.
- Confidence scores (low/medium/high) per finding, separate from severity.
- WASM-level scanning via `sorseal analyze --wasm` (`src/wasm_scan.rs`).
- `sorseal hook install` pre-commit integration.
- Multi-platform release binaries (Linux/macOS/Windows) with SHA-256 checksums.
- GitHub Action `mode` (`verify`/`analyze`/`both`) and `fail-on` inputs.
- CI test matrix on Ubuntu, macOS, and Windows.

### Changed

- Analysis ~2–3× faster (lexing source once per file); behavior and digests
  unchanged and golden-locked.
- Bumped `ureq` to 3.4.1, `toml` to 1.1.4+spec-1.1.0, base64 to 0.23.
- MSRV documented as Rust 1.85.

### Fixed

- Cross-OS reproducibility of findings and sealed digests (path normalization).
- SARIF output path contract when running the GitHub Action in a single mode.
- Platform-dependent `rejects_absolute_wasm_path` test on Windows.

## [0.1.x] - 2026-08-05

### Added

- Provenance sealing/verification CLI for Soroban/WASM artifacts.
- Reporting in console, JSON, and Markdown formats; SARIF output.
- SLSA v1.0 (DSSE PAE) Ed25519 attestations.
- On-chain verification against Soroban RPC and full upgrade-lineage audit.
- Fund-free `simulate-onchain` demo + upgradeable testnet contract.
- First 12 detection rules (`SORSEAL-101..112`).
- `sorseal watch` file-integrity monitoring.