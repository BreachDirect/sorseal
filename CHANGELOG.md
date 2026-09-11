# Changelog

All notable changes to this project are documented here. Per-release detail in
[RELEASES.md](./RELEASES.md).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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