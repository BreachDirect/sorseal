# Sorseal releases

Prebuilt binaries (Linux/macOS/Windows) are uploaded on every tagged release by
`.github/workflows/release.yml`. The changelog below is grouped by tag.

## v0.2.2 (2026-11-08)

Ships on crates.io with prebuilt binaries attached to the GitHub release.

- **`sorseal drift <left> <right>`** — compare two sealed records and report
  what moved. Accepts two provenance files, two manifests, or one of each (so a
  manifest can be checked against the seal it produced). Reports `ADDED` /
  `REMOVED` / `CHANGED` per artifact plus top-level `CONTEXT` differences
  (project, toolchain, git), in console or `--format json`. Seal timestamps are
  excluded, so two seals of an unchanged tree report `NO DRIFT`. Exits `1` on
  any difference so it can gate CI.
- **Security: `cargo audit` and `cargo deny` are green again.** Seven RustSec
  advisories in the `rustls` stack pulled in via `ureq` are cleared by a
  lockfile refresh — `rustls` 0.23.46, `rustls-webpki` 0.103.16,
  `webpki-roots` 1.0.11, `ureq` 3.5.1. The previously published `0.2.1`
  shipped `rustls` 0.23.43 (RUSTSEC-2026-0285/-0346/-0348/-0349/-0381/-0382);
  `cargo install sorseal --locked` from `0.2.2` does not.
- `sha2` stays pinned at 0.11.0 and `stellar-strkey` at 0.0.16 — both newer
  lines declare `rust-version` above the project MSRV of 1.85.

## v0.2.1 (2026-09-12)

Released on crates.io; the GitHub tag and five platform binaries were added
later (2026-11-08) so the release matches what crates.io publishes. A
fixes-only patch after `v0.2.0`:

- **Manifest-relative paths.** All project paths (artifacts, build commands,
  provenance, SARIF) resolve relative to the manifest file, not the process
  CWD — `sorseal analyze --manifest path/to/sorseal.toml` now works from any
  directory instead of silently scanning the wrong tree.
- **Windows builds.** `record`/`verify` run the build command via `cmd /C`
  (Git Bash's `sh` is not guaranteed on Windows).
- **Webhook backstop.** `watch` caps each webhook delivery at 15s so a silent
  endpoint cannot stall the monitor loop.

## v0.2.0 (2026-09-11)

Released. SHA-256 checksums and five platform binaries are attached to the
[`v0.2.0` GitHub release](https://github.com/BreachDirect/sorseal/releases/tag/v0.2.0).

### Detection engine

- **Four new rules** (16 total): `SORSEAL-113` oracle-price-feed,
  `SORSEAL-114` flash-loan-approve, `SORSEAL-115` wasm-unreachable-export,
  `SORSEAL-116` wasm-no-exports.
- **Confidence scores.** Every finding now carries a `confidence`
  (low/medium/high) separate from severity, surfaced in console, JSON, Markdown,
  and SARIF — derived from per-rule metadata so the sealed analysis digest is
  unchanged. Rules that need data-flow are honestly marked low/medium
  confidence (see `RULES.md`).
- **WASM-level scanning.** `sorseal analyze --wasm` scans the compiled artifact
  bytecode — traps (`unreachable`) and exports — catching what source scanning
  cannot. Dependency-free section walker (`src/wasm_scan.rs`).
- **~2–3× faster analysis.** Source lines are lexed (comment/string-stripped)
  once per file instead of repeatedly per rule; behavior and digests identical
  (golden-locked). A new perf smoke test (`tests/perf.rs`) keeps a ~200k-line
  tree well under a second in release.

### Engineering

- Multi-platform release binaries (Linux/macOS/Windows) with SHA-256 checksums.
- GitHub Action gains `mode` (`verify`/`analyze`/`both`) and `fail-on`.
- `sorseal hook install` — pre-commit integration that blocks commits on a
  drifted/unaudited tree.
- CI test matrix now runs on Ubuntu, macOS, and Windows.
- New good-first-issue drafts for the roadmap: data-flow/taint confidence,
  extensible custom rules, `npx sorseal` wrapper, VS Code extension, hosted
  verify-any-contract page + badge, threshold attestations, provenance-path
  golden tests.

### Docs

- `RULES.md` — per-rule rationale ("why these 16 and not others"), confidence
  ladder, and rule changelog.
- README: comparison vs Slither / cargo-audit / cargo-deny, full 16-rule table
  with confidence, `--wasm` quick start.

## v0.1.x (initial)

- Provenance sealing/verification, reporting, SARIF + GitHub Action, SLSA v1.0
  attestations, on-chain verification + upgrade audit, fund-free
  `simulate-onchain` demo, `watch` file-integrity monitoring.
- First 12 detection rules (`SORSEAL-101..112`) with `--seal`, `--fail-on`,
  `--explain`, and inline suppressions.