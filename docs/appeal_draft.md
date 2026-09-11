# Wave appeal — sorseal (BreachDirect/sorseal)

> Paste this into the appeal form. Insert the original rejection quote (if one
> was provided) in the bracketed section and trim the "Format-check" paragraph
> if the form has a length limit.

---

**Repository:** https://github.com/BreachDirect/sorseal
**Maintainer:** ToryMic (`github.com/ToryMic`)
**Appealing:** the rejection of `sorseal` from Stellar Drips Wave 9.

Since the original review, the project has changed materially on every axis the
Wave rubric measures: code, project quality, and activity.

**1. Substantive code changes since rejection**

- `sorseal analyze`: a dependency-free static security analyzer for Soroban
  contracts — 16 rules (missing auth, reentrancy, unchecked arithmetic and
  transfers, oracle manipulation, flash-loan approvals, etc.), per-rule
  confidence scores, inline suppressions, JSON output, and WASM-level scanning
  of the compiled artifact. Findings stay reproducible enough to be sealed into
  a signed digest — verification fails if the analysis secrets differ.
- `sorseal onchain-audit`: full upgrade-lineage audit of a deployed contract
  from ledger events.
- Provenance core: Ed25519/SLSA v1.0 DSSE attestations, sealed reproducible
  builds, cross-platform reproducibility (path normalization fixed so digests
  are identical on macOS/Windows/Linux).

**2. Project quality**

- 120 tests (unit, CLI, golden-file regression, perf), all green on a three-OS
  CI matrix (Ubuntu/macOS/Windows). Clippy `-D warnings`, `cargo fmt` enforced.
- Weekly `cargo audit` + `cargo deny` gate (advisories, yanked deps, license
  checks); `#![forbid(unsafe_code)]`; dependency tree deliberately small.
- Released **v0.2.0** with signed checksums and binaries for five platforms, a
  GitHub Action (SARIF output, `verify`/`analyze` modes, `fail-on`), docs
  (architecture, threat model, per-rule rationale), SECURITY.md, CODEOWNERS,
  changelog, and a mergable ruleset with enforced required checks.
- Community contribution merged: `md_escape` hardening (PR #24).

**3. Activity**

- 60+ commits between 2026-08-05 and the release; regular dependency
  maintenance (dependabot), tagged release, and an active triaged backlog:
  4 open `good-first-issue`s, each scoped to a weekend, plus a phased roadmap
  (keyless OIDC signing, multi-signer rotation, hosted verification API).
- A `sorseal hook` pre-commit integration and an end-to-end testnet demo
  (fund-free `simulate-onchain`) keep the tool usable day one by Stellar
  developers.

**4. Ecosystem relevance**

- No comparable tool exists for Soroban/WASM provenance (it also covers the
  real upgrade risk: wasm hashes change on `update_current_contract_wasm`, so
  deployed bytecode must be re-verified). The recommendations of a recent
  ecosystem audit on upgrading/auditing Soroban contracts map directly to what
  `sorseal` automates.

[If the review quoted specific concerns, paste them here and address each:
**Original concern:** ___ / **What changed:** ___]

**Format-check:** the repository is live (`main`), public, MIT-licensed, with
real commits on a regular cadence (most recent: {DATE}), so the acceptance
criteria for an active, contributor-ready project are met today and can be
verified by opening any of the `good-first-issue` labels.