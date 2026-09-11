# Wave appeal — sorseal (BreachDirect/sorseal)

> Paste the block below into the appeal form under
> "What development work / improvements have you made since the repo was
> initially rejected?" It is one continuous answer (~530 words, well under the
> 10,000-char limit). Every claim is verifiable by opening the repository.

---

## What development work / improvements have you made since the repo was initially rejected?

Since the repository's rejection, substantive and verifiable work has landed on
every axis the review evaluates — code, project quality, and ecosystem
relevance. Each item below can be checked in minutes by opening the repository,
running its tests, or reproducing its demo.

**1. Code — a real security analyzer landed.**

`https://github.com/BreachDirect/sorseal` now ships `sorseal analyze`: a
dependency-free static security analyzer for Soroban contracts with a 16-rule
engine (SORSEAL-101..116) covering the attack classes that actually drain
contracts — missing authorization, reentrancy, unchecked arithmetic and
transfers, oracle manipulation, flash-loan approvals, unsafe code, and
storage-key hygiene. Every finding carries a confidence score; findings export
to JSON and SARIF; and the digest of a scan can be sealed into the provenance
file and re-verified offline, so "this exact analysis was produced for this
exact source" is independently checkable.

Analysis is reproducible from shipped examples: the teaching contract produces
20 findings (6 Critical · 3 High · 9 Medium · 2 Low), the clean demo contract
produces 0, and both sealed digests are documented in
`docs/analysis_showcase.md`. A WASM-level scanner (`--wasm`) also inspects the
compiled artifact for traps and export holes that source scanning cannot catch.
`sorseal onchain-audit` reconstructs a deployed contract's full upgrade lineage
from ledger events.

**2. Project quality — release-grade engineering.**

- **Release v0.2.0**: signed binaries and SHA-256 checksums for five platforms,
  a GitHub Action (SARIF output, `verify`/`analyze` modes, `fail-on` gate), and
  a pre-commit hook.
- **Testing**: 120 tests (unit, CLI, golden-regression, perf) green on the CI
  matrix across Ubuntu, macOS, and Windows; clippy `-D warnings` and fmt
  enforced on every push.
- **Security posture**: weekly `cargo audit` + `cargo deny` (advisories, yanked
  deps, license compliance), `#![forbid(unsafe_code)]`, a small dependency
  tree, and a SECURITY.md disclosure policy.
- **Process**: CI merges are blocked by a branch ruleset enforcing the real
  required-job contexts; docs cover architecture, per-rule rationale, and
  contribution process; CODEOWNERS and a changelog are in place.
- **Community**: a non-maintainer PR was merged (PR #24, report-output
  hardening), dependency updates flow on a dependabot cadence, and the backlog
  holds 16 triaged issues including 5 scoped good-first-issues with explicit
  acceptance criteria.

**3. Ecosystem relevance and maintainer activity.**

- Published to crates.io (`sorseal` v0.2.0, docs.rs auto-built) — installable
  by any Soroban developer via `cargo install sorseal`.
- Engaged directly with Stellar tooling: filed
  `https://github.com/stellar/stellar-cli/issues/2723`, a feature request for a
  command that prints a deployed contract's live wasm hash — the exact
  verification gap sorseal automates.
- A fund-free `simulate-onchain` testnet demo deploys and upgrades a real
  contract so reviewers can exercise the tool with no wallet funds.
- Maintainer activity has continued through and past the review: 60+ commits,
  regular releases, and a roadmap (keyless OIDC signing, multi-signer rotation,
  hosted verification endpoint) sliced into landable units.

The repository is not the same project that was reviewed. Every criterion the
review weighs has demonstrably improved, and a reviewer can confirm it hands-on
— `cargo test`, reproduce the showcase, or pick up any good-first-issue today.