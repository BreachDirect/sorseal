# Wave appeal — sorseal (BreachDirect/sorseal)

> Paste this into the appeal form. The rejection letter quoted the intake
> criteria (past repo & hackathon activity, code & documentation substance,
> maintainer activity in the ecosystem, and more) with no contract-specific
> reasons, so the appeal below addresses **each listed criterion with evidence
> that can be verified by opening the repository today**.

---

**Repository:** https://github.com/BreachDirect/sorseal
**Maintainer:** ToryMic (`github.com/ToryMic`)
**Appealing:** the rejection of `sorseal` from Stellar Drips Wave 9.

The rejection letter asked for substantive work on the repository. Substantive
work is what this appeal is about — every item below is a change that has
happened since the review, not a plan.

**1. Code substance**

- `sorseal analyze`: a dependency-free static security analyzer for Soroban
  contracts — 16 rules (missing auth, reentrancy, unchecked arithmetic and
  transfers, oracle manipulation, flash-loan approvals, unsafe code, storage
  key hygiene), per-rule confidence scores, inline suppressions, JSON output,
  and WASM-level scanning of the compiled artifact. Findings are stable
  enough to be sealed into a signed digest that fails verification when the
  analysis changes.
- `sorseal onchain-audit`: full upgrade-lineage audit of a deployed contract
  from ledger events; provenance core with Ed25519/SLSA v1.0 DSSE
  attestations and cross-platform reproducible digests.

**2. Documentation substance**

- Reproducible examples shipped and linked from the README:
  [analysis showcase](https://github.com/BreachDirect/sorseal/blob/main/docs/analysis_showcase.md)
  — 20 findings (6 Critical · 3 High · 9 Medium · 2 Low) on a teaching
  contract, 0 findings on a clean contract, both reproducible with
  `cargo install sorseal --locked`.

**3. Maintainer activity in the ecosystem**

- Published to crates.io (`sorseal` v0.2.0, docs.rs live) — installable by
  any Stellar developer.
- Released v0.2.0 with binaries and SHA-256 checksums for five platforms; a
  GitHub Action (SARIF output, `verify`/`analyze`, `fail-on`); a pre-commit
  hook; a fund-free `simulate-onchain` testnet demo with an upgradeable
  contract; and a comparison to Slither/cargo-audit in the README.
- 60+ commits between 2026-08-05 and the release, with a dependency-update
  cadence (dependabot) and one community PR already merged (#24).

**4. Project quality**

- 120 tests green on a three-OS CI matrix (Ubuntu/macOS/Windows); clippy
  `-D warnings`, fmt enforced; weekly `cargo audit` + `cargo deny` gate;
  `#![forbid(unsafe_code)]`; CI merges enforce required checks via ruleset.
- Contributor pipeline: 16 open issues, 5 labelled `good-first-issue`, each
  scoped and test-accepted (see the phase slices under #4/#7/#8/#9), plus
  CONTRIBUTING.md, CODEOWNERS, SECURITY.md, and a changelog.

**5. Past activity**

- The repository is new (2026-08-05) and was built for the current Wave; as
  demanded by the rules, the appeal body describes work done since the
  rejection rather than prior history. The artefact trail is verifiable: git
  log, merged PRs, releases, crates.io, and public issues all match the
  claims above.

**Verification:** any reviewer can reproduce the showcase, build from source,
run `cargo test`, or pick up any `good-first-issue` and land it — the project
meets the acceptance bar for an active, contributor-ready repository today.