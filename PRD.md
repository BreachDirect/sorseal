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

## Goals (Phase 3 — shipped)

- **Static vulnerability analysis** — `sorseal analyze` inspects a contract's
  Rust source for known-fragile Soroban patterns (missing `require_auth`,
  reentrancy, unchecked value arithmetic, panic on caller input, oracle
  manipulation, approve-and-exploit shapes) and reports them with a stable rule
  id, severity, and remediation.
- **16 rules with confidence scores** — the rule set covers the patterns that
  drain Soroban contracts, each with a *severity* (impact) and an independent
  *confidence* (how sure the lexical scan is), so a multi-finding report can be
  triaged without treating every line as equally urgent.
- **WASM-level scanning** — `sorseal analyze --wasm` additionally scans the
  compiled artifact bytecode for traps (`unreachable`) and exports that source
  scanning cannot see.
- **Audit-in-the-loop** — the finding digest is sealed into the provenance
  record (`analyze --seal`), so the audit itself is tamper-evident and
  reproducible, exactly like the wasm + source digests.
- **Report formats for audit trails** — findings render as console, Markdown
  (deliverable) or SARIF (GitHub Code Scanning), consistent with the `verify`
  output.
- **Showcase fixture** — a bundled, intentionally-vulnerable example contract
  (`examples/vulnerable-contract`) that a fresh `sorseal analyze` flags
  immediately, proving the tool finds real Soroban issue classes.
- **Fund-free on-chain demo** — `sorseal simulate-onchain` (and
  `scripts/sim-demo.sh`) drives the real `onchain-verify` / `onchain-audit`
  code paths against an in-memory ledger derived from the sealed provenance, so
  the full seal → deploy → upgrade → verify → audit story is reproducible with
  zero funds and no network — including the drifted/unsealed-deployment failure
  case.
- **Performance guarantee** — the analyzer lexes each source line exactly once
  (not ~16×); a kept-in-regression-guard perf test (`tests/perf.rs`) keeps a
  ~200k-line tree well under budget in debug and under a second in release.

## Goals (Phase 4 — in progress)

- **Data-flow awareness** — a light taint/data-flow pass so the heuristic rules
  (unchecked-transfer, oracle-price-feed, flash-loan-approve, unchecked-env-caller)
  can confirm whether a value traces back to user input or a balance read, and
  re-score those findings from low/medium to high confidence instead of relying
  on patterns alone.
- **Extensible rules** — team-local custom detection patterns via a config file,
  turning sorseal from a fixed rule set into a platform.
- **`npx sorseal` wrapper + VS Code extension** — a zero-install path for
  JS-first Soroban teams, and inline editor squiggles.
- **Hosted verify-any-contract page + provenance badge** — paste a contract ID
  to see provenance status; embed a README badge that links back to the verify
  page.
- **Provenance regression tests** — extend the golden-diff pattern beyond
  `analyze` to `record`/`verify`/`sign` so the seal path has the same tamper-
  detection guarantee as the rule set.

## Non-goals

- OIDC-based CI signing (no trusted third party at runtime).
- A web dashboard or drift history (the hosted verify page above is a separate,
  explicitly opted-in service).
- Full semantic/WASM-level analysis or formal verification — the analyzer is
  deliberately lexical and pattern-based, flagging *suspicious* constructs for
  a human reviewer rather than proving absence of bugs.

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
9. `sorseal watch --init` scaffolds a starter `sorseal.watch.toml`.
10. `sorseal watch --once` hashes listed files, records baselines on first run,
    detects drift on subsequent runs, and exits non-zero on any failure.
11. `sorseal watch --once --sarif` produces a valid SARIF report for file
    integrity findings.
12. `sorseal watch` (daemon mode) re-checks on the configured interval and
    sends alerts to Discord / Telegram / POST webhooks on drift.
13. `sorseal analyze` on the bundled `examples/vulnerable-contract` reports
    findings across all severities (Critical through Low) and a deterministic
    finding digest.
14. The finding list is stable: unchanged source produces an identical digest
    across runs, and a changed source changes it.
15. `sorseal analyze --seal` appends a valid `analysis` entry to the provenance
    and `sorseal verify` accepts it; tampering with the sealed digest or the
    source under it fails verification.
16. `sorseal analyze --sarif findings.sarif` produces valid SARIF 2.1.0
    consumable by GitHub Code Scanning.
17. `sorseal analyze --format markdown` produces an audit-trail document
    suitable for attaching to a security review.
18. `sorseal simulate-onchain` on a provenance with multiple artifacts
    reconstructs the upgrade lineage and reports the current deployment PASSED;
    `--deploy-wasm` with an unsealed hash reports FAILED with a clear
    `current ... NONE` finding. It needs no network and no funded account.

## Out of scope

Anything that requires network access at runtime for the core path (all hashing
is local and offline; the only networked commands are the explicitly on-chain
`onchain-verify` and the webhook alerts in `watch`). The tool must not make
assumptions about how the user deploys — it only asserts reproducibility of the
declared artifacts and, on request, equivalence with what is actually deployed.
