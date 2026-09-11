<p align="center">
  <strong>Sorseal — the provenance layer for Soroban</strong><br/>
  <em>Prove your smart contract wasn't swapped after deployment — and catch the bugs that drain contracts before you ship.</em>
</p>

<p align="center">
  <a href="https://github.com/BreachDirect/sorseal/actions/workflows/ci.yml"><img src="https://github.com/BreachDirect/sorseal/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/BreachDirect/sorseal/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/rust-1.85+-orange.svg" alt="MSRV 1.85">
  <a href="https://github.com/BreachDirect/sorseal/actions/workflows/security.yml"><img src="https://github.com/BreachDirect/sorseal/actions/workflows/security.yml/badge.svg" alt="Security audit"></a>
  <a href="https://github.com/BreachDirect/sorseal/blob/main/docs/WAVE_EVIDENCE_ToryMic.md"><img src="https://img.shields.io/badge/stellar-wave_9-6B3FA0.svg" alt="Wave 9"></a>
</p>

---

## The problem

Every Soroban deployment is a trust assumption. Was the WASM on-chain built from the source you reviewed? Was it modified before deploy? Did someone sneak in a function that drains the treasury?

**Sorseal answers these questions.** It seals your build with cryptographic proof, scans your source for the patterns that let contracts get drained, and lets anyone verify the chain from source to deployment — all from the CLI.

## Install

```bash
# prebuilt binary (fastest)
# Download the archive for your platform from the latest release,
# then extract the `sorseal` binary onto your PATH:
#   https://github.com/BreachDirect/sorseal/releases/latest
#   assets: sorseal-<version>-x86_64-unknown-linux-gnu.tar.gz
#           sorseal-<version>-aarch64-unknown-linux-gnu.tar.gz
#           sorseal-<version>-x86_64-apple-darwin.tar.gz
#           sorseal-<version>-aarch64-apple-darwin.tar.gz
#           sorseal-<version>-x86_64-pc-windows-msvc.zip
# Verify integrity against sorseal-<version>-checksums.txt.

# or from source
git clone https://github.com/BreachDirect/sorseal.git && cd sorseal && cargo install --path . --locked
```

**Requirements:** Rust 1.85+ and `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`).

## See it in action

```
$ sorseal analyze

Critical  SORSEAL-101  src/lib.rs:23 — function mutates state without require_auth  (high confidence)
High      SORSEAL-102  src/lib.rs:32 — reentrancy: state mutation + external call, no guard  (medium confidence)
High      SORSEAL-105  src/lib.rs:42 — transfer amount not derived from balance read  (medium confidence)

3 findings — Critical: 1 · High: 2 · Medium: 0 · Low: 0
```

```
$ sorseal verify

PASSED  my-contract :: wasm     — sha256 matches sealed digest
PASSED  my-contract :: source   — sha256 matches sealed digest
PASSED  my-contract :: command  — build_command unchanged

3 checks: 3 passed, 0 failed, 0 errored
```

> **Try it now:** `cd examples/vulnerable-contract && sorseal analyze`

### On-chain demo without funds

`scripts/sim-demo.sh` walks the full `record → verify → simulate-onchain → onchain-audit` chain against an **in-memory synthetic ledger** — no testnet account, no XLM, no `stellar` CLI. For a live testnet run (needs a funded account), see `scripts/demo.sh`.

## Add one line to your CI

Every pull request gets scanned automatically. Upload results to GitHub Code Scanning:

```yaml
- uses: BreachDirect/sorseal@main
  with:
    sarif-file: sorseal.sarif
```

Or gate on severity — fail the build if any Critical/High finding exists:

```yaml
- uses: BreachDirect/sorseal@main
```

Then add a step:
```yaml
- run: sorseal analyze --fail-on High
```

## Quick start

### Contract provenance

```bash
sorseal init              # scaffold a sorseal.toml manifest
sorseal record            # seal: build + hash + write provenance
sorseal verify            # rebuild and compare digests
```

### Vulnerability scan

```bash
sorseal analyze                     # scan all artifacts
sorseal analyze --wasm              # also scan the compiled WASM bytecode
sorseal analyze --fail-on High      # CI gate: exit non-zero on High/Critical
sorseal analyze --format json       # machine-readable findings
sorseal analyze --sarif out.sarif   # SARIF for code scanning
sorseal analyze --explain           # list all rules
sorseal analyze --seal              # seal finding digest into provenance
```

### File integrity monitoring

```bash
sorseal watch --init    # generate starter config
sorseal watch --once    # single check (for cron)
sorseal watch           # daemon mode with webhook alerts
```

## All commands

| Command | What it does |
|---|---|
| `sorseal init` | Scaffold a `sorseal.toml` manifest |
| `sorseal record` | Build artifacts, write `sorseal.provenance.json` |
| `sorseal verify` | Rebuild and verify artifacts match sealed provenance |
| `sorseal report` | Render provenance as console, JSON, or Markdown |
| `sorseal keygen` | Generate an Ed25519 keypair for signing |
| `sorseal sign` | Sign provenance as an in-toto/SLSA v1.0 attestation |
| `sorseal verify-attestation` | Verify a signed attestation |
| `sorseal onchain-verify` | Compare on-chain WASM hash against sealed provenance |
| `sorseal onchain-audit` | Audit a contract's full upgrade history |
| `sorseal simulate-onchain` | Fund-free offline on-chain verify + audit demo |
| `sorseal analyze` | Scan source for Soroban vulnerability patterns |
| `sorseal watch` | Monitor files for integrity drift, alert on changes |
| `sorseal hook` | Install/uninstall/status for a `verify + analyze` pre-commit hook |

## Detection rules

`sorseal analyze` checks for the patterns that let Soroban contracts get drained, reentered, or crashed. Each rule has a stable id, a severity (how bad an exploit would be) and a confidence (how certain the scan is that the finding is real — exact bytecode/pattern matches are high, heuristic data-flow-adjacent rules are medium/low):

| Rule | Name | Severity | Confidence | What it catches |
|---|---|---|---|---|
| `SORSEAL-101` | missing-authorization | Critical | high | State/value mutation without `require_auth` |
| `SORSEAL-102` | reentrancy | High | medium | External call after state mutation, no guard |
| `SORSEAL-103` | unchecked-arithmetic | Medium | medium | Raw `+`/`-`/`*` on amounts instead of `checked_*` |
| `SORSEAL-104` | panic-on-user-input | Low | high | `panic!`/`unwrap()` on a caller-reachable path |
| `SORSEAL-105` | unchecked-transfer | High | medium | `.transfer` amount not derived from balance read |
| `SORSEAL-106` | missing-reentrancy-guard | Medium | medium | `invoke_contract` without `non_reentrant` |
| `SORSEAL-107` | hardcoded-storage-key | Medium | medium | Hardcoded `Symbol::new()` as persistent storage key — collisions across upgrades |
| `SORSEAL-108` | unsafe-raw-pointer | Critical | high | `unsafe` block or raw pointer deref in contract code |
| `SORSEAL-109` | panic-on-storage-read | Low | high | `unwrap()` on `env.storage()` read — panics if key missing |
| `SORSEAL-110` | admin-key-never-rotated | Medium | low | `OWNER`/`ADMIN` storage write without rotation pattern |
| `SORSEAL-111` | missing-token-balance-check | High | medium | Token operation without verifying contract holds the asset |
| `SORSEAL-112` | unchecked-env-caller | Medium | medium | Caller address used without `require_auth` — spoofable |
| `SORSEAL-113` | oracle-price-feed | Medium | low | Price-feed read with no staleness/auth guard — single-oracle manipulation |
| `SORSEAL-114` | flash-loan-approve | High | low | Allowance granted + external call in the same function |
| `SORSEAL-115` | wasm-unreachable-export | High | high | Deployed WASM body traps with an `unreachable` opcode (source scanners miss it) |
| `SORSEAL-116` | wasm-no-exports | Medium | high | WASM module exports nothing — wrong artifact being sealed |

Run `sorseal analyze --explain SORSEAL-107` for detailed guidance on any rule.

## How sorseal compares

Sorseal is the only tool in this table that ties source analysis to a **sealed, verifiable provenance record for Soroban**. It analyses your *own* contract source where Slither-analogues would, and dresses the results as signed in-toto/SLSA attestations you can verify on-chain.

| Need | Tool | Sorseal's take |
|---|---|---|
| Solidity smart-contract security | Slither | Sorseal covers the Soroban/WASM analogue; here for framing |
| Rust dependency CVEs | cargo-audit / cargo-deny | `record` gates builds the same way; `analyze` is about your own code, not deps |
| Lockfile policy (licenses, duplicates) | cargo-deny | Complementary — `deny.toml` rules apply unchanged to Soroban builds |
| Was your deployed contract swapped? | **—** | **sorseal `record` → `verify` → `onchain-verify` (unique)** |
| Are my build attestations signed? | **—** | **sorseal `sign` (Ed25519 DSSE, SLSA v1.0) (unique)** |
| Does my contract get reentered/drained? | Soroban security reviews (manual) | `sorseal analyze` catches 16 known patterns automatically |

**Why these 16 checks and not others:** the rule set is the minimum that, applied mechanically, misses materially fewer of the vulnerabilities that actually drain Soroban contracts (missing auth, unchecked arithmetic/transfers, reentrancy, oracle manipulation) than a manual review does, while staying deliberately lexical so it has **zero build-time deps and zero false-negative cost from unparseable code**. Rules are pure-pattern and explicitly low-confidence where data flow would be needed — see [RULES.md](RULES.md) for the reasoning per rule and the changelog. Anything beyond that (taint tracking, custom rules) is on the roadmap.

## Architecture at a glance

```
sorseal init         ──→  sorseal.toml (manifest)
sorseal record       ──→  build → hash (WASM + source + toolchain + git) → sorseal.provenance.json
sorseal verify       ──→  rebuild → compare digests → PASSED/FAILED
sorseal analyze      ──→  lexical scan → findings (JSON/console/SARIF/Markdown)
sorseal sign         ──→  Ed25519 DSSE envelope (in-toto/SLSA v1.0)
sorseal onchain-*    ──→  getLedgerEntries/getEvents XDR → verify against provenance
sorseal watch        ──→  hash baseline → drift detection → Discord/Telegram/POST alert
```

## Ecosystem work & Wave evidence

This repository is part of a broader set of contributions to the Stellar / Soroban ecosystem. See [WAVE_EVIDENCE_ToryMic.md](docs/WAVE_EVIDENCE_ToryMic.md) for a curated list of related projects, demos, and tooling maintained by ToryMic, including testing, indexers, contract frameworks, and privacy/payment prototypes.

- Evidence file: [WAVE_EVIDENCE_ToryMic.md](docs/WAVE_EVIDENCE_ToryMic.md)
- Maintainers: [MAINTAINERS.md](MAINTAINERS.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, code style, and PR process.

### Getting involved in Wave 9

This repository is a **Stellar Drips Wave 9** project. The quickest ways to contribute right now:

1. **Pick up a `good-first-issue`** — issues labelled `good-first-issue` are scoped and small enough to land in a weekend.
2. **Run `sorseal analyze` on your own contract** and file a bug/feature report with real output.
3. **Add a detection rule** — new Soroban issue classes (storage-key collisions, oracle manipulation, missing balance checks) make great intermediate issues.
4. **Document** — rule-explanation pages, worked examples, and real testnet walkthroughs.
5. **Post captured evidence** — run `scripts/sim-demo.sh` and attach output to PRs. Real output is stronger Wave evidence than code-only changes.

### Project roadmap

| Area | Status |
|---|---|
| Build provenance (`record`/`verify`) | shipped |
| Reporting (console/JSON/Markdown) | shipped |
| CI / SARIF + GitHub Action | shipped |
| Signed attestations (SLSA v1.0) | shipped |
| On-chain verification + upgrade audit | shipped |
| Vulnerability scan (16 rules, `--wasm`, confidence scores, `--seal`) | shipped |
| CI severity gate (`--fail-on`) | shipped |
| File integrity monitoring | shipped |
| Prebuilt binary releases (Linux/macOS/Windows) | shipped |
| **Detection engine** (data-flow awareness to cut heuristics → low-confidence) | in progress |
| **Extensible rules** (team-local custom patterns via config) | in progress |
| **`npx sorseal` wrapper + VS Code extension** | in progress |
| **Hosted verify-any-contract page + provenance badge** | in progress |

## License

MIT
