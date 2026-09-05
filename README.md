# sorseal

**Provenance + vulnerability scanning for Soroban/WASM artifacts** — prove deployed bytecode matches source, and scan contract source for security patterns before you ship.

sorseal seals the build: it records SHA-256 digests for your contract artifacts (WASM + source tree + toolchain + git commit), then verifies at any time that a clean rebuild reproduces those exact digests. On top of that provenance base it statically scans contract source for known-fragile Soroban patterns (`sorseal analyze`), seals the finding digests into the audit trail, and can monitor files for unauthorized changes, alerting when drift is detected.

## Install

```bash
cargo install sorseal --locked
```

Or build from source:

```bash
git clone https://github.com/BreachDirect/sorseal.git
cd sorseal
cargo build --release
```

**Requirements:** Rust 1.85+ and `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`).

## Quick start

### Contract provenance

```bash
# scaffold a manifest
sorseal init

# seal (record digests)
sorseal record

# verify (rebuild + compare)
sorseal verify
```

### File integrity monitoring

```bash
# generate a starter config
sorseal watch --init

# run a single check (for cron)
sorseal watch --once

# run as a daemon
sorseal watch
```

## Commands

| Command | Description |
|---|---|
| `sorseal init` | Scaffold a `sorseal.toml` manifest for your project |
| `sorseal record` | Build artifacts and write `sorseal.provenance.json` |
| `sorseal verify` | Rebuild and verify artifacts match the sealed provenance |
| `sorseal report` | Render provenance as console, JSON, or Markdown |
| `sorseal keygen` | Generate an Ed25519 keypair for signing attestations |
| `sorseal sign` | Sign the provenance as an in-toto/SLSA v1.0 attestation |
| `sorseal verify-attestation` | Verify a signed attestation against a public key |
| `sorseal onchain-verify` | Compare on-chain WASM hash against sealed provenance |
| `sorseal onchain-audit` | Audit a contract's full on-chain upgrade history |
| `sorseal simulate-onchain` | Fund-free, offline on-chain verify + audit demo |
| `sorseal analyze` | Statically scan contract source for Soroban vulnerability patterns |
| `sorseal watch` | Monitor files for integrity drift and alert on changes |

## Features

### Contract provenance

Seal your Soroban contract builds with cryptographic proof that the deployed bytecode matches your source code.

```bash
$ sorseal record
Sorseal — my-contract

sealed  my-contract :: wasm  sha256 a1b2c3d4e5f6... (24576 bytes)
sealed  my-contract :: source sha256 f6e5d4c3b2a1...

toolchain rustc 1.85.0 · git commit 8a3f2b1c (clean)

provenance written to sorseal.provenance.json
```

```bash
$ sorseal verify
Sorseal — my-contract verify

PASSED  my-contract :: wasm — sha256 matches sealed digest
PASSED  my-contract :: source — sha256 matches sealed digest
PASSED  my-contract :: command — build_command unchanged

3 checks: 3 passed, 0 failed, 0 errored
```

### SARIF output for CI

```bash
sorseal verify --sarif results.sarif
```

Upload to GitHub Code Scanning with the [sorseal GitHub Action](action.yml):

```yaml
- uses: BreachDirect/sorseal@main
  with:
    sarif-file: sorseal.sarif
```

### Static vulnerability analysis

`sorseal analyze` statically scans a contract's Rust source for known-fragile
Soroban patterns — the same ones that let value-holding contracts get drained —
and reports them with a severity and remediation, so findings can be triaged
and fed straight into CI or an audit report.

```bash
$ sorseal analyze
Sorseal — vulnerable-contract analyze :: vulnerable-contract

Critical  SORSEAL-101  src/lib.rs:23 — function mutates contract state or moves value without `require_auth`; an unauthenticated caller may drive changes
Medium    SORSEAL-103  src/lib.rs:25 — unchecked arithmetic on a likely value quantity; consider `checked_add/sub/mul` to guard against overflow
Critical  SORSEAL-101  src/lib.rs:32 — function mutates contract state or moves value without `require_auth`; an unauthenticated caller may drive changes
High      SORSEAL-102  src/lib.rs:32 — possible reentrancy: the function mutates state and makes an external/invoke call without `require_auth`
Medium    SORSEAL-103  src/lib.rs:32 — unchecked arithmetic on a likely value quantity; consider `checked_add/sub/mul` to guard against overflow
Medium    SORSEAL-103  src/lib.rs:35 — unchecked arithmetic on a likely value quantity; consider `checked_add/sub/mul` to guard against overflow
Medium    SORSEAL-106  src/lib.rs:37 — external `invoke_contract`/`call_contract` call detected without an adjacent `non_reentrant` guard
Critical  SORSEAL-101  src/lib.rs:42 — function mutates contract state or moves value without `require_auth`; an unauthenticated caller may drive changes
High      SORSEAL-105  src/lib.rs:42 — token `.transfer`/`.transfer_from` call with no prior balance/allowance read; the transferred amount is not derived from what this contract actually holds
Critical  SORSEAL-101  src/lib.rs:49 — function mutates contract state or moves value without `require_auth`; an unauthenticated caller may drive changes
Medium    SORSEAL-103  src/lib.rs:49 — unchecked arithmetic on a likely value quantity; consider `checked_add/sub/mul` to guard against overflow
Medium    SORSEAL-103  src/lib.rs:55 — unchecked arithmetic on a likely value quantity; consider `checked_add/sub/mul` to guard against overflow
Low       SORSEAL-104  src/lib.rs:59 — `panic!` or `unwrap()` on a code path that may be reachable from callers; prefer returning a Result and reverting with a clear error

13 findings — Critical: 4 · High: 2 · Medium: 6 · Low: 1
analysis digest sha256 b911e3584977
```

Detection rules (each with a stable id, severity, and remediation):

| Rule | Severity | Detects |
|---|---|---|
| `SORSEAL-101` missing-authorization | Critical | State/value mutation without `require_auth` |
| `SORSEAL-102` reentrancy | High | External call after state mutation, no guard |
| `SORSEAL-103` unchecked-arithmetic | Medium | Raw `+`/`-`/`*` on amounts instead of `checked_*` |
| `SORSEAL-104` panic-on-input | Low | `panic!`/`unwrap()` on a caller-reachable value path |
| `SORSEAL-105` unchecked-transfer | High | `.transfer`/`.transfer_from` amount not derived from a prior balance/allowance read |
| `SORSEAL-106` missing-reentrancy-guard | Medium | `invoke_contract`/`call_contract` without `non_reentrant` |

Output as JSON, Markdown (audit deliverable), or SARIF (code scanning):

```bash
sorseal analyze --format json        # machine-readable findings + digest
sorseal analyze --format markdown > audit.md
sorseal analyze --sarif findings.sarif
```

Run `sorseal analyze` as a CI gate with a severity threshold — the process
exits non-zero when findings at or above the threshold exist:

```bash
sorseal analyze --fail-on High       # gate the build on no High/Critical findings
```

Neither `--fail-on` nor any other flag needs to be set for ordinary use:
without a gate, `analyze` is report-only and exits 0 even with findings.

Explain a rule without scanning, and build suppressions for reviewed/acceptable
findings:

```bash
sorseal analyze --explain SORSEAL-105   # guidance + fix for one rule
sorseal analyze --explain               # list every rule
```

```rust
// sorseal:ignore SORSEAL-104 reviewed: this input is validated by the caller
let rate: i128 = env.storage().instance().get(&KEY).unwrap();
```

Findings tagged with `// sorseal:ignore <RULE>` on the line above are dropped
(counts, SARIF, and the sealed digest all exclude them); add `--no-ignore` to
temporarily see everything. Because suppressions change the finding set, a
suppressed run seals a different digest than an unsuppressed one.

And because the audit itself must be tamper-evident, the finding digest can be
sealed into the provenance record alongside the wasm + source digests:

```bash
sorseal analyze --seal
```

`--seal` appends `analysis` entries (finding count, worst severity, SHA-256 of
the stable finding serialization, and timestamp) to `sorseal.provenance.json`,
so `sorseal verify` proves the audited source was not altered since the
analysis was produced.

Try it on the bundled intentionally-vulnerable example contract:

```bash
cd examples/vulnerable-contract
sorseal analyze
```

### Signed attestations

```bash
sorseal keygen
sorseal sign --key sorseal.key
sorseal verify-attestation --public-key sorseal.pub
```

Produces Ed25519-signed in-toto Statements (SLSA v1.0 predicate, DSSE envelope) so releases can be authenticated by public key alone.

### On-chain verification

Check that a deployed contract's on-chain WASM hash matches your sealed provenance:

```bash
sorseal onchain-verify --contract-id CABC123...
```

Audit the full upgrade lineage of a contract:

```bash
sorseal onchain-audit --contract-id CABC123...
```

### On-chain demo without funds

A live deploy/upgrade demo needs a funded account to pay transaction fees.
`sorseal simulate-onchain` drives the **same** on-chain code paths (the
`getLedgerEntries` XDR decode, `getEvents` paging, upgrade-lineage
reconstruction, and provenance cross-checking) against an in-memory ledger
derived from your provenance — so the whole seal → deploy → upgrade → verify →
audit story is reproducible on any machine with **zero funds and no network**:

```bash
./scripts/sim-demo.sh
```

The first case is a fully-sealed contract (verify **PASSED**, audit **PASSED**,
every version in the lineage attested). The second injects an unsealed current
deployment and shows the tool catching the drift (verify **FAILED**, audit
**FAILED** with `current ... NONE`). Run just one case yourself:

```bash
# clean: current deployment is sealed
sorseal simulate-onchain

# drift: simulate an unsealed current deployment
sorseal simulate-onchain --deploy-wasm 9999999999999999999999999999999999999999999999999999999999999999
```

### File integrity monitoring

Monitor critical files for unauthorized changes:

```bash
$ sorseal watch --once
Sorseal — file integrity watch

PASSED  /etc/nginx/nginx.conf — unchanged
FAILED  /usr/bin/sshd — sha256 mismatch: baseline abc123, current def456
PASSED  /etc/passwd — unchanged

3 files checked: 2 passed, 1 failed
```

Configure with `sorseal.watch.toml`:

```toml
[watch]
interval_secs = 300

[[watch.paths]]
path = "/etc/nginx/nginx.conf"
label = "nginx-config"

[[watch.paths]]
path = "/usr/bin/sshd"
label = "sshd-binary"

[[watch.webhooks]]
type = "discord"
url = "https://discord.com/api/webhooks/..."

[[watch.webhooks]]
type = "telegram"
token = "your-bot-token"
chat_id = "123456"
```

## Ecosystem work & Wave evidence

This repository is part of a broader set of contributions to the Stellar / Soroban ecosystem. See [WAVE_EVIDENCE_ToryMic.md](WAVE_EVIDENCE_ToryMic.md) for a curated list of related projects, demos, and tooling maintained by ToryMic, including testing, indexers, contract frameworks, and privacy/payment prototypes.

- Evidence file: [WAVE_EVIDENCE_ToryMic.md](WAVE_EVIDENCE_ToryMic.md)
- Maintainers: [MAINTAINERS.md](MAINTAINERS.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide (setup,
code style, PR process, testing requirements).

### Getting involved in Wave 9

This repository is a **Stellar Drips Wave 9** project. The quickest ways to
contribute right now, in rough order of leverage for the repo *and* for Wave 9
contribution credit:

1. **Pick up a `good-first-issue`** — issues labelled
   `good-first-issue` are scoped, reviewable, and small enough to land in a
   weekend. Say you're taking one in the thread, then reference the issue + the
   Wave in your PR so it can be attributed and rewarded.
2. **Run `sorseal analyze` on your own Soroban contract** and file a bug/feature
   report with real output. Every genuine finding (or rule gap) you surface
   improves the analyzer and earns an issue + PR of its own.
3. **Add a detection rule** — the rule table below lists what `analyze` covers
   today. New Soroban issue classes (unchecked balance, missing auth branches,
   oracle/price reads, storage-key collisions) make great intermediate issues.
4. **Document** — rule-explanation pages, worked examples, tips for integrating
   `analyze --fail-on` into GitHub Actions, and real testnet walkthroughs are
   high-value, low-risk contributions.
5. **Post captured evidence** — run `scripts/sim-demo.sh` and `sorseal analyze`
   against the `examples/vulnerable-contract`, then attach the console + SARIF
   + proven JSON output to PRs and to `WAVE_EVIDENCE_ToryMic.md`. PRs that show
   the tool actually catching a bug or proving a deployment are the strongest
   Wave evidence. (No funded testnet account is required — see the
   `simulate-onchain` demo above.)

> **Tip for contributors:** commits and PRs with real captured CLI output
> (console + SARIF + proven JSON) are far stronger Wave evidence than code-only
> changes — show the tool actually finding (or verifying) things.

### Project roadmap

Current shipped & in-flight capabilities:

| Area | Command | Status |
|---|---|---|
| Build provenance | `record` / `verify` | shipped |
| Reporting | `report` (console/JSON/Markdown) | shipped |
| CI / SARIF | `verify --sarif` + GitHub Action | shipped |
| Signed attestations | `keygen` / `sign` / `verify-attestation` | shipped |
| On-chain verification | `onchain-verify` | shipped |
| Upgrade-lineage audit | `onchain-audit` | shipped |
| On-chain demo (no funds) | `simulate-onchain` | shipped |
| File integrity watch | `watch` | shipped |
| Vulnerability scan | `analyze` (6 rules, `--seal`) | shipped |
| Vulnerability CI gate | `analyze --fail-on <severity>` | shipped |
| JSON findings output | `analyze --format json` | shipped |
| Self-documenting rules | `analyze --explain [RULE]` | shipped |
| Finding suppressions | `analyze` inline `// sorseal:ignore` | shipped |
| Golden-file digest tests | `tests/analyze_golden.rs` | shipped |

## License

MIT
