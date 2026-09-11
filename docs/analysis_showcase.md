# Analysis showcase — sorseal against real contracts

This page demonstrates `sorseal analyze` on two example Soroban contracts
shipped in this repository:

| Example | Contract | Full analysis output |
| --- | --- | --- |
| `examples/vulnerable-contract` | Teaching contract, every function contains a known-fragile Soroban pattern | 20 findings (6 Critical · 3 High · 9 Medium · 2 Low) |
| `examples/demo-contract` | Clean upgradeable testnet contract | 0 findings |

Both runs are reproducible locally:

```bash
cd examples/vulnerable-contract && sorseal analyze
cd examples/demo-contract        && sorseal analyze
```

`cargo install sorseal --locked` or `cargo run --release --` both work; the
CLI needs no network and nothing beyond the source tree.

## vulnerable-contract

### Run head

```
Sorseal — vulnerable-contract analyze :: vulnerable-contract

Critical  SORSEAL-101  src/lib.rs:23 — function mutates contract state or moves value without `require_auth`; an unauthenticated caller may drive changes  (high confidence)
Medium    SORSEAL-112  src/lib.rs:23 — caller/address parameter used without `require_auth`; the address may be spoofable  (medium confidence)
Medium    SORSEAL-103  src/lib.rs:25 — unchecked arithmetic on a likely value quantity; consider `checked_add/sub/mul` to guard against overflow  (medium confidence)
Critical  SORSEAL-101  src/lib.rs:32 — function mutates contract state or moves value without `require_auth`; an unauthenticated caller may drive changes  (high confidence)
High      SORSEAL-102  src/lib.rs:32 — possible reentrancy: the function mutates state and makes an external/invoke call without `require_auth`  (medium confidence)
... (full run lists all 20)

20 findings — Critical: 6 · High: 3 · Medium: 9 · Low: 2
analysis digest sha256 437ec280728c
```

### What each vulnerable pattern triggered

| Rule | Title | Designer bug it catches | Count |
| --- | --- | --- | --- |
| `SORSEAL-101` | missing-authorization | VULN-A/B/D/E/G — state mutations with no `require_auth` | 5 (Critical) |
| `SORSEAL-108` | unsafe-code | VULN-G — `unsafe` block in sandboxed contract | 1 (Critical) |
| `SORSEAL-102` | reentrancy | VULN-B — state write before cross-contract invoke, no guard | 1 (High) |
| `SORSEAL-105` | unchecked-transfer | VULN-E — transfer with no prior balance read | 1 (High) |
| `SORSEAL-111` | insufficient-balance-check | VULN-E — token op without balance/allowance check | 1 (High) |
| `SORSEAL-103` | unchecked-arithmetic | VULN-C — `balance - amount`, `seed * rate` | 6 (Medium) |
| `SORSEAL-106` | external-call-without-guard | VULN-B — `invoke_contract` with no reentrancy guard | 1 (Medium) |
| `SORSEAL-112` | unauth-address-param | VULN-A/E — `Address` param never authenticated | 2 (Medium) |
| `SORSEAL-104` | panic-on-reachable-path | VULN-D — `panic!`/`unwrap` on caller-reachable path | 2 (Low) |

The designer bugs in the fixture (comments `VULN-A`…`VULN-I` in `src/lib.rs`)
are all caught by the rule set — none of the teaching patterns slip through.

## demo-contract

```
Sorseal — demo-contract analyze :: demo-contract

CLEAN   no findings in source

0 findings — Critical: 0 · High: 0 · Medium: 0 · Low: 0
analysis digest sha256 e3b0c44298fc
```

The upgradeable testnet demo contract (used by `scripts/demo.sh`) analyzes
clean under the same rule set, which also forms the base line for the CI gate
(`sorseal analyze --fail-on Critical` in the pull-request workflow).

## Reproducibility

A sealed analysis write a signed digest of the findings:
`sorseal analyze --seal` embeds the finding-digest into the provenance file,
and `sorseal verify --provenance <file>` recomputes it — so a claim like
"this contract was scanned with these exact findings" can be checked by
anyone, offline.