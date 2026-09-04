# sorseal — simulated on-chain evidence (fund-free)

Generated with `scripts/sim-demo.sh`. No network, no funded account.


== Case 1 — current deployment sealed: verify PASSED, audit PASSED
simulated on-chain contract 0a0a0a0a0a0a (mock://local) — provenance has 3 artifact(s)
  ledger is served from the sealed provenance; no network, no funds

sorseal onchain-verify (simulated) ...
PASSED  contract :: wasm hash — deployed bytecode matches sealed provenance
         deployed sha256 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
         sealed   sha256 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee

sorseal onchain-audit (simulated) ...
  retaining ledgers 900..4000 — performing audit of the full lineage
Sorseal — on-chain audit

contract    0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a
rpc         mock://local
scan window ledgers 900..4000 — 2 upgrade event(s) found
lineage     consistent

version wasm sha256  live from                live until               attested upgrade tx
─────── ──────────── ──────────────────────── ──────────────────────── ──────── ────────────
v0      aaaaaaaaaaaa <deployment>             2026-09-01T00:00:00Z     sealed   —
v1      cccccccccccc 2026-09-01T00:00:00Z     2026-09-02T00:00:00Z     sealed   000000000000
v2*     eeeeeeeeeeee 2026-09-02T00:00:00Z     now                      sealed   000000000000


PASSED   current deployment is sealed by provenance

== Case 2 — drifted/unsealed current deployment: verify FAILED, audit FAILED
simulated on-chain contract 0a0a0a0a0a0a (mock://local) — provenance has 3 artifact(s)
  ledger is served from the sealed provenance; no network, no funds

sorseal onchain-verify (simulated) ...
FAILED  contract :: wasm hash — deployed bytecode does NOT match sealed provenance
         deployed sha256 9999999999999999999999999999999999999999999999999999999999999999
         sealed   sha256 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee

sorseal onchain-audit (simulated) ...
  retaining ledgers 900..4000 — performing audit of the full lineage
Sorseal — on-chain audit

contract    0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a
rpc         mock://local
scan window ledgers 900..4000 — 2 upgrade event(s) found
lineage     GAPS DETECTED

version wasm sha256  live from                live until               attested upgrade tx
─────── ──────────── ──────────────────────── ──────────────────────── ──────── ────────────
v0      aaaaaaaaaaaa <deployment>             2026-09-01T00:00:00Z     sealed   —
v1      cccccccccccc 2026-09-01T00:00:00Z     2026-09-02T00:00:00Z     sealed   000000000000
v2      eeeeeeeeeeee 2026-09-02T00:00:00Z     now                      sealed   000000000000
v3*     999999999999 <deployment>             now                      NONE     —

WARNING  current on-chain wasm is not the newest upgrade in the scanned window — some upgrades predate the RPC retention window and are not shown
WARNING  current wasm 999999999999... has no sealed provenance

FAILED   current deployment has NO sealed provenance

Done. Both cases ran offline with zero funds and no network.
