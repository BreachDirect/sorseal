#!/usr/bin/env bash
# Fund-free, offline demonstration of the on-chain story.
#
# A real deploy/upgrade demo needs a funded account to pay fees. This script
# instead drives the SAME `onchain-verify` / `onchain-audit` code paths against
# an in-memory ledger (sorseal simulate-onchain) with zero funds and no network.
#
#   ./scripts/sim-demo.sh [sorseal-bin-path]
set -euo pipefail

BIN="${1:-$(cd "$(dirname "$0")/.." && pwd)/target/release/sorseal}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

cat > "$WORK/sorseal.provenance.json" <<'EOF'
{
  "format": "sorseal-provenance",
  "version": 1,
  "project": "sim-demo",
  "toolchain": "rustc 1.95.0",
  "git": { "present": false },
  "artifacts": [
    { "id": "v1", "command": "cargo build", "wasm_path": "v1.wasm", "wasm_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "wasm_size": 1, "source_root": ".", "source_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "built_at": "2026-09-01T00:00:00Z" },
    { "id": "v2", "command": "cargo build", "wasm_path": "v2.wasm", "wasm_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "wasm_size": 1, "source_root": ".", "source_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "built_at": "2026-09-01T00:00:00Z" },
    { "id": "v3", "command": "cargo build", "wasm_path": "v3.wasm", "wasm_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "wasm_size": 1, "source_root": ".", "source_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "built_at": "2026-09-01T00:00:00Z" }
  ]
}
EOF

cd "$WORK"
[ -x "$BIN" ] || { echo "sorseal binary not found at $BIN (build with: cargo build --release)" >&2; exit 1; }

log "Case 1 — current deployment sealed: verify PASSED, audit PASSED"
"$BIN" simulate-onchain

log "Case 2 — drifted/unsealed current deployment: verify FAILED, audit FAILED"
"$BIN" simulate-onchain --deploy-wasm "9999999999999999999999999999999999999999999999999999999999999999"

echo
echo "Done. Both cases ran offline with zero funds and no network."
