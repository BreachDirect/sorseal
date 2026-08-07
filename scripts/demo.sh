#!/usr/bin/env bash
# End-to-end sorseal demo against a real Soroban network.
#
# Demonstrates the full story: seal the build, deploy, upgrade twice, then
# prove on-chain that (a) the current deployment is sealed and (b) the full
# upgrade lineage — including the versions that were deployed WITHOUT a seal —
# is visible and cross-checked against provenance.
#
# Prereqs: a built `sorseal` binary and the Stellar CLI (`stellar`, formerly
# soroban-cli), plus the wasm32 target:
#   rustup target add wasm32v1-none
#   cargo install soroban-cli --version 27.1.0 --locked   # provides the `stellar` CLI
#   cargo build --release
#
# Env:
#   SORSEAL_BIN   path to the sorseal binary        (default: sorseal)
#   STELLAR_BIN   path to the stellar CLI           (default: stellar)
#   RPC_URL       Soroban RPC endpoint              (default: testnet)
#   NETWORK_PASSPHRASE  network passphrase          (default: testnet)
#   SOURCE_KEY    secret key of the signing account (default: generate+fund)
#
# Run from anywhere; it operates on examples/demo-contract.
set -euo pipefail

SORSEAL_BIN="${SORSEAL_BIN:-sorseal}"
STELLAR_BIN="${STELLAR_BIN:-stellar}"
RPC_URL="${RPC_URL:-https://soroban-testnet.stellar.org}"
NETWORK_PASSPHRASE="${NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"
CONTRACT_DIR="$(cd "$(dirname "$0")/.." && pwd)/examples/demo-contract"
WASM="$CONTRACT_DIR/target/wasm32v1-none/release/demo_contract.wasm"
KEY="sorseal-demo"
CONTRACT_ALIAS="sorseal-demo-contract"

log() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

command -v "$SORSEAL_BIN" >/dev/null || fail "$SORSEAL_BIN not found on PATH"
command -v "$STELLAR_BIN" >/dev/null || fail "$STELLAR_BIN not found on PATH (cargo install soroban-cli)"

cd "$CONTRACT_DIR"
mkdir -p target

log "Generating a testnet keypair to sign deploys"
if [ -n "${SOURCE_KEY:-}" ]; then
  "$STELLAR_BIN" keys add "$KEY" --secret-key "$SOURCE_KEY" --network-passphrase "$NETWORK_PASSPHRASE"
else
  if "$STELLAR_BIN" keys ls 2>/dev/null | grep -q "$KEY"; then
    "$STELLAR_BIN" keys rm "$KEY" --force >/dev/null 2>&1 || true
  fi
  "$STELLAR_BIN" keys generate "$KEY" --fund --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE"
fi

log "Stage 1 — build + seal v1 (value = 1_000)"
cargo build --release --target wasm32v1-none
"$SORSEAL_BIN" record

log "Stage 2 — deploy v1"
"$STELLAR_BIN" contract alias remove "$CONTRACT_ALIAS" >/dev/null 2>&1 || true
"$STELLAR_BIN" contract deploy \
  --wasm "$WASM" --alias "$CONTRACT_ALIAS" --source-account "$KEY" \
  --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE"
CONTRACT_ID="$("$STELLAR_BIN" contract alias show "$CONTRACT_ALIAS" --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE" | tail -1)"
log "Contract id: $CONTRACT_ID"

log "Stage 3 — prove v1 is sealed on-chain"
"$SORSEAL_BIN" onchain-verify --contract-id "$CONTRACT_ID" --rpc "$RPC_URL"

log "Stage 4 — upgrade to v2 (value = 2_000), deployed WITHOUT a seal"
sed -i 's/        1_000/        2_000/' "$CONTRACT_DIR/src/lib.rs"
cargo build --release --target wasm32v1-none
"$STELLAR_BIN" contract upgrade \
  --wasm "$WASM" --source-account "$KEY" \
  --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE" \
  --contract-id "$CONTRACT_ID" >/dev/null

log "Stage 5 — upgrade to v3 (value = 3_000), deployed WITHOUT a seal"
sed -i 's/        2_000/        3_000/' "$CONTRACT_DIR/src/lib.rs"
cargo build --release --target wasm32v1-none
"$STELLAR_BIN" contract upgrade \
  --wasm "$WASM" --source-account "$KEY" \
  --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE" \
  --contract-id "$CONTRACT_ID" >/dev/null

log "Stage 6 — audit the lineage: v1 sealed, v2/v3 unsealed, current FAILED"
set +e
"$SORSEAL_BIN" onchain-audit --contract-id "$CONTRACT_ID" --rpc "$RPC_URL"
AUDIT_EXIT=$?
set -e
[ "$AUDIT_EXIT" -eq 1 ] || fail "expected exit 1 (unsealed current), got $AUDIT_EXIT"

log "Stage 7 — seal v3 and re-audit: current PASSED"
"$SORSEAL_BIN" record --allow-dirty
"$SORSEAL_BIN" onchain-audit --contract-id "$CONTRACT_ID" --rpc "$RPC_URL"

log "Done. Contract id: $CONTRACT_ID"
