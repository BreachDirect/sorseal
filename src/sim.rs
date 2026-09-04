//! Deterministic, fund-free simulation of a Soroban ledger for exercising
//! `sorseal onchain-verify` and `sorseal onchain-audit` offline.
//!
//! A real deploy/upgrade demo needs a funded account to pay transaction fees.
//! The [`MockTransport`] in this module drives the *same* public on-chain code
//! paths (getLedgerEntries decode, getEvents paging, upgrade-lineage
//! reconstruction, provenance cross-checking) against an in-memory ledger, so
//! the full story — seal -> deploy v1 -> upgrade v2 -> upgrade v3 -> verify ->
//! audit — is reproducible on any machine with zero funds and no network.

use crate::onchain::{self, Transport};
use crate::provenance::Provenance;
use anyhow::{anyhow, Result};
use base64::Engine;
use serde_json::{json, Value};
use stellar_strkey::Contract;

/// XDR discriminants, mirroring `crate::onchain` and `crate::audit` so the
/// mock synthesizes byte-compatible responses.
const XDR_TAG_CONTRACT_DATA: u32 = 6;
const XDR_TAG_SC_ADDRESS_TYPE_CONTRACT: u32 = 1;
const XDR_TAG_SCV_LEDGER_KEY_CONTRACT_INSTANCE: u32 = 20;
const XDR_TAG_DURABILITY_PERSISTENT: u32 = 1;
const XDR_TAG_SCV_CONTRACT_INSTANCE: u32 = 19;
const XDR_TAG_EXECUTABLE_WASM: u32 = 0;
const XDR_TAG_SCV_VEC: u32 = 16;
const XDR_TAG_SCV_OPTIONAL_PRESENT: u32 = 1;
const XDR_TAG_SCV_SYMBOL: u32 = 15;
const XDR_TAG_SCV_BYTES: u32 = 13;

/// One synthetic ledger state: the deployed wasm and the upgrade history.
pub struct MockLedger {
    /// Normalized 64-char hex contract id.
    pub contract_hex: String,
    /// The base64 `LedgerEntry` XDR for the currently-deployed wasm.
    current_entry_b64: String,
    /// Synthetic `executable_update` events, ascending by ledger.
    pub events: Vec<Value>,
    /// Ledger window served by `getEvents`.
    pub oldest_ledger: u32,
    pub latest_ledger: u32,
}

/// A `Transport` that answers `getLedgerEntries` / `getEvents` from a fixed,
/// in-memory [`MockLedger`] instead of the network.
pub struct MockTransport {
    ledger: MockLedger,
}

impl MockTransport {
    pub fn new(ledger: MockLedger) -> Self {
        Self { ledger }
    }

    fn events_response(&self, body: &Value) -> Value {
        // The window probe (startLedger) is answered with the served window and
        // no events; a data request returns the upgrade events in one page and
        // ends the scan with a null cursor.
        let start = body
            .get("params")
            .and_then(|p| p.get("startLedger"))
            .and_then(|s| s.as_u64())
            .unwrap_or(self.ledger.oldest_ledger as u64);

        let events: Vec<Value> = if start <= self.ledger.oldest_ledger as u64 {
            self.ledger.events.clone()
        } else {
            Vec::new()
        };
        json!({
            "jsonrpc": "2.0",
            "id": body.get("id").cloned().unwrap_or(Value::Null),
            "result": {
                "latestLedger": self.ledger.latest_ledger,
                "oldestLedger": self.ledger.oldest_ledger,
                "events": events,
                "cursor": Value::Null
            }
        })
    }
}

impl Transport for MockTransport {
    fn post(&self, body: &Value) -> Result<Value> {
        let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
        match method {
            "getLedgerEntries" => Ok(json!({
                "jsonrpc": "2.0",
                "id": body.get("id").cloned().unwrap_or(Value::Null),
                "result": { "entries": [{ "xdr": self.ledger.current_entry_b64 }] }
            })),
            "getEvents" => Ok(self.events_response(body)),
            other => Err(anyhow!("mock transport has no method '{other}'")),
        }
    }
}

// ---------------------------------------------------------------------------
// XDR encoders (the inverse of `onchain::wasm_hash_from_entry` and
// `audit::decode_wasm_executable` / `audit::is_executable_update`).
// ---------------------------------------------------------------------------

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// `ScVal::symbol(name)` — the topic[0] matcher.
fn symbol_scval_b64(name: &str) -> String {
    let mut b = Vec::with_capacity(8 + name.len() + 3);
    push_u32(&mut b, XDR_TAG_SCV_SYMBOL);
    push_u32(&mut b, name.len() as u32);
    let bytes = name.as_bytes();
    b.extend_from_slice(bytes);
    // pad symbol bytes to a multiple of 4
    let pad = (4 - bytes.len() % 4) % 4;
    b.extend_from_slice(&[0u8; 3][..pad]);
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// `Option<vec![symbol("Wasm"), bytes(hash)]>` — topic[1]/topic[2].
fn wasm_scval_b64(wasm_hex: &str) -> Result<String> {
    let hash = hex_bytes(wasm_hex)?;
    let mut b = Vec::with_capacity(60);
    push_u32(&mut b, XDR_TAG_SCV_VEC);
    push_u32(&mut b, XDR_TAG_SCV_OPTIONAL_PRESENT);
    push_u32(&mut b, 2); // vec length
    push_u32(&mut b, XDR_TAG_SCV_SYMBOL);
    push_u32(&mut b, 4); // "Wasm"
    b.extend_from_slice(b"Wasm");
    push_u32(&mut b, XDR_TAG_SCV_BYTES);
    push_u32(&mut b, 32);
    b.extend_from_slice(&hash);
    Ok(base64::engine::general_purpose::STANDARD.encode(b))
}

/// A `getLedgerEntries` `LedgerEntry` XDR whose contract instance points at
/// `wasm_hex` (only the fields `wasm_hash_from_entry` reads are present).
fn contract_instance_entry_b64(id_hex: &str, wasm_hex: &str) -> Result<String> {
    let id = hex_bytes(id_hex)?;
    let wasm = hex_bytes(wasm_hex)?;
    let mut b = Vec::with_capacity(48 + 48);
    push_u32(&mut b, XDR_TAG_CONTRACT_DATA);
    push_u32(&mut b, 0); // ExtensionPoint void
    push_u32(&mut b, XDR_TAG_SC_ADDRESS_TYPE_CONTRACT);
    b.extend_from_slice(&id);
    push_u32(&mut b, XDR_TAG_SCV_LEDGER_KEY_CONTRACT_INSTANCE);
    push_u32(&mut b, XDR_TAG_DURABILITY_PERSISTENT);
    push_u32(&mut b, XDR_TAG_SCV_CONTRACT_INSTANCE);
    push_u32(&mut b, XDR_TAG_EXECUTABLE_WASM);
    b.extend_from_slice(&wasm);
    Ok(base64::engine::general_purpose::STANDARD.encode(b))
}

fn hex_bytes(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.as_bytes();
    if hex.len() != 64 || !hex.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "expected a 64-char hex wasm hash, got '{}'",
            String::from_utf8_lossy(hex)
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in hex.chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(byte).unwrap();
        out[i] = u8::from_str_radix(s, 16).unwrap();
    }
    Ok(out)
}

/// Build a synthetic ledger from a provenance whose artifacts form an upgrade
/// chain: artifact[0] is the initial deployment, then each subsequent artifact
/// is an upgrade. The contract is deployed as the *last* artifact's wasm, so an
/// audit against the sealed provenance reports the current deployment PASSED.
///
/// `upgrades` sets how many upgrades the ledger has performed (default: all
/// artifacts past the first). Exactly one artifact yields a ledger with no
/// upgrade events (a single deployment).
pub fn ledger_from_provenance(
    provenance: &Provenance,
    contract_id: &str,
    upgrades: Option<usize>,
) -> Result<MockLedger> {
    ledger_from_provenance_with_current(provenance, contract_id, upgrades, None)
}

/// Like [`ledger_from_provenance`] but lets the caller over-ride the currently
/// deployed wasm with `current_wasm` (a 64-char hex hash) instead of the last
/// artifact's. Use a hash not present in provenance to simulate the drift case
/// where the current on-chain deployment is unsealed (audit reports FAILED).
pub fn ledger_from_provenance_with_current(
    provenance: &Provenance,
    contract_id: &str,
    upgrades: Option<usize>,
    current_wasm_override: Option<&str>,
) -> Result<MockLedger> {
    let contract_hex = onchain::normalize_contract_id(contract_id)?;
    if provenance.artifacts.is_empty() {
        return Err(anyhow!("provenance has no artifacts to simulate"));
    }

    let upgrade_count = upgrades.unwrap_or(provenance.artifacts.len().saturating_sub(1));
    let chain: Vec<&str> = provenance
        .artifacts
        .iter()
        .take(upgrade_count + 1)
        .map(|a| a.wasm_sha256.as_str())
        .collect();
    let current_wasm = current_wasm_override.unwrap_or_else(|| chain.last().copied().unwrap_or(""));

    let mut events = Vec::new();
    let contract_strkey = Contract(
        hex_bytes(&contract_hex).map_err(|e| anyhow!("invalid simulated contract id: {e}"))?,
    )
    .to_string();
    let contract_strkey: &str = contract_strkey.as_str();
    for i in 1..chain.len() {
        let old = chain[i - 1];
        let new = chain[i];
        let ledger = 1000 + (i as u32) * 1000;
        let tx_hash = format!("{:064x}", i);
        let closed_at = format!("2026-09-{:02}T00:00:{:02}Z", (i as u8).min(28), 0);
        events.push(json!({
            "type": "system",
            "ledger": ledger,
            "ledgerClosedAt": closed_at,
            "contractId": contract_strkey,
            "id": format!("{ledger:020}-0000000000"),
            "operationIndex": 0,
            "transactionIndex": 0,
            "txHash": tx_hash,
            "inSuccessfulContractCall": true,
            "topic": [
                symbol_scval_b64("executable_update"),
                wasm_scval_b64(old)?,
                wasm_scval_b64(new)?,
            ],
            "value": "",
        }));
    }

    let current_entry_b64 = contract_instance_entry_b64(&contract_hex, current_wasm)?;
    let latest_ledger = 1000 + (chain.len().max(1) as u32) * 1000;

    Ok(MockLedger {
        contract_hex,
        current_entry_b64,
        events,
        oldest_ledger: 900,
        latest_ledger,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn provenance_with(wasms: Vec<String>) -> Provenance {
        serde_json::from_value(json!({
            "format": "sorseal-provenance",
            "version": 1,
            "project": "demo",
            "toolchain": "stable",
            "git": { "present": false },
            "artifacts": wasms.iter().enumerate().map(|(i, w)| json!({
                "id": format!("a{i}"),
                "command": "cargo build",
                "wasm_path": format!("a{i}.wasm"),
                "wasm_sha256": w,
                "wasm_size": 1,
                "source_root": ".",
                "source_sha256": "0".repeat(64),
                "built_at": "2026-01-01T00:00:00Z",
            })).collect::<Vec<_>>()
        }))
        .unwrap()
    }

    #[test]
    fn symbol_and_wasm_scvals_match_real_fixtures() {
        // Topic[0] matches the known-good matcher bytes used in audit tests.
        assert_eq!(
            symbol_scval_b64("executable_update"),
            "AAAADwAAABFleGVjdXRhYmxlX3VwZGF0ZQAAAA=="
        );
        // "Wasm"-bearing vec matches the shape decode_wasm_executable expects.
        let wasm = "c9109d0b6a6c41bcf20c371e224fd542119f3371c33d86a3baba6fa85d1914bf";
        assert!(wasm_scval_b64(wasm).is_ok());
    }

    #[test]
    fn entry_decodes_to_given_wasm() {
        let id = "cd".repeat(32);
        let wasm = "ab".repeat(32);
        let entry = contract_instance_entry_b64(&id, &wasm).unwrap();
        let decoded = onchain::wasm_hash_from_entry(&entry).unwrap().unwrap();
        assert_eq!(crate::digest::hex(&decoded), wasm);
    }

    #[test]
    fn ledger_with_multiple_artifacts_is_a_chain() {
        let p = provenance_with(vec!["11".repeat(32), "22".repeat(32), "33".repeat(32)]);
        let l = ledger_from_provenance(&p, &"cd".repeat(32), None).unwrap();
        assert_eq!(l.events.len(), 2);
        assert_eq!(l.events[0]["ledger"].as_u64(), Some(2000));
        assert_eq!(l.events[1]["ledger"].as_u64(), Some(3000));
    }
}
