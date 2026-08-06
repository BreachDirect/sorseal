//! On-chain verification: query Soroban RPC for the deployed contract's WASM
//! hash and compare it against the sealed provenance record.

use crate::digest;
use crate::provenance::Provenance;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::path::Path;
use stellar_strkey::Contract;

pub const TESTNET_RPC: &str = "https://soroban-testnet.stellar.org";
pub const MAINNET_RPC: &str = "https://soroban-mainnet.stellar.org";

// XDR discriminants for the ledger key and contract instance we inspect. See
// https://github.com/stellar/stellar-xdr for the authoritative definitions.
const XDR_TAG_CONTRACT_DATA: u32 = 6; // LedgerEntryType
const XDR_TAG_SC_ADDRESS_TYPE_CONTRACT: u32 = 1; // SCAddressType
const XDR_TAG_SCV_LEDGER_KEY_CONTRACT_INSTANCE: u32 = 20; // SCValType
const XDR_TAG_DURABILITY_PERSISTENT: u32 = 1; // ContractDataDurability
const XDR_TAG_SCV_CONTRACT_INSTANCE: u32 = 19; // SCValType
const XDR_TAG_EXECUTABLE_WASM: u32 = 0; // ContractExecutableType
const XDR_TAG_EXECUTABLE_STELLAR_ASSET: u32 = 1; // ContractExecutableType

/// Build the 48-byte `LedgerKeyContractData` XDR that addresses a contract's
/// instance entry: the `SCV_LEDGER_KEY_CONTRACT_INSTANCE` key at the
/// contract's address in persistent durability.
fn contract_instance_key(id: &[u8; 32]) -> [u8; 48] {
    let mut key = [0u8; 48];
    key[0..4].copy_from_slice(&XDR_TAG_CONTRACT_DATA.to_be_bytes());
    key[4..8].copy_from_slice(&XDR_TAG_SC_ADDRESS_TYPE_CONTRACT.to_be_bytes());
    key[8..40].copy_from_slice(id);
    key[40..44].copy_from_slice(&XDR_TAG_SCV_LEDGER_KEY_CONTRACT_INSTANCE.to_be_bytes());
    key[44..48].copy_from_slice(&XDR_TAG_DURABILITY_PERSISTENT.to_be_bytes());
    key
}

/// Decode a base64 `LedgerEntry` returned by `getLedgerEntries` and extract the
/// deployed wasm hash. Returns `None` when the contract is a built-in Stellar
/// Asset Contract (no wasm on-chain) and errors on structurally unexpected XDR.
fn wasm_hash_from_entry(entry_b64: &str) -> Result<Option<[u8; 32]>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(entry_b64)
        .context("ledger entry is not valid base64")?;
    let mut cur = Cursor::new(&bytes);

    // LedgerEntry: switch (LedgerEntryType) -> CONTRACT_DATA = 6.
    expect_tag(&mut cur, XDR_TAG_CONTRACT_DATA, "LedgerEntry type")?;
    // ContractDataEntry { ExtensionPoint ext, SCAddress contract, SCVal key,
    //   ContractDataDurability durability, SCVal val }
    read_u32(&mut cur, "ExtensionPoint")?; // ext (void = 0)
    expect_tag(&mut cur, XDR_TAG_SC_ADDRESS_TYPE_CONTRACT, "SCAddress type")?;
    take(&mut cur, 32, "SCAddress contract id")?;
    expect_tag(
        &mut cur,
        XDR_TAG_SCV_LEDGER_KEY_CONTRACT_INSTANCE,
        "SCVal key type",
    )?;
    expect_tag(&mut cur, XDR_TAG_DURABILITY_PERSISTENT, "durability")?;
    expect_tag(&mut cur, XDR_TAG_SCV_CONTRACT_INSTANCE, "SCVal val type")?;

    // SCContractInstance { ContractExecutable executable, SCMap* storage }
    let exec = read_u32(&mut cur, "ContractExecutable type")?;
    match exec {
        XDR_TAG_EXECUTABLE_WASM => {
            let wasm: [u8; 32] = take(&mut cur, 32, "wasm hash")?
                .try_into()
                .expect("slice of length 32");
            Ok(Some(wasm))
        }
        XDR_TAG_EXECUTABLE_STELLAR_ASSET => Ok(None),
        other => bail!("unexpected ContractExecutable type {other}"),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
}

fn read_u32(cur: &mut Cursor<'_>, what: &str) -> Result<u32> {
    let end = cur
        .pos
        .checked_add(4)
        .filter(|&end| end <= cur.bytes.len())
        .ok_or_else(|| anyhow!("truncated XDR: {what}"))?;
    let v = u32::from_be_bytes(
        cur.bytes[cur.pos..end]
            .try_into()
            .expect("slice of length 4"),
    );
    cur.pos = end;
    Ok(v)
}

fn take<'a>(cur: &mut Cursor<'a>, n: usize, what: &str) -> Result<&'a [u8]> {
    let end = cur
        .pos
        .checked_add(n)
        .filter(|&end| end <= cur.bytes.len())
        .ok_or_else(|| anyhow!("truncated XDR: {what}"))?;
    let out = &cur.bytes[cur.pos..end];
    cur.pos = end;
    Ok(out)
}

fn expect_tag(cur: &mut Cursor<'_>, expected: u32, what: &str) -> Result<()> {
    let got = read_u32(cur, what)?;
    if got != expected {
        bail!("unexpected XDR tag for {what}: expected {expected}, got {got}");
    }
    Ok(())
}

/// Query the Soroban RPC `getLedgerEntries` method for a contract id and return
/// the deployed wasm hash as lowercase hex.
pub fn fetch_deployed_wasm_hash(rpc_url: &str, contract_id: &str) -> Result<String> {
    let hex_id = normalize_contract_id(contract_id)?;
    let id: [u8; 32] = hex_to_bytes(&hex_id)?;
    let key = contract_instance_key(&id);
    let b64 = base64::engine::general_purpose::STANDARD;
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLedgerEntries",
        "params": { "keys": [b64.encode(key)] }
    });

    let resp = ureq::post(rpc_url)
        .content_type("application/json")
        .send_json(&body)
        .with_context(|| format!("RPC request to {rpc_url} failed"))?;

    let parsed: Value = resp
        .into_body()
        .read_json()
        .with_context(|| format!("RPC returned non-JSON from {rpc_url}"))?;

    if let Some(err) = parsed.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        bail!("Soroban RPC error: {msg}");
    }
    let entries = parsed
        .get("result")
        .and_then(|r| r.get("entries"))
        .and_then(|e| e.as_array())
        .ok_or_else(|| anyhow!("RPC response has no result.entries: {parsed}"))?;
    if entries.is_empty() {
        bail!("no contract instance found on-chain for '{contract_id}'");
    }
    let entry_b64 = entries
        .first()
        .and_then(|e| e.get("xdr"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("RPC response has no result.entries[0].xdr: {parsed}"))?;

    match wasm_hash_from_entry(entry_b64)? {
        Some(wasm) => Ok(digest::hex(&wasm)),
        None => bail!("contract '{contract_id}' is a Stellar Asset Contract with no wasm on-chain"),
    }
}

fn hex_to_bytes(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid hex contract id: must be exactly 64 hex chars");
    }
    let mut out = [0u8; 32];
    for (i, byte) in (0..hex.len()).step_by(2).enumerate() {
        out[i] = u8::from_str_radix(&hex[byte..byte + 2], 16)
            .map_err(|e| anyhow!("invalid hex contract id: {e}"))?;
    }
    Ok(out)
}

/// Accept a contract id as either a hex string (optionally 0x-prefixed) or a
/// C... strkey; return the normalized 64-char hex form used by the RPC.
pub fn normalize_contract_id(id: &str) -> Result<String> {
    let id = id.trim();
    let hex = id.strip_prefix("0x").unwrap_or(id);
    // A 64-char hex id is unambiguous — and uppercase 'C' is a valid hex
    // digit, so check hex first to avoid misrouting it to the strkey path.
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(hex.to_ascii_lowercase());
    }
    if id.starts_with('C') {
        let contract = Contract::from_string(id)
            .map_err(|e| anyhow!("invalid contract strkey '{id}': {e}"))?;
        return Ok(digest::hex(&contract.0));
    }
    bail!(
        "contract id must be a C... strkey or 64 hex chars, got '{}'",
        id
    )
}

/// Result of one on-chain check.
#[derive(Debug, Clone)]
pub struct OnChainCheck {
    pub contract_id: String,
    pub deployed_wasm_sha256: String,
    pub sealed_wasm_sha256: String,
    pub match_: bool,
}

/// Compare the deployed on-chain wasm hash against the sealed provenance for
/// the given artifact id (or the first artifact when none is specified).
pub fn verify_contract(
    provenance: &Provenance,
    rpc_url: &str,
    contract_id: &str,
    artifact: Option<&str>,
) -> Result<OnChainCheck> {
    let art = match artifact {
        Some(id) => provenance
            .artifacts
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| anyhow!("provenance has no artifact with id '{id}'"))?,
        None => provenance
            .artifacts
            .first()
            .ok_or_else(|| anyhow!("provenance has no artifacts to check on-chain"))?,
    };

    let deployed = fetch_deployed_wasm_hash(rpc_url, contract_id)?;
    let sealed = art.wasm_sha256.to_ascii_lowercase();
    let normalized = normalize_contract_id(contract_id)?;
    let match_ = deployed == sealed;

    Ok(OnChainCheck {
        contract_id: normalized,
        deployed_wasm_sha256: deployed,
        sealed_wasm_sha256: sealed,
        match_,
    })
}

/// Render an on-chain check for the console.
pub fn render_check(check: &OnChainCheck) -> String {
    let status = if check.match_ {
        "PASSED  contract :: wasm hash — deployed bytecode matches sealed provenance"
    } else {
        "FAILED  contract :: wasm hash — deployed bytecode does NOT match sealed provenance"
    };
    format!(
        "{status}\n         deployed sha256 {}\n         sealed   sha256 {}",
        check.deployed_wasm_sha256, check.sealed_wasm_sha256
    )
}

/// Load a provenance file from a cwd-relative path.
pub fn load_provenance(cwd: &Path, provenance: &str) -> Result<Provenance> {
    Provenance::load(&cwd.join(provenance))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_hex_and_strkey() {
        let hex = "abcd".repeat(16);
        assert_eq!(normalize_contract_id(&hex).unwrap(), hex);
        assert_eq!(normalize_contract_id(&format!("0x{hex}")).unwrap(), hex);
        assert!(normalize_contract_id("garbage").is_err());
        assert!(normalize_contract_id(&"abcd".repeat(15)).is_err());
    }

    #[test]
    fn normalize_accepts_uppercase_hex_starting_with_c() {
        // Uppercase 'C' is a valid hex digit: a 64-char hex id that happens to
        // start with 'C' must be treated as hex, not mistaken for a strkey.
        let hex = format!("C{}0", "ab".repeat(31).to_uppercase());
        assert_eq!(hex.len(), 64);
        assert_eq!(
            normalize_contract_id(&hex).unwrap(),
            hex.to_ascii_lowercase()
        );
        assert_eq!(
            normalize_contract_id(&format!("0x{hex}")).unwrap(),
            hex.to_ascii_lowercase()
        );
    }

    #[test]
    fn normalize_accepts_strkey_roundtrip() {
        // A valid C... contract strkey decodes to 32 bytes; re-encoding the
        // hex must round-trip through Contract::from_string.
        let hex = "aa55".repeat(16);
        let encoded = Contract(hex_to_arr(&hex)).to_string();
        assert!(encoded.starts_with('C'));
        assert_eq!(normalize_contract_id(&encoded).unwrap(), hex);
    }

    #[test]
    fn contract_instance_key_layout() {
        // Live testnet contract: CB2GZTFWZ43I3F7LJJZH46MJPHOU2L33A22USDRG6RERTZ4FUYOM5K
        let id: [u8; 32] =
            hex_to_arr("8d9996d9e6d1b2fd694e4fcf312f3ba9a5ef60d6a921c4de89233cf0b4c399d5");
        let key = contract_instance_key(&id);
        assert_eq!(
            key.to_vec(),
            hex_to_vec(
                "00000006000000018d9996d9e6d1b2fd694e4fcf312f3ba9a5ef60d6a921c4de89233cf0b4c399d50000001400000001"
            )
        );
    }

    #[test]
    fn wasm_hash_from_entry_decodes_live_fixture() {
        // A real `getLedgerEntries` response captured from soroban-testnet.
        let entry = concat!(
            "AAAABgAAAAAAAAABjZmW2ebRsv1pTk/PMS87qaXvYNapIcTeiSM88LTDmdUAAAAUAAAAAQAAABMAAAAA",
            "zO3XrBL3WH6w88OUASmQWwVpzmFqFbV7ioblQ+8E5DAAAAABAAAACQAAABAAAAABAAAAAQAAAA8AAAAN",
            "Q29uZmlnTWFuYWdlcgAAAAAAABIAAAABt/O5AP1sGZgEryOq1Q4AtypIXkt7QZafmFAw+AUMnBgAAAAQ",
            "AAAAAQAAAAEAAAAPAAAAC0luaXRpYWxpemVkAAAAAAAAAAABAAAAEAAAAAEAAAACAAAADwAAAApMYXN0",
            "VXBkYXRlAAAAAAAPAAAABkJUQ1VTRAAAAAAABQAAAABqdBu2AAAAEAAAAAEAAAACAAAADwAAAApMYXN0",
            "VXBkYXRlAAAAAAAPAAAABkVUSFVTRAAAAAAABQAAAABqdBusAAAAEAAAAAEAAAACAAAADwAAAApMYXN0",
            "VXBkYXRlAAAAAAAPAAAABlhMTVVTRAAAAAAABQAAAABqdBt1AAAAEAAAAAEAAAACAAAADwAAAAVQcmlj",
            "ZQAAAAAAAA8AAAAGQlRDVVNEAAAAAAAKAAAAAAAAAAAAAACXFYscYAAAABAAAAABAAAAAgAAAA8AAAAF",
            "UHJpY2UAAAAAAAAPAAAABkVUSFVTRAAAAAAACgAAAAAAAAAAAAAABHNPXFAAAAAQAAAAAQAAAAIAAAAP",
            "AAAABVByaWNlAAAAAAAADwAAAAZYTE1VU0QAAAAAAAoAAAAAAAAAAAAAAAAAGM2cAAAAEAAAAAEAAAAB",
            "AAAADwAAAAlQdWJsaXNoZXIAAAAAAAASAAAAAAAAAAAJDqKNhO2/XZAvmR1Wynm2lxfIUQwB6TDzqNVO",
            "lQgQTg=="
        );
        let wasm = wasm_hash_from_entry(entry).unwrap();
        assert_eq!(
            wasm.unwrap().to_vec(),
            hex_to_vec("ccedd7ac12f7587eb0f3c3940129905b0569ce616a15b57b8a86e543ef04e430")
        );
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_to_arr(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in (0..s.len()).step_by(2).enumerate() {
            out[i] = u8::from_str_radix(&s[byte..byte + 2], 16).unwrap();
        }
        out
    }
}
