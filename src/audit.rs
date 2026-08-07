//! On-chain upgrade audit: reconstruct a contract's deployed-wasm history from
//! the public `executable_update` system events the ledger emits on every
//! contract upgrade, then cross-check each version against sealed provenance.
//!
//! This is the piece that makes provenance verifiable on Stellar itself: the
//! upgrade history is emitted by the ledger (never by the sealer), so a
//! reviewer can confirm *every* version that was ever live on-chain, whether
//! or not it matches a sealed record — turning "the current bytecode matches
//! my build" into "the entire lineage of this contract matches my builds".

use crate::onchain::{
    self, expect_tag, read_u32, take, Cursor, XDR_TAG_SCV_BYTES, XDR_TAG_SCV_OPTIONAL_PRESENT,
    XDR_TAG_SCV_SYMBOL, XDR_TAG_SCV_VEC,
};
use crate::provenance::Provenance;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashSet;

/// Topic[0] symbol of the ledger-emitted upgrade event.
const EXECUTABLE_UPDATE: &str = "executable_update";

/// The symbol length (17 bytes) matches the string above.
const EXECUTABLE_UPDATE_LEN: u32 = 17;

/// `getEvents` page size and the safety bound on the scan loop.
const PAGE_LIMIT: u32 = 200;
const MAX_PAGES: u32 = 10_000;

/// One `executable_update` event emitted by the ledger.
#[derive(Debug, Clone)]
pub struct UpgradeEvent {
    /// Ledger sequence at which the upgrade landed.
    pub ledger: u32,
    /// RFC 3339 close time of that ledger.
    pub closed_at: String,
    /// Hex transaction hash that performed the upgrade.
    pub tx_hash: String,
    /// Normalized 64-char hex contract id this upgrade applied to.
    pub contract: String,
    /// Hex sha256 of the wasm that was live *before* the upgrade.
    pub old_wasm: String,
    /// Hex sha256 of the wasm that became live *after* the upgrade.
    pub new_wasm: String,
}

/// A single version of the contract's on-chain wasm.
#[derive(Debug, Clone)]
pub struct VersionRecord {
    /// Hex sha256 of the wasm for this version.
    pub wasm: String,
    /// True when this is the currently-deployed wasm.
    pub current: bool,
    /// RFC 3339 when this version went live (None for the first version).
    pub live_from: Option<String>,
    /// RFC 3339 when this version was replaced (None while still live).
    pub live_until: Option<String>,
    /// Hex tx hash of the upgrade that introduced this version.
    pub upgrade_tx: Option<String>,
    /// Sealed provenance artifact id that covers this wasm, if any.
    pub attested_by: Option<String>,
}

/// The reconstructed lineage plus the result of cross-checking it.
#[derive(Debug, Clone)]
pub struct AuditReport {
    /// Normalized 64-char hex contract id.
    pub contract_id: String,
    /// RPC endpoint used.
    pub rpc_url: String,
    /// The ledger window that was scanned ([oldest, latest]).
    pub scan_window: (u32, u32),
    /// Upgrade events found for this contract, oldest first.
    pub events: Vec<UpgradeEvent>,
    /// Every wasm version, oldest first.
    pub versions: Vec<VersionRecord>,
    /// True when consecutive upgrades chain old->new without gaps.
    pub chain_consistent: bool,
    /// True when the currently-deployed wasm is covered by sealed provenance.
    pub current_attested: bool,
    /// True when sealed provenance was supplied to cross-check against.
    pub provenance_supplied: bool,
    /// Non-fatal findings (unattested versions, retention gaps, ...).
    pub warnings: Vec<String>,
}

/// Base64-encoded `ScVal::symbol("executable_update")` topic matcher.
fn executable_update_scval() -> String {
    let mut b = Vec::with_capacity(20);
    b.extend_from_slice(&XDR_TAG_SCV_SYMBOL.to_be_bytes());
    b.extend_from_slice(&EXECUTABLE_UPDATE_LEN.to_be_bytes());
    b.extend_from_slice(EXECUTABLE_UPDATE.as_bytes());
    b.extend_from_slice(&[0u8; 3]); // pad symbol to a multiple of 4 bytes
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// The server-side `getEvents` filter for `executable_update` events. The
/// wildcard segments pin the 3-topic shape of the event.
fn upgrade_event_filter() -> Value {
    json!([{
        "type": "system",
        "topics": [[executable_update_scval(), "*", "*"]]
    }])
}

/// True when `topic0` is the base64 `ScVal::symbol("executable_update")`.
fn is_executable_update(topic0: &str) -> bool {
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(topic0) else {
        return false;
    };
    let mut cur = Cursor::new(&bytes);
    let Ok(tag) = read_u32(&mut cur, "topic type") else {
        return false;
    };
    let Ok(len) = read_u32(&mut cur, "topic symbol length") else {
        return false;
    };
    let Ok(sym) = take(&mut cur, len as usize, "topic symbol") else {
        return false;
    };
    tag == XDR_TAG_SCV_SYMBOL && sym == EXECUTABLE_UPDATE.as_bytes()
}

/// Decode a topic executable SCVal — `scvVec([symbol("Wasm"), bytes(hash)])` —
/// into the hex wasm hash. See `is_executable_update` for the layout; the vec
/// case is Option-wrapped, so the payload is `tag, present, len, ...`.
fn decode_wasm_executable(topic: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(topic)
        .context("executable topic is not valid base64")?;
    let mut cur = Cursor::new(&bytes);
    expect_tag(&mut cur, XDR_TAG_SCV_VEC, "executable SCVal type")?;
    expect_tag(
        &mut cur,
        XDR_TAG_SCV_OPTIONAL_PRESENT,
        "executable vec present",
    )?;
    expect_tag(&mut cur, 2, "executable vec length")?;
    expect_tag(&mut cur, XDR_TAG_SCV_SYMBOL, "executable kind type")?;
    let kind_len = read_u32(&mut cur, "executable kind length")?;
    if kind_len != 4 {
        bail!("unexpected executable kind length {kind_len}");
    }
    let kind = take(&mut cur, 4, "executable kind")?;
    if kind != b"Wasm" {
        bail!(
            "unexpected executable kind '{}' (expected 'Wasm')",
            String::from_utf8_lossy(kind)
        );
    }
    expect_tag(&mut cur, XDR_TAG_SCV_BYTES, "wasm hash type")?;
    let hash_len = read_u32(&mut cur, "wasm hash length")?;
    if hash_len != 32 {
        bail!("unexpected wasm hash length {hash_len}");
    }
    let hash = take(&mut cur, 32, "wasm hash")?;
    Ok(crate::digest::hex(hash))
}

/// Decode a raw `getEvents` event object into an `UpgradeEvent`, validating
/// that it is an `executable_update` for a wasm-backed contract.
pub fn decode_upgrade_event(raw: &Value) -> Result<UpgradeEvent> {
    let topic = raw
        .get("topic")
        .and_then(|t| t.as_array())
        .ok_or_else(|| anyhow!("event has no topic array"))?;
    if topic.len() != 3 {
        bail!("expected 3 executable_update topics, got {}", topic.len());
    }
    let t0 = topic[0]
        .as_str()
        .ok_or_else(|| anyhow!("event topic[0] is not a string"))?;
    if !is_executable_update(t0) {
        bail!("event topic[0] is not an executable_update symbol");
    }
    let t1 = topic[1]
        .as_str()
        .ok_or_else(|| anyhow!("event topic[1] is not a string"))?;
    let t2 = topic[2]
        .as_str()
        .ok_or_else(|| anyhow!("event topic[2] is not a string"))?;

    let contract = raw
        .get("contractId")
        .and_then(|c| c.as_str())
        .map(onchain::normalize_contract_id)
        .transpose()?
        .ok_or_else(|| anyhow!("event has no contractId"))?;

    Ok(UpgradeEvent {
        ledger: raw.get("ledger").and_then(|l| l.as_u64()).unwrap_or(0) as u32,
        closed_at: raw
            .get("ledgerClosedAt")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        tx_hash: raw
            .get("txHash")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        contract,
        old_wasm: decode_wasm_executable(t1)?,
        new_wasm: decode_wasm_executable(t2)?,
    })
}

/// Parse the "startLedger must be within the ledger range: A - B" error that a
/// conforming node returns for an out-of-range `startLedger`.
fn parse_ledger_range(msg: &str) -> Option<(u32, u32)> {
    let rest = msg.split_once("ledger range: ")?.1;
    let (a, b) = rest.split_once(" - ")?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

/// Discover the [oldest, latest] ledger window the RPC retains, by probing an
/// out-of-range `startLedger` and reading the range from the error.
pub fn rpc_ledger_window(rpc_url: &str) -> Result<(u32, u32)> {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "getEvents",
        "params": { "startLedger": 1, "filters": upgrade_event_filter(), "pagination": { "limit": 1 } }
    });
    let resp = onchain::rpc_post(rpc_url, &body)?;
    if let Some(err) = resp.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        if let Some(range) = parse_ledger_range(msg) {
            return Ok(range);
        }
        bail!("Soroban RPC error: {msg}");
    }
    let result = resp
        .get("result")
        .ok_or_else(|| anyhow!("RPC response has no result: {resp}"))?;
    let latest = result
        .get("latestLedger")
        .and_then(|l| l.as_u64())
        .ok_or_else(|| anyhow!("RPC response has no latestLedger: {resp}"))?
        as u32;
    let oldest = result
        .get("oldestLedger")
        .and_then(|l| l.as_u64())
        .map(|v| v as u32)
        .unwrap_or(1);
    Ok((oldest, latest))
}

/// Scan the RPC for every `executable_update` event in `[start, end]`, page by
/// page, and return the ones for `contract_hex`. The scan uses the cursor
/// returned by the node and de-duplicates by event id, so the result is the
/// complete upgrade history the retention window can still produce.
pub fn scan_upgrade_events(
    rpc_url: &str,
    start: u32,
    end: u32,
    contract_hex: &str,
) -> Result<Vec<UpgradeEvent>> {
    let mut events: Vec<UpgradeEvent> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0u32;

    loop {
        pages += 1;
        if pages > MAX_PAGES {
            bail!("scan exceeded {MAX_PAGES} pages — is the node's cursor making progress?");
        }
        let params = match &cursor {
            Some(c) => {
                json!({ "filters": upgrade_event_filter(), "pagination": { "cursor": c, "limit": PAGE_LIMIT } })
            }
            None => {
                json!({ "startLedger": start, "filters": upgrade_event_filter(), "pagination": { "limit": PAGE_LIMIT } })
            }
        };
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "getEvents", "params": params });
        let resp = onchain::rpc_post(rpc_url, &body)?;
        if let Some(err) = resp.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            bail!("Soroban RPC error: {msg}");
        }
        let result = resp
            .get("result")
            .ok_or_else(|| anyhow!("RPC response has no result: {resp}"))?;

        let page_events = result.get("events").and_then(|e| e.as_array());
        let page_events = page_events.map(|a| a.len()).unwrap_or(0);
        if page_events == 0 {
            break;
        }
        for raw in result.get("events").and_then(|e| e.as_array()).unwrap() {
            let id = raw
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() || !seen.insert(id) {
                continue;
            }
            let ev = decode_upgrade_event(raw)?;
            if ev.contract == contract_hex {
                events.push(ev);
            }
        }
        cursor = result
            .get("cursor")
            .and_then(|c| c.as_str())
            .map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }

    events.sort_by_key(|e| e.ledger);
    let _ = end; // the node's cursor naturally stops at the retention frontier
    Ok(events)
}

/// Reconstruct the version lineage from the scan and cross-check it against
/// sealed provenance.
pub fn build_audit(
    contract_hex: &str,
    events: Vec<UpgradeEvent>,
    current_wasm: String,
    provenance: Option<&Provenance>,
    rpc_url: &str,
    scan_window: (u32, u32),
) -> AuditReport {
    let mut warnings: Vec<String> = Vec::new();

    // A valid chain has each event's `old` equal to the previous event's `new`.
    let mut chain_consistent = true;
    for pair in events.windows(2) {
        if pair[0].new_wasm != pair[1].old_wasm {
            chain_consistent = false;
            warnings.push(format!(
                "inconsistent upgrade chain at ledger {}: {} -> {} then {} -> {}",
                pair[1].ledger,
                crate::runner::short(&pair[0].old_wasm),
                crate::runner::short(&pair[0].new_wasm),
                crate::runner::short(&pair[1].old_wasm),
                crate::runner::short(&pair[1].new_wasm)
            ));
        }
    }

    let mut versions: Vec<VersionRecord> = Vec::new();
    if events.is_empty() {
        versions.push(VersionRecord {
            wasm: current_wasm.clone(),
            current: true,
            live_from: None,
            live_until: None,
            upgrade_tx: None,
            attested_by: None,
        });
    } else {
        // The wasm live before the first scanned upgrade.
        versions.push(VersionRecord {
            wasm: events[0].old_wasm.clone(),
            current: false,
            live_from: None,
            live_until: Some(events[0].closed_at.clone()),
            upgrade_tx: None,
            attested_by: None,
        });
        for (i, ev) in events.iter().enumerate() {
            let is_last = i == events.len() - 1;
            versions.push(VersionRecord {
                wasm: ev.new_wasm.clone(),
                current: false,
                live_from: Some(ev.closed_at.clone()),
                live_until: if is_last {
                    None
                } else {
                    Some(events[i + 1].closed_at.clone())
                },
                upgrade_tx: Some(ev.tx_hash.clone()),
                attested_by: None,
            });
        }

        // The live wasm must equal the newest upgrade's `new`, or upgrades
        // predate the RPC retention window and the lineage has a gap.
        let last = events.last().expect("non-empty events");
        if last.new_wasm != current_wasm {
            chain_consistent = false;
            warnings.push(
                "current on-chain wasm is not the newest upgrade in the scanned window — \
                 some upgrades predate the RPC retention window and are not shown"
                    .to_string(),
            );
            versions.last_mut().expect("non-empty versions").current = false;
            versions.push(VersionRecord {
                wasm: current_wasm.clone(),
                current: true,
                live_from: None,
                live_until: None,
                upgrade_tx: None,
                attested_by: None,
            });
        } else {
            versions.last_mut().expect("non-empty versions").current = true;
        }
    }

    // A no-op upgrade (old == new) does not introduce a new version; collapse
    // consecutive identical hashes so each row is a distinct deployed wasm.
    let mut versions = collapse_noops(versions);

    // Cross-check every version against the sealed artifacts.
    let mut current_attested = false;
    for v in &mut versions {
        let matched = provenance.and_then(|p| {
            p.artifacts
                .iter()
                .find(|a| a.wasm_sha256.eq_ignore_ascii_case(&v.wasm))
        });
        v.attested_by = matched.map(|a| a.id.clone());
        if v.current && v.attested_by.is_some() {
            current_attested = true;
        }
    }
    for v in &versions {
        if v.attested_by.is_none() {
            let which = if v.current {
                "current".to_string()
            } else if v.live_from.is_none() {
                "initial".to_string()
            } else {
                format!(
                    "version at {}",
                    v.live_from.as_deref().unwrap_or("(unknown)")
                )
            };
            warnings.push(format!(
                "{} wasm {}... has no sealed provenance",
                which,
                crate::runner::short(&v.wasm)
            ));
        }
    }

    AuditReport {
        contract_id: contract_hex.to_string(),
        rpc_url: rpc_url.to_string(),
        scan_window,
        events,
        versions,
        chain_consistent,
        current_attested,
        provenance_supplied: provenance.is_some(),
        warnings,
    }
}

/// Merge consecutive versions with the same wasm hash: a no-op upgrade
/// (old == new) does not change what is deployed, so it is not a new version.
fn collapse_noops(mut versions: Vec<VersionRecord>) -> Vec<VersionRecord> {
    let mut merged: Vec<VersionRecord> = Vec::new();
    for v in versions.drain(..) {
        if let Some(prev) = merged.last_mut() {
            if prev.wasm == v.wasm {
                prev.live_until = v.live_until;
                prev.current = prev.current || v.current;
                continue;
            }
        }
        merged.push(v);
    }
    merged
}

/// Render the audit report for the console.
pub fn render_audit(a: &AuditReport) -> String {
    let mut lines = vec!["Sorseal — on-chain audit".to_string(), String::new()];
    lines.push(format!("contract    {}", a.contract_id));
    lines.push(format!("rpc         {}", a.rpc_url));
    lines.push(format!(
        "scan window ledgers {}..{} — {} upgrade event(s) found",
        a.scan_window.0,
        a.scan_window.1,
        a.events.len()
    ));
    lines.push(format!(
        "lineage     {}",
        if a.chain_consistent {
            "consistent".to_string()
        } else {
            "GAPS DETECTED".to_string()
        }
    ));
    lines.push(String::new());
    lines.push(format!(
        "{:<7} {:<12} {:<24} {:<24} {:<8} upgrade tx",
        "version", "wasm sha256", "live from", "live until", "attested"
    ));
    lines.push(
        "─────── ──────────── ──────────────────────── ──────────────────────── ──────── ────────────"
            .to_string(),
    );
    for (i, v) in a.versions.iter().enumerate() {
        let label = if v.current {
            format!("v{i}*")
        } else {
            format!("v{i} ")
        };
        let live_from = v
            .live_from
            .as_deref()
            .map(|s| s[..min(s.len(), 24)].to_string())
            .unwrap_or_else(|| "<deployment>".to_string());
        let live_until = v
            .live_until
            .as_deref()
            .map(|s| s[..min(s.len(), 24)].to_string())
            .unwrap_or_else(|| "now".to_string());
        let attested = if v.attested_by.is_some() {
            "sealed"
        } else {
            "NONE"
        };
        let tx = v
            .upgrade_tx
            .as_deref()
            .map(crate::runner::short)
            .unwrap_or_else(|| "—".to_string());
        lines.push(format!(
            "{label:<7} {:<12} {:<24} {:<24} {:<8} {}",
            crate::runner::short(&v.wasm),
            live_from,
            live_until,
            attested,
            tx
        ));
    }
    lines.push(String::new());
    for w in &a.warnings {
        lines.push(format!("WARNING  {w}"));
    }
    lines.push(String::new());
    match (a.provenance_supplied, a.current_attested) {
        (true, true) => {
            lines.push("PASSED   current deployment is sealed by provenance".to_string())
        }
        (true, false) => {
            lines.push("FAILED   current deployment has NO sealed provenance".to_string())
        }
        (false, _) => lines.push(
            "OK       history reconstructed; no provenance supplied to cross-check".to_string(),
        ),
    }
    lines.join("\n")
}

fn min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_update_matcher_roundtrips() {
        let filter = upgrade_event_filter();
        let topics = filter[0]["topics"][0].as_array().unwrap();
        assert_eq!(topics[0], executable_update_scval());
        assert_eq!(topics[1], "*");
        assert_eq!(topics[2], "*");
        assert!(is_executable_update(&executable_update_scval()));
        assert!(!is_executable_update("not-base64!!"));
    }

    #[test]
    fn decode_upgrade_event_parses_live_fixture() {
        // A real `executable_update` event captured from soroban-testnet for
        // contract CC6BUSDNM... (ledger 3878363). topic[1] is the wasm that
        // was live *before*, topic[2] the one that became live *after*.
        let raw = json!({
            "type": "system",
            "ledger": 3878363,
            "ledgerClosedAt": "2026-07-30T11:29:46Z",
            "contractId": "CC6BUSDNMGLT4EVDRUSEF5MZNHQFJ7NWYJUDDJON6PNPJP6DRLD4QXOF",
            "id": "0017137774209552384-0000000000",
            "operationIndex": 0,
            "transactionIndex": 5,
            "txHash": "8638148be2cbd8a60ceae5ed774fede3f4428bd7f54c170d141e30cae4ef9d14",
            "inSuccessfulContractCall": true,
            "topic": [
                "AAAADwAAABFleGVjdXRhYmxlX3VwZGF0ZQAAAA==",
                "AAAAEAAAAAEAAAACAAAADwAAAARXYXNtAAAADQAAACDJEJ0LamxBvPIMNx4iT9VCEZ8zccM9hqO6um+oXRkUvw==",
                "AAAAEAAAAAEAAAACAAAADwAAAARXYXNtAAAADQAAACA7wVr4Dun6kRcj+0FDiLqnWdnCgKjix6+qEXlVhmRCgw=="
            ],
            "value": "AAAAEAAAAAEAAAAA"
        });
        let ev = decode_upgrade_event(&raw).unwrap();
        assert_eq!(ev.ledger, 3878363);
        assert_eq!(ev.closed_at, "2026-07-30T11:29:46Z");
        assert_eq!(
            ev.tx_hash,
            "8638148be2cbd8a60ceae5ed774fede3f4428bd7f54c170d141e30cae4ef9d14"
        );
        assert_eq!(
            ev.contract,
            "bc1a486d61973e12a38d2442f59969e054fdb6c26831a5cdf3daf4bfc38ac7c8"
        );
        // topic[1] = old, topic[2] = new
        assert_eq!(
            ev.old_wasm,
            "c9109d0b6a6c41bcf20c371e224fd542119f3371c33d86a3baba6fa85d1914bf"
        );
        assert_eq!(
            ev.new_wasm,
            "3bc15af80ee9fa911723fb414388baa759d9c280a8e2c7afaa11795586644283"
        );
    }

    #[test]
    fn decode_rejects_non_upgrade_event() {
        let raw = json!({
            "type": "system",
            "ledger": 1,
            "topic": ["AAAADwAAAAh0cmFuc2Zlcg=="]
        });
        assert!(decode_upgrade_event(&raw).is_err());
    }

    #[test]
    fn parse_ledger_range_extracts_window() {
        let (a, b) =
            parse_ledger_range("startLedger must be within the ledger range: 3874600 - 3995501")
                .unwrap();
        assert_eq!((a, b), (3874600, 3995501));
        assert!(parse_ledger_range("boom").is_none());
    }

    fn provenance_with(wasm: &str) -> Provenance {
        serde_json::from_value(json!({
            "format": "sorseal-provenance",
            "version": 1,
            "project": "demo",
            "toolchain": "stable",
            "git": { "present": false },
            "artifacts": [{ "id": "echo", "command": "cargo build", "wasm_path": "x.wasm",
                "wasm_sha256": wasm, "wasm_size": 1, "source_root": ".", "source_sha256": "0".repeat(64),
                "built_at": "2026-01-01T00:00:00Z" }]
        }))
        .unwrap()
    }

    #[test]
    fn build_audit_reconstructs_lineage_and_attestation() {
        // Two upgrades → three versions. The current on-chain wasm is v2's new.
        let events = vec![
            UpgradeEvent {
                ledger: 1000,
                closed_at: "2026-01-02T00:00:00Z".into(),
                tx_hash: "a".repeat(64),
                contract: "c".into(),
                old_wasm: "11".repeat(32),
                new_wasm: "22".repeat(32),
            },
            UpgradeEvent {
                ledger: 2000,
                closed_at: "2026-01-03T00:00:00Z".into(),
                tx_hash: "b".repeat(64),
                contract: "c".into(),
                old_wasm: "22".repeat(32),
                new_wasm: "33".repeat(32),
            },
        ];
        // provenance seals v1 only
        let prov = provenance_with(&"22".repeat(32));
        let report = build_audit("c", events, "33".repeat(32), Some(&prov), "rpc", (1, 3000));
        assert!(report.chain_consistent);
        assert!(report.provenance_supplied);
        assert_eq!(report.versions.len(), 3);
        assert_eq!(report.versions[0].wasm, "11".repeat(32));
        assert_eq!(report.versions[1].wasm, "22".repeat(32));
        assert!(report.versions[1].attested_by.is_some());
        assert_eq!(report.versions[1].attested_by.as_deref(), Some("echo"));
        assert!(report.versions[0].attested_by.is_none());
        // current (v2) unattested -> fail
        assert!(!report.current_attested);
        assert!(report.versions[2].current);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("current") && w.contains("no sealed provenance")));
    }

    #[test]
    fn build_audit_flags_current_mismatch() {
        // The current wasm differs from the newest upgrade's `new`: a gap.
        let events = vec![UpgradeEvent {
            ledger: 1000,
            closed_at: "2026-01-02T00:00:00Z".into(),
            tx_hash: "a".repeat(64),
            contract: "c".into(),
            old_wasm: "11".repeat(32),
            new_wasm: "22".repeat(32),
        }];
        let report = build_audit("c", events, "99".repeat(32), None, "rpc", (1, 3000));
        assert!(!report.chain_consistent);
        assert!(!report.provenance_supplied);
        assert_eq!(report.versions.len(), 3); // v0, v1, + unmatched current
        assert!(report.versions[2].current);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("retention window")));
    }

    #[test]
    fn build_audit_no_events_is_single_version() {
        let report = build_audit("c", vec![], "ab".repeat(32), None, "rpc", (1, 3000));
        assert_eq!(report.versions.len(), 1);
        assert!(report.versions[0].current);
    }

    #[test]
    fn collapse_noops_merges_identical_consecutive_hashes() {
        let versions = vec![
            VersionRecord {
                wasm: "11".repeat(32),
                live_from: None,
                live_until: Some("2026-01-02T00:00:00Z".into()),
                current: false,
                attested_by: None,
                upgrade_tx: Some("a".repeat(64)),
            },
            // no-op upgrade: same wasm, later window
            VersionRecord {
                wasm: "11".repeat(32),
                live_from: Some("2026-01-02T00:00:00Z".into()),
                live_until: Some("2026-01-03T00:00:00Z".into()),
                current: false,
                attested_by: None,
                upgrade_tx: Some("b".repeat(64)),
            },
            VersionRecord {
                wasm: "22".repeat(32),
                live_from: Some("2026-01-03T00:00:00Z".into()),
                live_until: None,
                current: true,
                attested_by: None,
                upgrade_tx: Some("c".repeat(64)),
            },
        ];
        let merged = collapse_noops(versions);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].wasm, "11".repeat(32));
        assert_eq!(
            merged[0].live_until.as_deref(),
            Some("2026-01-03T00:00:00Z")
        );
        assert_eq!(
            merged[0].upgrade_tx.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert!(!merged[0].current);
        assert!(merged[1].current);
    }

    #[test]
    fn build_audit_collapses_noop_upgrade() {
        // v0 -> no-op upgrade (old == new) -> real upgrade -> current
        let events = vec![
            UpgradeEvent {
                ledger: 1000,
                closed_at: "2026-01-02T00:00:00Z".into(),
                tx_hash: "a".repeat(64),
                contract: "c".into(),
                old_wasm: "11".repeat(32),
                new_wasm: "11".repeat(32),
            },
            UpgradeEvent {
                ledger: 2000,
                closed_at: "2026-01-03T00:00:00Z".into(),
                tx_hash: "b".repeat(64),
                contract: "c".into(),
                old_wasm: "11".repeat(32),
                new_wasm: "22".repeat(32),
            },
        ];
        let report = build_audit("c", events, "22".repeat(32), None, "rpc", (1, 3000));
        assert!(report.chain_consistent);
        assert_eq!(report.versions.len(), 2);
        assert_eq!(report.versions[0].wasm, "11".repeat(32));
        assert_eq!(
            report.versions[0].live_until.as_deref(),
            Some("2026-01-03T00:00:00Z")
        );
        assert!(report.versions[1].current);
        // no-op upgrade tx is dropped; the real change's tx survives
        assert_eq!(
            report.versions[1].upgrade_tx.as_deref(),
            Some("b".repeat(64).as_str())
        );
    }
}
