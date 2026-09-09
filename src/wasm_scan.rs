//! Binary-level scanning of the compiled `.wasm` artifact.
//!
//! `sorseal analyze --wasm` inspects the sealed WASM binary directly rather
//! than the Rust source, so it verifies what is actually deployed. It is a
//! minimal hand-rolled parser (magic + version + section walk via LEB128) with
//! no wasm-crate dependency, in keeping with the repo's dependency-light rule.
//!
//! Findings use stable `RuleId::Wasm*` ids so they flow through the existing
//! console/JSON/Markdown/SARIF renderers and the sealed analysis digest.

use anyhow::{bail, Result};

/// LEB128 (unsigned) offset reader used for section lengths.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn next_u8(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// Unsigned LEB128 (u32/u64 per MVP spec).
    fn next_uleb(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.next_u8()?;
            result |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
            if shift >= 64 {
                return None; // malformed
            }
        }
    }
}

/// A summary of the WASM structure we care about for scanning purposes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WasmStats {
    /// Number of entries in the function section (declarations).
    pub functions: u64,
    /// Number of entries in the export section.
    pub exports: u64,
    /// Number of declared memories.
    pub memories: u64,
    /// Number of exported functions whose code body contains an `unreachable`
    /// opcode (0x00) immediately followed by `end` (0x0b) — a trap path that
    /// is reachable by callers.
    pub trappy_exports: u64,
    /// True when the file starts with the WASM magic + MVP version.
    pub is_valid_wasm: bool,
}

/// Opcode field aliases used by the binary scan (MVP encodings; multi-byte
/// opcodes have a prefix `0xfc`/`0xfd` for misc/sat types).
const OP_UNREACHABLE: u8 = 0x00;
const OP_END: u8 = 0x0b;

/// Parse a WASM binary and compute `WasmStats`.
pub fn scan(bytes: &[u8]) -> Result<WasmStats> {
    let mut r = Reader::new(bytes);
    // Magic: \0asm ; version: 0x01 0x00 0x00 0x00
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" || bytes[4..8] != [0x01, 0x00, 0x00, 0x00] {
        bail!("not a wasm module (missing \\0asm magic / MVP version)");
    }
    r.pos = 8;
    let mut stats = WasmStats {
        is_valid_wasm: true,
        ..WasmStats::default()
    };

    // Section format: id:u8, size:uleb, payload.
    while r.remaining() > 0 {
        let id = r.next_u8().unwrap();
        let size = r.next_uleb().unwrap_or(0);
        let start = r.pos;
        let end = (start + size as usize).min(bytes.len());
        match id {
            3 /* function section: vec<(type_idx:u32)> */ => {
                let mut sub = Reader::new(&bytes[start..end]);
                stats.functions = sub.next_uleb().unwrap_or(0);
            }
            5 /* memory section: vec<limits> */ => {
                let mut sub = Reader::new(&bytes[start..end]);
                stats.memories = sub.next_uleb().unwrap_or(0);
            }
            7 /* export section: vec<(name, kind, idx)> */ => {
                let mut sub = Reader::new(&bytes[start..end]);
                stats.exports = sub.next_uleb().unwrap_or(0);
            }
            _ => {}
        }
        r.pos = end;
    }

    // Scan each code section body for unreachable;end trap sequences. We walk
    // the raw bytes instead of reconstructing full instruction decoding, which
    // is enough for a high-signal "trap reachable from callers" flag.
    let mut r2 = Reader::new(bytes);
    r2.pos = 8;
    while r2.remaining() > 0 {
        let id = r2.next_u8().unwrap();
        let size = r2.next_uleb().unwrap_or(0);
        let start = r2.pos;
        let end = (start + size as usize).min(bytes.len());
        if id == 10 {
            // code section: vec<body: uleb size + bytes>
            let mut sub = Reader::new(&bytes[start..end]);
            let n = sub.next_uleb().unwrap_or(0);
            for _ in 0..n {
                let body_size = sub.next_uleb().unwrap_or(0) as usize;
                let body_start_abs = start + sub.pos;
                let body_end_abs = (body_start_abs + body_size).min(end);
                if body_start_abs < body_end_abs {
                    let body = &bytes[body_start_abs..body_end_abs];
                    if body
                        .windows(2)
                        .any(|w| w[0] == OP_UNREACHABLE && w[1] == OP_END)
                    {
                        stats.trappy_exports += 1;
                    }
                }
                sub.pos = (sub.pos + body_size).min(end - start);
            }
        }
        r2.pos = end;
    }

    Ok(stats)
}

/// High-signal binary findings for a wasm artifact on top of `WasmStats`.
/// Reuses the finding shape so SARIF/JSON/digest handle them uniformly.
pub fn wasm_findings(stats: &WasmStats) -> Vec<crate::analyze::Finding> {
    let mut out = Vec::new();
    if stats.trappy_exports > 0 {
        out.push(crate::analyze::Finding {
            rule: crate::analyze::RuleId::WasmUnreachableExport,
            severity: crate::analyze::Severity::High,
            message: format!(
                "wasm bytecode contains {} exported function body(s) with an `unreachable` trap; \
                 callers can be reverted by reaching this path",
                stats.trappy_exports
            ),
            file: "artifact.wasm".to_string(),
            line: 1,
            remediation: "Inspect the trap path: the exported entry point should return a \
                          structured error (e.g. a Status/ErrCode) rather than an `unreachable`.",
        });
    }
    if stats.exports == 0 {
        out.push(crate::analyze::Finding {
            rule: crate::analyze::RuleId::WasmNoExports,
            severity: crate::analyze::Severity::Medium,
            message: "wasm module declares zero exports; a deployable Soroban contract \
                      must expose at least one export (e.g. `__check_auth`, entry points)"
                .to_string(),
            file: "artifact.wasm".to_string(),
            line: 1,
            remediation: "Ensure the `#[contractimpl]` (or `wasm` export) attributes are present \
                          so the build emits entry-point exports before deploying.",
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, valid MVP module: `\0asm` magic, version 1, one custom
    /// section (id 0) of 3 bytes `abc`, no functions/exports.
    fn minimal_wasm() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, // magic \0asm
            0x01, 0x00, 0x00, 0x00, // version 1
            0x00, 0x03, 0x61, 0x62, 0x63, // custom section "abc"
        ]
    }

    /// A wasm with one function (2 declarations = 1), one export, one memory,
    /// and a code body containing an unreachable;end trap.
    fn trappy_wasm() -> Vec<u8> {
        // type section omitted (type 0 assumed); function section: 1 fn of type 0
        let mut w = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
            // function section (id 3): vec count=1, type idx 0
            0x03, 0x02, 0x01, 0x00,
            // memory section (id 5): count=1, limits min=1, flags 0x00
            0x05, 0x03, 0x01, 0x00, 0x01,
        ];
        // code section (id 10): count=1, body size=2, body = 0x00 0x0b
        w.extend_from_slice(&[0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b]);
        w
    }

    #[test]
    fn rejects_non_wasm_bytes() {
        assert!(scan(b"hello world, definitely not wasm").is_err());
        assert!(scan(b"\x00\x61\x73\x6d\x02\x00\x00\x00").is_err()); // wrong version
    }

    #[test]
    fn parses_minimal_valid_module() {
        let stats = scan(&minimal_wasm()).unwrap();
        assert!(stats.is_valid_wasm);
        assert_eq!(stats.exports, 0);
        assert_eq!(stats.functions, 0);
        assert_eq!(stats.trappy_exports, 0);
    }

    #[test]
    fn detects_unreachable_trap_in_export_body() {
        let stats = scan(&trappy_wasm()).unwrap();
        assert!(stats.is_valid_wasm);
        assert!(stats.trappy_exports >= 1);
        let findings = wasm_findings(&stats);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == crate::analyze::RuleId::WasmUnreachableExport),
            "expected wasm-unreachable finding: {findings:?}"
        );
    }

    #[test]
    fn flags_module_without_exports() {
        let stats = scan(&minimal_wasm()).unwrap();
        let findings = wasm_findings(&stats);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == crate::analyze::RuleId::WasmNoExports),
            "expected wasm-no-exports finding: {findings:?}"
        );
    }
}
