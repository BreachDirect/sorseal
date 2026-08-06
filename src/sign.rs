//! Ed25519 signing and DSSE/SLSA v1.0 attestation for sealed provenance.

use crate::digest;
use crate::provenance::Provenance;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::rand_core::UnwrapErr;
use getrandom::SysRng;
use serde_json::{json, Value};
use std::path::Path;

pub const PRIVATE_KEY_EXT: &str = "sorseal.key";
pub const PUBLIC_KEY_EXT: &str = "sorseal.pub";
pub const ATTESTATION_FILENAME: &str = "sorseal.attestation.json";
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Generate an Ed25519 keypair and write the private key to `key_path`.
/// The public key is derived and returned so the caller can print it.
pub fn keygen(key_path: &Path) -> Result<String> {
    let mut csprng = UnwrapErr(SysRng);
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    if let Some(parent) = key_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    std::fs::write(key_path, signing_key.to_bytes())
        .with_context(|| format!("failed to write private key to {}", key_path.display()))?;
    set_private_perm(key_path);
    Ok(encode_hex(&verifying_key.to_bytes()))
}

/// Read a private key file and return the signing key.
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read private key {}", path.display()))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("private key must be exactly 32 bytes: {}", path.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Read a public key file (32 raw bytes or hex) and return the verifying key.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read public key {}", path.display()))?;
    let raw: Vec<u8> = if bytes.len() == 32 {
        bytes.to_vec()
    } else {
        // allow ASCII-hex encoded keys (trailing whitespace tolerated)
        let text = String::from_utf8(bytes.to_vec())
            .map_err(|_| anyhow!("public key is neither 32 raw bytes nor 64 hex chars"))?;
        hex_to_bytes(text.trim())?
    };
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("public key must decode to exactly 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("invalid Ed25519 public key: {e}"))
}

/// Build a DSSE-signed SLSA v1.0 attestation for the sealed provenance and
/// write it to `out_path`.
pub fn attest(signing_key: &SigningKey, provenance: &Provenance, out_path: &Path) -> Result<()> {
    let statement = build_slsa_statement(provenance);
    let payload = serde_json::to_vec(&statement)?;
    let envelope = sign_dsse(signing_key, &payload);
    std::fs::write(out_path, serde_json::to_string_pretty(&envelope)? + "\n")
        .with_context(|| format!("failed to write attestation to {}", out_path.display()))?;
    Ok(())
}

/// Sign a payload as a DSSE envelope (https://github.com/secure-systems-lab/dsse).
fn sign_dsse(signing_key: &SigningKey, payload: &[u8]) -> Value {
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload_b64 = b64.encode(payload);
    // DSSE pre-authentication encoding: "DSSEv1" SP payloadType SP payload
    let pae = format!("DSSEv1 {DSSE_PAYLOAD_TYPE} {payload_b64}");
    let signature: Signature = signing_key.sign(pae.as_bytes());
    let keyid = encode_hex(&signing_key.verifying_key().to_bytes());

    json!({
        "payload": payload_b64,
        "payloadType": DSSE_PAYLOAD_TYPE,
        "signatures": [{
            "keyid": keyid,
            "sig": b64.encode(signature.to_bytes())
        }]
    })
}

/// Verify a DSSE envelope against a public key and return the payload bytes.
pub fn verify_dsse(envelope: &Value, verifying_key: &VerifyingKey) -> Result<Vec<u8>> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload_b64 = envelope
        .get("payload")
        .and_then(|p| p.as_str())
        .ok_or_else(|| anyhow!("attestation is missing 'payload'"))?;
    let payload_type = envelope
        .get("payloadType")
        .and_then(|p| p.as_str())
        .ok_or_else(|| anyhow!("attestation is missing 'payloadType'"))?;
    if payload_type != DSSE_PAYLOAD_TYPE {
        bail!(
            "unsupported payloadType '{}' (expected '{DSSE_PAYLOAD_TYPE}')",
            payload_type
        );
    }

    let signatures = envelope
        .get("signatures")
        .and_then(|s| s.as_array())
        .ok_or_else(|| anyhow!("attestation is missing 'signatures'"))?;
    if signatures.is_empty() {
        bail!("attestation has no signatures");
    }

    let sig_b64 = signatures[0]
        .get("sig")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("first signature is missing 'sig'"))?;
    let sig_bytes = b64
        .decode(sig_b64)
        .map_err(|e| anyhow!("invalid base64 signature: {e}"))?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| anyhow!("invalid Ed25519 signature: {e}"))?;

    let payload = b64
        .decode(payload_b64)
        .map_err(|e| anyhow!("invalid base64 payload: {e}"))?;

    let pae = format!("DSSEv1 {payload_type} {payload_b64}");
    verifying_key
        .verify(pae.as_bytes(), &signature)
        .map_err(|_| anyhow!("attestation signature verification failed"))?;
    Ok(payload)
}

/// Build an in-toto Statement v1 with a SLSA v1.0 provenance predicate from a
/// sealed sorseal provenance record.
fn build_slsa_statement(provenance: &Provenance) -> Value {
    let subjects: Vec<Value> = provenance
        .artifacts
        .iter()
        .map(|a| {
            json!({
                "name": a.wasm_path,
                "digest": { "sha256": a.wasm_sha256 }
            })
        })
        .collect();

    let (invocation_id, started) = match provenance.artifacts.first() {
        Some(a) => (
            if provenance.git.present {
                provenance.git.commit.clone()
            } else {
                format!("build:{}", a.built_at)
            },
            a.built_at.clone(),
        ),
        None => (String::new(), String::new()),
    };

    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://breachdirect.dev/sorseal/build/v1",
                "externalParameters": {
                    "toolchain": provenance.toolchain,
                    "project": provenance.project
                },
                "internalParameters": {
                    "artifacts": provenance.artifacts.iter().map(|a| json!({
                        "id": a.id,
                        "command": a.command,
                        "source_root": a.source_root,
                        "source_sha256": a.source_sha256
                    })).collect::<Vec<_>>()
                },
                "resolvedDependencies": provenance.artifacts.iter().map(|a| json!({
                    "uri": format!("git+{}", a.source_root),
                    "digest": { "sha256": a.source_sha256 }
                })).collect::<Vec<_>>()
            },
            "runDetails": {
                "builder": { "id": "https://github.com/BreachDirect/sorseal" },
                "buildType": "https://breachdirect.dev/sorseal/build/v1",
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": started,
                    "finishedOn": started
                },
                "byproducts": [{
                    "name": "format",
                    "value": provenance.format
                }]
            }
        }
    })
}

/// A simple in-toto/Statement-free subject check: verify the signed attestation
/// payload lists the same artifact digests as the sealed provenance.
pub fn subjects_match(statement: &Value, provenance: &Provenance) -> Result<bool> {
    let subjects = statement
        .get("subject")
        .and_then(|s| s.as_array())
        .ok_or_else(|| anyhow!("statement has no 'subject' array"))?;

    for art in &provenance.artifacts {
        let found = subjects.iter().any(|s| {
            s.get("name").and_then(|n| n.as_str()) == Some(art.wasm_path.as_str())
                && s.pointer("/digest/sha256").and_then(|d| d.as_str())
                    == Some(art.wasm_sha256.as_str())
        });
        if !found {
            return Ok(false);
        }
    }
    Ok(true)
}

fn encode_hex(bytes: &[u8]) -> String {
    digest::hex(bytes)
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid hex string for public key");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| anyhow!("{e}")))
        .collect()
}

#[cfg(unix)]
fn set_private_perm(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_private_perm(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{ArtifactProvenance, GitState};
    use tempfile::tempdir;

    fn sample_provenance() -> Provenance {
        Provenance {
            format: crate::provenance::FORMAT.to_string(),
            version: crate::provenance::VERSION,
            project: "demo".to_string(),
            toolchain: "rustc 1.95.0".to_string(),
            git: GitState {
                present: true,
                commit: "a".repeat(40),
                clean: true,
            },
            artifacts: vec![ArtifactProvenance {
                id: "echo".to_string(),
                command: "cargo build --release".to_string(),
                wasm_path: "target/release/echo.wasm".to_string(),
                wasm_sha256: "f".repeat(64),
                wasm_size: 1024,
                source_root: ".".to_string(),
                source_sha256: "e".repeat(64),
                built_at: "2026-08-06T00:00:00Z".to_string(),
            }],
        }
    }

    #[test]
    fn keygen_roundtrip_and_signature() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.sorseal.key");
        let pub_hex = keygen(&key_path).unwrap();
        assert_eq!(pub_hex.len(), 64);

        let sk = load_signing_key(&key_path).unwrap();
        assert_eq!(encode_hex(&sk.verifying_key().to_bytes()), pub_hex);

        let vk = load_verifying_key(&write_pub(&dir, &pub_hex)).unwrap();
        assert_eq!(vk, sk.verifying_key());
    }

    #[test]
    fn attest_sign_and_verify_roundtrip() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.sorseal.key");
        let pub_hex = keygen(&key_path).unwrap();
        let sk = load_signing_key(&key_path).unwrap();

        let prov = sample_provenance();
        let out_path = dir.path().join("sorseal.attestation.json");
        attest(&sk, &prov, &out_path).unwrap();

        let envelope: Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
        let vk = load_verifying_key(&write_pub(&dir, &pub_hex)).unwrap();
        let payload = verify_dsse(&envelope, &vk).unwrap();
        let statement: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(statement["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(statement["predicateType"], "https://slsa.dev/provenance/v1");
        assert!(subjects_match(&statement, &prov).unwrap());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.sorseal.key");
        let pub_hex = keygen(&key_path).unwrap();
        let sk = load_signing_key(&key_path).unwrap();
        let prov = sample_provenance();
        let out_path = dir.path().join("sorseal.attestation.json");
        attest(&sk, &prov, &out_path).unwrap();

        let mut envelope: Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
        envelope["payload"] = base64::engine::general_purpose::STANDARD
            .encode(b"tampered")
            .into();
        let vk = load_verifying_key(&write_pub(&dir, &pub_hex)).unwrap();
        assert!(verify_dsse(&envelope, &vk).is_err());
    }

    fn write_pub(dir: &tempfile::TempDir, hex: &str) -> std::path::PathBuf {
        let p = dir.path().join("test.pub");
        std::fs::write(&p, hex.as_bytes()).unwrap();
        p
    }
}
