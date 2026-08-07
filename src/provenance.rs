//! `sorseal.provenance.json` — the sealed record of what was built and hashed.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const PROVENANCE_FILENAME: &str = "sorseal.provenance.json";
pub const FORMAT: &str = "sorseal-provenance";
pub const VERSION: u32 = 1;

/// Source-control state captured at seal time. `present: false` means the
/// project was not a git repository, so git checks are skipped on verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitState {
    pub present: bool,
    #[serde(default)]
    pub commit: String,
    #[serde(default)]
    pub clean: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    pub id: String,
    pub command: String,
    pub wasm_path: String,
    pub wasm_sha256: String,
    pub wasm_size: u64,
    pub source_root: String,
    pub source_sha256: String,
    pub built_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub format: String,
    pub version: u32,
    pub project: String,
    pub toolchain: String,
    pub git: GitState,
    pub artifacts: Vec<ArtifactProvenance>,
}

impl Provenance {
    /// Load and validate a provenance file from disk.
    pub fn load(path: &Path) -> Result<Provenance> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let p: Provenance = serde_json::from_str(&contents)
            .map_err(|e| anyhow!("invalid provenance JSON in {}: {e}", path.display()))?;
        p.validate()?;
        Ok(p)
    }

    /// Structural validation shared by `load` and tests: the record must be the
    /// right format/version and every digest must be well-formed, so a
    /// corrupted or hand-edited provenance is rejected up front instead of
    /// producing confusing comparisons later.
    fn validate(&self) -> Result<()> {
        if self.format != FORMAT {
            bail!(
                "unrecognized provenance format '{}' (expected '{FORMAT}')",
                self.format
            );
        }
        if self.version != VERSION {
            bail!(
                "unsupported provenance version {} (expected {VERSION})",
                self.version
            );
        }
        if self.project.trim().is_empty() {
            bail!("provenance.project must not be empty");
        }
        if self.git.present && self.git.commit.trim().is_empty() {
            bail!("provenance records a git commit but the commit is empty");
        }
        for a in &self.artifacts {
            if !is_hex64(&a.wasm_sha256) {
                bail!(
                    "artifact '{}': wasm_sha256 '{}' is not 64 hex chars",
                    a.id,
                    a.wasm_sha256
                );
            }
            if !is_hex64(&a.source_sha256) {
                bail!(
                    "artifact '{}': source_sha256 '{}' is not 64 hex chars",
                    a.id,
                    a.source_sha256
                );
            }
        }
        Ok(())
    }

    /// Write the provenance to disk, pretty-printed.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json + "\n")?;
        Ok(())
    }
}

/// True when `s` is exactly 64 lowercase/uppercase ASCII hex chars.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_provenance() -> Provenance {
        Provenance {
            format: FORMAT.to_string(),
            version: VERSION,
            project: "demo".to_string(),
            toolchain: "rustc 1.95.0".to_string(),
            git: GitState {
                present: true,
                commit: "a".repeat(40),
                clean: true,
            },
            artifacts: vec![ArtifactProvenance {
                id: "echo".to_string(),
                command: "cargo build".to_string(),
                wasm_path: "x.wasm".to_string(),
                wasm_sha256: "f".repeat(64),
                wasm_size: 1,
                source_root: ".".to_string(),
                source_sha256: "e".repeat(64),
                built_at: "2026-01-01T00:00:00Z".to_string(),
            }],
        }
    }

    #[test]
    fn rejects_bad_format_and_version() {
        let mut p = valid_provenance();
        p.format = "other".into();
        assert!(p.validate().is_err());
        p = valid_provenance();
        p.version = 99;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_malformed_digests() {
        let mut p = valid_provenance();
        p.artifacts[0].wasm_sha256 = "not-a-digest".into();
        assert!(p.validate().is_err());
        p = valid_provenance();
        p.artifacts[0].source_sha256 = "zz".repeat(32);
        assert!(p.validate().is_err());
        p = valid_provenance();
        p.git.commit = "".into();
        assert!(p.validate().is_err());
    }
}
