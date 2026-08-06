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
        if p.format != FORMAT {
            bail!(
                "unrecognized provenance format '{}' (expected '{FORMAT}')",
                p.format
            );
        }
        if p.version != VERSION {
            bail!(
                "unsupported provenance version {} (expected {VERSION})",
                p.version
            );
        }
        Ok(p)
    }

    /// Write the provenance to disk, pretty-printed.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json + "\n")?;
        Ok(())
    }
}
