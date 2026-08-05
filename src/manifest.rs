//! `sorseal.toml` — declares which artifacts to build, hash, and seal.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const MANIFEST_FILENAME: &str = "sorseal.toml";

fn default_toolchain() -> String {
    "stable".to_string()
}

fn default_source_root() -> PathBuf {
    PathBuf::from(".")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    #[serde(default = "default_toolchain")]
    pub toolchain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub build_command: String,
    pub wasm_path: PathBuf,
    #[serde(default = "default_source_root")]
    pub source_root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub project: Project,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
}

impl Manifest {
    /// Load and validate a manifest from disk.
    pub fn load(path: &Path) -> Result<Manifest> {
        let contents = fs::read_to_string(path)
            .map_err(|_| anyhow!("manifest not found: {}", path.display()))?;
        let manifest: Manifest =
            toml::from_str(&contents).map_err(|e| anyhow!("invalid {}: {e}", path.display()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        if self.project.name.trim().is_empty() {
            bail!("manifest.project.name must not be empty");
        }
        if self.artifacts.is_empty() {
            bail!("manifest: at least one [[artifacts]] entry is required");
        }
        for a in &self.artifacts {
            if a.id.trim().is_empty() {
                bail!("artifact: 'id' must not be empty");
            }
            if a.build_command.trim().is_empty() {
                bail!("artifact '{}': 'build_command' must not be empty", a.id);
            }
            if a.wasm_path.as_os_str().is_empty() {
                bail!("artifact '{}': 'wasm_path' must not be empty", a.id);
            }
            if a.source_root.as_os_str().is_empty() {
                bail!("artifact '{}': 'source_root' must not be empty", a.id);
            }
        }
        Ok(())
    }
}
