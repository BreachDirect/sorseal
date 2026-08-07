//! `sorseal.toml` — declares which artifacts to build, hash, and seal.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const MANIFEST_FILENAME: &str = "sorseal.toml";

fn default_source_root() -> PathBuf {
    PathBuf::from(".")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
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
            .with_context(|| format!("failed to read {}", path.display()))?;
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
        let mut seen = std::collections::HashSet::new();
        for a in &self.artifacts {
            if a.id.trim().is_empty() {
                bail!("artifact: 'id' must not be empty");
            }
            if !seen.insert(a.id.as_str()) {
                bail!("manifest: duplicate artifact id '{}'", a.id);
            }
            if a.build_command.trim().is_empty() {
                bail!("artifact '{}': 'build_command' must not be empty", a.id);
            }
            validate_tree_path(&a.id, "wasm_path", &a.wasm_path)?;
            validate_tree_path(&a.id, "source_root", &a.source_root)?;
        }
        Ok(())
    }
}

/// A tree path must be relative and stay inside the project, so the seal
/// covers files that actually live in the repository.
fn validate_tree_path(id: &str, field: &str, p: &Path) -> Result<()> {
    if p.as_os_str().is_empty() {
        bail!("artifact '{id}': '{field}' must not be empty");
    }
    if !p.is_relative() {
        bail!(
            "artifact '{id}': '{field}' must be a relative path, got '{}'",
            p.display()
        );
    }
    for comp in p.components() {
        if comp == Component::ParentDir {
            bail!(
                "artifact '{id}': '{field}' must not contain '..', got '{}'",
                p.display()
            );
        }
    }
    Ok(())
}
