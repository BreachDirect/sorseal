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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn valid_artifact(id: &str) -> Artifact {
        Artifact {
            id: id.to_string(),
            build_command: "cargo build --release".to_string(),
            wasm_path: PathBuf::from("target/wasm32-unknown-unknown/release/contract.wasm"),
            source_root: PathBuf::from("."),
        }
    }

    fn write_toml(dir: &tempfile::TempDir, text: &str) -> std::path::PathBuf {
        let p = dir.path().join("sorseal.toml");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        p
    }

    #[test]
    fn loads_valid_manifest_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_toml(
            &dir,
            r#"
            [project]
            name = "my-contract"

            [[artifacts]]
            id = "echo"
            build_command = "cargo build --release"
            wasm_path = "target/wasm32-unknown-unknown/release/echo.wasm"
            source_root = "src"
            "#,
        );
        let m = Manifest::load(&p).unwrap();
        assert_eq!(m.project.name, "my-contract");
        assert_eq!(m.artifacts.len(), 1);
        assert_eq!(m.artifacts[0].id, "echo");
    }

    #[test]
    fn rejects_empty_project_name() {
        let mut m = Manifest {
            project: Project { name: "  ".into() },
            artifacts: vec![valid_artifact("a")],
        };
        assert!(m.validate().is_err());
        m.project.name = "x".into();
        assert!(m.validate().is_ok());
    }

    #[test]
    fn rejects_no_artifacts() {
        let m = Manifest {
            project: Project { name: "x".into() },
            artifacts: vec![],
        };
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("at least one"), "{err}");
    }

    #[test]
    fn rejects_duplicate_artifact_ids() {
        let m = Manifest {
            project: Project { name: "x".into() },
            artifacts: vec![valid_artifact("echo"), valid_artifact("echo")],
        };
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate artifact id 'echo'"), "{err}");
    }

    #[test]
    fn rejects_empty_artifact_fields() {
        let mut m = Manifest {
            project: Project { name: "x".into() },
            artifacts: vec![valid_artifact("")],
        };
        assert!(m.validate().is_err());
        let mut a = valid_artifact("a");
        a.build_command = "   ".into();
        let m2 = Manifest {
            project: Project { name: "x".into() },
            artifacts: vec![a],
        };
        assert!(m2.validate().is_err());
        m.artifacts.clear();
        let _ = &mut m;
    }

    #[test]
    fn rejects_absolute_wasm_path() {
        let mut a = valid_artifact("a");
        a.wasm_path = PathBuf::from("/etc/passwd");
        let m = Manifest {
            project: Project { name: "x".into() },
            artifacts: vec![a],
        };
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("must be a relative path"), "{err}");
    }

    #[test]
    fn rejects_parent_dir_via_source_root() {
        let mut a = valid_artifact("a");
        a.source_root = PathBuf::from("../outside");
        let m = Manifest {
            project: Project { name: "x".into() },
            artifacts: vec![a],
        };
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("must not contain '..'"), "{err}");
    }

    #[test]
    fn rejects_empty_wasm_path() {
        let mut a = valid_artifact("a");
        a.wasm_path = PathBuf::from("");
        let m = Manifest {
            project: Project { name: "x".into() },
            artifacts: vec![a],
        };
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("must not be empty"), "{err}");
    }

    #[test]
    fn invalid_toml_fails_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_toml(&dir, "[project\nname = "); // malformed TOML
        assert!(Manifest::load(&p).is_err());
    }
}
