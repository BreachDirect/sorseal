//! `sorseal init` — scaffold a manifest, discovering contract crates when
//! possible from the surrounding Cargo project.

use crate::manifest::{Artifact, Manifest, Project};
use anyhow::{bail, Result};
use std::fs;
use std::path::{Path, PathBuf};
use toml::Value;

#[derive(Debug)]
struct Package {
    dir: PathBuf,
    name: String,
    lib_name: String,
    is_cdylib: bool,
}

fn parse_package(dir: &Path, value: &Value) -> Option<Package> {
    let package = value.get("package")?;
    let name = package.get("name")?.as_str()?.to_string();
    let lib_name = value
        .get("lib")
        .and_then(|l| l.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| name.replace('-', "_"));
    let crate_types: Vec<String> = value
        .get("lib")
        .and_then(|l| l.get("crate-type"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let is_cdylib = crate_types.iter().any(|t| t == "cdylib");
    Some(Package {
        dir: dir.to_path_buf(),
        name,
        lib_name,
        is_cdylib,
    })
}

fn discover_packages(root: &Path) -> Vec<Package> {
    let root_cargo = root.join("Cargo.toml");
    let Ok(text) = fs::read_to_string(&root_cargo) else {
        return Vec::new();
    };
    let Ok(value) = text.parse::<Value>() else {
        return Vec::new();
    };

    if let Some(members) = value
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(Value::as_array)
    {
        let mut out = Vec::new();
        for member in members.iter().filter_map(Value::as_str) {
            let dir = root.join(member);
            let Ok(t) = fs::read_to_string(dir.join("Cargo.toml")) else {
                continue;
            };
            if let Ok(v) = t.parse::<Value>() {
                if let Some(p) = parse_package(&dir, &v) {
                    out.push(p);
                }
            }
        }
        out
    } else if value.get("package").is_some() {
        parse_package(root, &value).into_iter().collect()
    } else {
        Vec::new()
    }
}

const PLACEHOLDER_ID: &str = "artifact-id";

/// Build a manifest for the given directory, discovering cdylib contract
/// crates where possible and otherwise falling back to a placeholder entry.
pub fn scaffold_manifest(
    dir: &Path,
    project_name: Option<String>,
    force: bool,
) -> Result<Manifest> {
    let target = dir.join(crate::manifest::MANIFEST_FILENAME);
    if target.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite",
            crate::manifest::MANIFEST_FILENAME
        );
    }

    let packages = discover_packages(dir);
    let fallback_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-contract");
    let name = project_name.unwrap_or_else(|| {
        packages
            .first()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| fallback_name.to_string())
    });

    let artifacts: Vec<Artifact> = packages
        .iter()
        .filter(|p| p.is_cdylib)
        .map(|p| Artifact {
            id: p.name.clone(),
            build_command: format!(
                "cargo build --release --target wasm32-unknown-unknown -p {}",
                p.name
            ),
            wasm_path: PathBuf::from(format!(
                "target/wasm32-unknown-unknown/release/{}.wasm",
                p.lib_name
            )),
            source_root: if p.dir == dir {
                PathBuf::from(".")
            } else {
                p.dir.clone()
            },
        })
        .collect();

    let artifacts = if artifacts.is_empty() {
        vec![Artifact {
            id: PLACEHOLDER_ID.to_string(),
            build_command: "cargo build --release --target wasm32-unknown-unknown".to_string(),
            wasm_path: PathBuf::from("target/wasm32-unknown-unknown/release/my_contract.wasm"),
            source_root: PathBuf::from("."),
        }]
    } else {
        artifacts
    };

    Ok(Manifest {
        project: Project {
            name,
            toolchain: "stable".to_string(),
        },
        artifacts,
    })
}

impl Manifest {
    /// Whether this manifest is still the un-edited placeholder from `init`.
    pub fn is_placeholder(&self) -> bool {
        self.artifacts.iter().any(|a| a.id == PLACEHOLDER_ID)
    }
}
