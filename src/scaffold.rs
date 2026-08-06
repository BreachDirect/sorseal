//! `sorseal init` — scaffold a manifest, discovering contract crates when
//! possible from the surrounding Cargo project.

use crate::manifest::{Artifact, Manifest, Project};
use anyhow::{bail, Result};
use std::fs;
use std::path::{Path, PathBuf};
use toml::{Table, Value};

#[derive(Debug)]
struct Package {
    dir: PathBuf,
    name: String,
    lib_name: String,
    is_cdylib: bool,
}

fn parse_package(dir: &Path, value: &Table) -> Option<Package> {
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
    let Ok(value) = text.parse::<Table>() else {
        return Vec::new();
    };

    if let Some(members) = value
        .get("workspace")
        .and_then(|w| w.as_table())
        .and_then(|w| w.get("members"))
        .and_then(Value::as_array)
    {
        let mut out = Vec::new();
        // A root package in a workspace is an implicit member.
        if value.get("package").is_some() {
            if let Some(p) = parse_package(root, &value) {
                out.push(p);
            }
        }
        let names: Vec<&str> = members.iter().filter_map(Value::as_str).collect();
        for dir in expand_members(root, &names) {
            let Ok(t) = fs::read_to_string(dir.join("Cargo.toml")) else {
                continue;
            };
            if let Ok(v) = t.parse::<Table>() {
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

/// Expand workspace member entries. Cargo allows glob patterns such as
/// `contracts/*`; expand `*` within a path segment and `**` across segments.
fn expand_members(root: &Path, members: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for m in members {
        let m = m.trim();
        if m.is_empty() {
            continue;
        }
        if !m.contains('*') {
            out.push(root.join(m));
        } else {
            let segs: Vec<&str> = m.split('/').filter(|s| !s.is_empty()).collect();
            walk_pattern(root, &segs, &mut out);
        }
    }
    out
}

fn walk_pattern(dir: &Path, segs: &[&str], out: &mut Vec<PathBuf>) {
    let Some((head, rest)) = segs.split_first() else {
        out.push(dir.to_path_buf());
        return;
    };
    if *head == "**" {
        walk_pattern(dir, rest, out);
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                walk_pattern(&e.path(), segs, out);
            }
        }
    } else if head.contains('*') {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !segment_matches(head, name) {
                continue;
            }
            if rest.is_empty() {
                out.push(e.path());
            } else if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                walk_pattern(&e.path(), rest, out);
            }
        }
    } else {
        walk_pattern(&dir.join(head), rest, out);
    }
}

/// Match a single path segment against a `*` pattern, where `*` matches any
/// (possibly empty) run of characters.
fn segment_matches(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let mut rest = name;
    if let Some(first) = parts.first() {
        if !first.is_empty() {
            let Some(r) = rest.strip_prefix(first) else {
                return false;
            };
            rest = r;
        }
    }
    if let Some(last) = parts.last() {
        if !last.is_empty() {
            let Some(r) = rest.strip_suffix(last) else {
                return false;
            };
            rest = r;
        }
    }
    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        let Some(i) = rest.find(part) else {
            return false;
        };
        rest = &rest[i + part.len()..];
    }
    true
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
        project: Project { name },
        artifacts,
    })
}

impl Manifest {
    /// Whether this manifest is still the un-edited placeholder from `init`.
    pub fn is_placeholder(&self) -> bool {
        self.artifacts.iter().any(|a| a.id == PLACEHOLDER_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_matching() {
        assert!(segment_matches("*", "echo"));
        assert!(segment_matches("echo", "echo"));
        assert!(segment_matches("e*", "echo"));
        assert!(segment_matches("*o", "echo"));
        assert!(segment_matches("e*o", "echo"));
        assert!(segment_matches("ec*o", "echo"));
        assert!(segment_matches("ech*", "echo"));
        assert!(!segment_matches("ech", "echo"));
        assert!(!segment_matches("a*b", "acd"));
        assert!(!segment_matches("a*b*c", "abX"));
        assert!(segment_matches("a*b*c", "aXbYc"));
    }

    #[test]
    fn expands_glob_members() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("contracts/echo")).unwrap();
        fs::create_dir_all(tmp.path().join("contracts/escrow")).unwrap();
        fs::create_dir_all(tmp.path().join("src")).unwrap();

        let mut dirs = expand_members(tmp.path(), &["contracts/*"]);
        let mut names: Vec<String> = dirs
            .iter()
            .map(|d| {
                d.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
                    .to_string()
            })
            .collect();
        names.sort();
        assert_eq!(names, vec!["echo", "escrow"]);

        dirs = expand_members(tmp.path(), &["src", "contracts/echo"]);
        assert_eq!(
            dirs,
            vec![tmp.path().join("src"), tmp.path().join("contracts/echo")]
        );
    }
}
