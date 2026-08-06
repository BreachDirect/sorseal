//! Deterministic content digests for files and directory trees.

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;

/// Hex-encode a digest.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// SHA-256 of a file's raw bytes.
pub fn file_sha256(path: &Path) -> Result<String, anyhow::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Directory names always excluded from tree digests.
const SKIP_DIRS: [&str; 2] = [".git", "target"];

/// sorseal-generated output files always excluded from tree digests, exactly
/// like the provenance file: a seal must never depend on its own outputs. This
/// keeps the documented `record -> sign -> verify` flow reproducible — the
/// attestation, keys, and SARIF report live in the tree but are not source.
const SKIP_FILES: [&str; 4] = [
    crate::provenance::PROVENANCE_FILENAME,
    crate::sign::ATTESTATION_FILENAME,
    "sorseal.key",
    "sorseal.pub",
];

/// Any SARIF report is a generated output regardless of the `--sarif` filename.
const SARIF_EXTENSION: &str = ".sarif";

/// SHA-256 of a directory tree, keyed on relative path + file bytes.
///
/// Traversal is depth-first and paths are sorted before hashing, so the digest
/// depends only on content, never on filesystem iteration order. Generated
/// sorseal outputs are excluded so a record never depends on a previous record.
pub fn tree_sha256(root: &Path) -> Result<String, anyhow::Error> {
    let mut files: Vec<String> = Vec::new();
    collect(root, root, &mut files)?;
    files.sort();

    let mut hasher = Sha256::new();
    for rel in &files {
        hasher.update(rel.as_bytes());
        hasher.update(b"\n");
        hash_file(&mut hasher, &root.join(rel))?;
        hasher.update(b"\n");
    }
    Ok(hex(&hasher.finalize()))
}

/// Stream a file's bytes into `hasher` without buffering it fully in memory.
fn hash_file(hasher: &mut Sha256, path: &Path) -> Result<(), anyhow::Error> {
    let mut file = fs::File::open(path)?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(())
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), anyhow::Error> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if SKIP_DIRS.contains(&name_str.as_ref()) {
            continue;
        }
        if SKIP_FILES.contains(&name_str.as_ref()) || name_str.ends_with(SARIF_EXTENSION) {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)?
            .to_string_lossy()
            .into_owned();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect(root, &entry.path(), out)?;
        } else if ft.is_file() {
            out.push(rel);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_outputs_do_not_affect_tree_digest() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        fs::write(tmp.path().join("Cargo.toml"), "[package]\n").unwrap();

        let before = tree_sha256(tmp.path()).unwrap();

        // Signing / SARIF / keygen outputs land in the tree but must not
        // change the source fingerprint (or `record -> sign -> verify` would
        // spuriously fail).
        fs::write(tmp.path().join(crate::sign::ATTESTATION_FILENAME), "{}").unwrap();
        fs::write(tmp.path().join("sorseal.sarif"), "{}").unwrap();
        fs::write(tmp.path().join("custom.sarif"), "{}").unwrap();
        fs::write(tmp.path().join("sorseal.key"), "k").unwrap();
        fs::write(tmp.path().join("sorseal.pub"), "p").unwrap();

        let after = tree_sha256(tmp.path()).unwrap();
        assert_eq!(before, after);

        // ...but a genuine source change still moves the digest.
        fs::write(tmp.path().join("src/lib.rs"), "pub fn g() {}\n").unwrap();
        assert_ne!(before, tree_sha256(tmp.path()).unwrap());
    }
}
