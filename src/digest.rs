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

/// SHA-256 of a directory tree, keyed on relative path + file bytes.
///
/// Traversal is depth-first and paths are sorted before hashing, so the digest
/// depends only on content, never on filesystem iteration order. The
/// provenance file itself is always excluded so a record never depends on the
/// previous record.
pub fn tree_sha256(root: &Path) -> Result<String, anyhow::Error> {
    let mut files: Vec<String> = Vec::new();
    collect(root, root, &mut files)?;
    files.sort();

    let mut hasher = Sha256::new();
    for rel in &files {
        let data = fs::read(root.join(rel))?;
        hasher.update(rel.as_bytes());
        hasher.update(b"\n");
        hasher.update(&data);
        hasher.update(b"\n");
    }
    Ok(hex(&hasher.finalize()))
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), anyhow::Error> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if SKIP_DIRS.contains(&name_str.as_ref()) {
            continue;
        }
        if name_str == crate::provenance::PROVENANCE_FILENAME {
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
