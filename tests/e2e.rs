//! End-to-end tests: drive the real `sorseal` binary against a copy of the
//! `echo` fixture, exercising record -> verify as a user would.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sorseal")
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/echo")
}

fn copy_fixture(dst: &Path) {
    copy_dir(&fixture(), dst);
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        let path = entry.path();
        let target = dst.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap();
        }
    }
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run sorseal")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn provenance(dir: &Path) -> serde_json::Value {
    let path = dir.join("sorseal.provenance.json");
    let text = fs::read_to_string(&path).expect("provenance file should exist");
    serde_json::from_str(&text).expect("provenance should be valid JSON")
}

#[test]
fn record_then_verify_is_reproducible() {
    let tmp = tempfile::tempdir().unwrap();
    copy_fixture(tmp.path());

    let rec = run(tmp.path(), &["record"]);
    assert!(rec.status.success(), "record failed:\n{}", stdout(&rec));

    let prov = provenance(tmp.path());
    assert_eq!(prov["format"], "sorseal-provenance");
    assert_eq!(prov["version"], 1);
    assert_eq!(prov["project"], "echo");
    let art = &prov["artifacts"][0];
    assert_eq!(art["id"], "echo");
    assert_eq!(art["wasm_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(art["source_sha256"].as_str().unwrap().len(), 64);
    assert!(art["wasm_size"].as_u64().unwrap() > 0);

    // wipe the build output to prove verify genuinely rebuilds from source
    fs::remove_dir_all(tmp.path().join("target")).unwrap();

    let ver = run(tmp.path(), &["verify"]);
    assert!(
        ver.status.success(),
        "verify failed after clean rebuild:\n{}",
        stdout(&ver)
    );
    assert!(stdout(&ver).contains("PASSED"));
}

#[test]
fn verify_detects_source_drift() {
    let tmp = tempfile::tempdir().unwrap();
    copy_fixture(tmp.path());
    assert!(run(tmp.path(), &["record"]).status.success());

    // append a byte to the contract source
    let src = tmp.path().join("src/lib.rs");
    let mut text = fs::read_to_string(&src).unwrap();
    text.push_str("\n// drift\n");
    fs::write(&src, text).unwrap();

    let ver = run(tmp.path(), &["verify"]);
    assert_eq!(ver.status.code(), Some(1));
    let out = stdout(&ver);
    assert!(out.contains("FAILED"));
    assert!(out.contains("wasm") || out.contains("source"));
}

#[test]
fn verify_detects_corrupted_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    copy_fixture(tmp.path());
    assert!(run(tmp.path(), &["record"]).status.success());

    let prov_path = tmp.path().join("sorseal.provenance.json");
    let mut prov = provenance(tmp.path());
    prov["artifacts"][0]["wasm_sha256"] = "0".repeat(64).into();
    fs::write(&prov_path, prov.to_string()).unwrap();

    let ver = run(tmp.path(), &["verify"]);
    assert_eq!(ver.status.code(), Some(1));
    assert!(stdout(&ver).contains("FAILED"));
}

#[test]
fn init_writes_valid_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let rec = run(tmp.path(), &["init", "--project", "demo"]);
    assert!(rec.status.success(), "init failed:\n{}", stdout(&rec));
    let text = fs::read_to_string(tmp.path().join("sorseal.toml")).unwrap();
    assert!(text.contains("demo"));
    let _: toml::Value = text.parse().unwrap();
}

#[test]
fn init_discovers_cdylib_crate_in_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    // member crate = copy of the echo fixture (a cdylib)
    let member = tmp.path().join("contracts/echo");
    fs::create_dir_all(&member).unwrap();
    copy_dir(&fixture().join("src"), &member.join("src"));
    fs::copy(fixture().join("Cargo.toml"), member.join("Cargo.toml")).unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"contracts/echo\"]\n",
    )
    .unwrap();

    let rec = run(tmp.path(), &["init"]);
    assert!(rec.status.success(), "init failed:\n{}", stdout(&rec));
    let text = fs::read_to_string(tmp.path().join("sorseal.toml")).unwrap();
    assert!(text.contains("echo"));
    assert!(text.contains("wasm32-unknown-unknown"));
}
