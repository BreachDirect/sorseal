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
    // The fixture build inside the test must write to the tempdir's own
    // target/ — never an inherited CARGO_TARGET_DIR from the host.
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR")
        .output()
        .expect("failed to run sorseal")
}

fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run git")
}

fn git_out(dir: &Path, args: &[&str]) -> String {
    let out = git(dir, args);
    assert!(out.status.success(), "git {args:?} failed");
    String::from_utf8_lossy(&out.stdout).to_string()
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
fn keygen_sign_and_verify_attestation_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    copy_fixture(tmp.path());
    assert!(run(tmp.path(), &["record"]).status.success());

    // generate a keypair
    let kg = run(tmp.path(), &["keygen", "--key", "test.key"]);
    assert!(kg.status.success(), "keygen failed:\n{}", stdout(&kg));
    assert!(tmp.path().join("test.key").exists());
    assert!(tmp.path().join("test.pub").exists());

    // sign the provenance into a DSSE attestation
    let sg = run(tmp.path(), &["sign", "--key", "test.key"]);
    assert!(sg.status.success(), "sign failed:\n{}", stdout(&sg));
    assert!(tmp.path().join("sorseal.attestation.json").exists());

    // verify the attestation against the public key and provenance
    let va = run(
        tmp.path(),
        &["verify-attestation", "--public-key", "test.pub"],
    );
    assert!(
        va.status.success(),
        "verify-attestation failed:\n{}",
        stdout(&va)
    );
    assert!(stdout(&va).contains("signature verified"));

    // tampering with the provenance must fail subject cross-check
    let mut prov = provenance(tmp.path());
    prov["artifacts"][0]["wasm_sha256"] = "0".repeat(64).into();
    let prov_path = tmp.path().join("sorseal.provenance.json");
    fs::write(&prov_path, prov.to_string()).unwrap();
    let va2 = run(
        tmp.path(),
        &["verify-attestation", "--public-key", "test.pub"],
    );
    assert_eq!(va2.status.code(), Some(1));
    assert!(stdout(&va2).contains("do NOT match"));
}

#[test]
fn sign_then_verify_still_reproduces() {
    // The documented flow: record -> keygen -> sign -> verify. The attestation
    // and keys live in the tree but are generated outputs — they must not
    // change the source fingerprint, or verify would spuriously fail.
    let tmp = tempfile::tempdir().unwrap();
    copy_fixture(tmp.path());
    assert!(run(tmp.path(), &["record"]).status.success());
    assert!(run(tmp.path(), &["keygen"]).status.success());
    assert!(run(tmp.path(), &["sign", "--key", "sorseal.key"])
        .status
        .success());
    assert!(tmp.path().join("sorseal.attestation.json").exists());

    fs::remove_dir_all(tmp.path().join("target")).unwrap();
    let ver = run(tmp.path(), &["verify"]);
    assert!(
        ver.status.success(),
        "verify after sign must still pass:\n{}",
        stdout(&ver)
    );
}

#[test]
fn verify_detects_changed_build_command() {
    let tmp = tempfile::tempdir().unwrap();
    copy_fixture(tmp.path());
    assert!(run(tmp.path(), &["record"]).status.success());

    // Change the build command while keeping the produced wasm identical: the
    // sealed record no longer describes how the artifact is built.
    let man_path = tmp.path().join("sorseal.toml");
    let man = fs::read_to_string(&man_path).unwrap();
    fs::write(
        &man_path,
        man.replace(
            "build_command = \"cargo build --release --target wasm32-unknown-unknown\"",
            "build_command = \"cargo build --release --target wasm32-unknown-unknown && true\"",
        ),
    )
    .unwrap();

    let ver = run(tmp.path(), &["verify"]);
    assert_eq!(ver.status.code(), Some(1));
    let out = stdout(&ver);
    assert!(
        out.contains("command") && out.contains("FAILED"),
        "expected a failed command-consistency check, got:\n{out}"
    );
}

#[test]
fn verify_emits_valid_sarif() {
    let tmp = tempfile::tempdir().unwrap();
    copy_fixture(tmp.path());
    assert!(run(tmp.path(), &["record"]).status.success());

    // corrupt the provenance so verify produces a finding
    let mut prov = provenance(tmp.path());
    prov["artifacts"][0]["wasm_sha256"] = "0".repeat(64).into();
    fs::write(tmp.path().join("sorseal.provenance.json"), prov.to_string()).unwrap();

    let ver = run(tmp.path(), &["verify", "--sarif", "out.sarif"]);
    assert_eq!(ver.status.code(), Some(1));
    let sarif_path = tmp.path().join("out.sarif");
    assert!(sarif_path.exists());
    let text = fs::read_to_string(&sarif_path).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(
        !results.is_empty(),
        "expected findings in SARIF for corrupted provenance"
    );
    assert_eq!(results[0]["level"], "error");
}

#[test]
fn init_writes_valid_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let rec = run(tmp.path(), &["init", "--project", "demo"]);
    assert!(rec.status.success(), "init failed:\n{}", stdout(&rec));
    let text = fs::read_to_string(tmp.path().join("sorseal.toml")).unwrap();
    assert!(text.contains("demo"));
    let parsed: toml::Table = text.parse().expect("init output must be valid TOML");
    assert_eq!(parsed["project"]["name"].as_str(), Some("demo"));
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

#[test]
fn init_discovers_cdylib_with_glob_members() {
    let tmp = tempfile::tempdir().unwrap();
    let member = tmp.path().join("contracts/echo");
    fs::create_dir_all(&member).unwrap();
    copy_dir(&fixture().join("src"), &member.join("src"));
    fs::copy(fixture().join("Cargo.toml"), member.join("Cargo.toml")).unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"contracts/*\"]\n",
    )
    .unwrap();

    let rec = run(tmp.path(), &["init"]);
    assert!(rec.status.success(), "init failed:\n{}", stdout(&rec));
    let text = fs::read_to_string(tmp.path().join("sorseal.toml")).unwrap();
    assert!(text.contains("echo"));
}

#[test]
fn git_flow_record_verify_and_dirty_refusal() {
    let tmp = tempfile::tempdir().unwrap();
    copy_fixture(tmp.path());
    fs::write(tmp.path().join(".gitignore"), "target/\n").unwrap();

    git(tmp.path(), &["init", "-q"]);
    git(tmp.path(), &["config", "user.email", "test@example.com"]);
    git(tmp.path(), &["config", "user.name", "Sorseal Test"]);
    git(tmp.path(), &["add", "."]);
    git(tmp.path(), &["commit", "-q", "-m", "initial"]);
    let sealed_commit = git_out(tmp.path(), &["rev-parse", "HEAD"])
        .trim()
        .to_string();

    // A dirty working tree must be refused without --allow-dirty.
    let mut src = fs::read_to_string(tmp.path().join("src/lib.rs")).unwrap();
    src.push_str("\n// uncommitted\n");
    fs::write(tmp.path().join("src/lib.rs"), src).unwrap();
    let rec = run(tmp.path(), &["record"]);
    assert_eq!(rec.status.code(), Some(2), "dirty record must be refused");
    git(tmp.path(), &["checkout", "--", "src/lib.rs"]);

    // Clean record seals the current commit with clean:true.
    let rec = run(tmp.path(), &["record"]);
    assert!(rec.status.success(), "record failed:\n{}", stdout(&rec));
    let prov = provenance(tmp.path());
    assert_eq!(prov["git"]["present"], true);
    assert_eq!(prov["git"]["clean"], true);
    assert_eq!(prov["git"]["commit"].as_str().unwrap(), sealed_commit);

    // Commit the seal: HEAD moves past the sealed commit.
    git(tmp.path(), &["add", "."]);
    git(tmp.path(), &["commit", "-q", "-m", "seal provenance"]);

    // Wipe the build output and verify: the sealed commit is reachable from HEAD.
    fs::remove_dir_all(tmp.path().join("target")).unwrap();
    let ver = run(tmp.path(), &["verify"]);
    assert!(
        ver.status.success(),
        "verify failed after git seal commit:\n{}",
        stdout(&ver)
    );
    assert!(stdout(&ver).contains("reachable"));
}
