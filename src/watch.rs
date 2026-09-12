//! File integrity monitoring — detect unauthorized changes to critical files.
//!
//! Reads a `sorseal.watch.toml` config, hashes each listed file, stores
//! baselines in `sorseal.watchstate.json`, and on each check compares
//! current hashes against baselines. Drift triggers alerts via stdout and
//! optional webhooks (Discord, Telegram, generic POST).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub const WATCH_CONFIG_FILENAME: &str = "sorseal.watch.toml";
pub const WATCH_STATE_FILENAME: &str = "sorseal.watchstate.json";

/// Upper bound on a single webhook delivery attempt. A silent or stalled
/// endpoint is skipped rather than wedging the watch loop indefinitely.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(15);

fn webhook_agent() -> &'static ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .timeout_global(Some(WEBHOOK_TIMEOUT))
            .build()
            .new_agent()
    })
}

// ── Config types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    pub watch: WatchSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchSettings {
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default)]
    pub paths: Vec<WatchPath>,
    #[serde(default)]
    pub webhooks: Vec<Webhook>,
}

fn default_interval() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchPath {
    pub path: PathBuf,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Webhook {
    #[serde(rename = "discord")]
    Discord { url: String },
    #[serde(rename = "telegram")]
    Telegram { token: String, chat_id: String },
    #[serde(rename = "post")]
    Post { url: String },
}

// ── State types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WatchState {
    pub baselines: HashMap<String, FileBaseline>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBaseline {
    pub label: String,
    pub sha256: String,
    pub size: u64,
}

// ── Check result types ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    Unchanged,
    New,
    Missing,
    Drift,
}

#[derive(Debug, Clone)]
pub struct FileCheck {
    pub path: PathBuf,
    pub label: String,
    pub status: FileStatus,
    pub baseline_hash: Option<String>,
    pub current_hash: Option<String>,
}

impl FileCheck {
    pub fn passed(&self) -> bool {
        self.status == FileStatus::Unchanged || self.status == FileStatus::New
    }
}

// ── Core functions ──────────────────────────────────────────────────────

/// Hash a file's raw bytes, returning (hex_hash, size).
pub fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((hex, size))
}

/// Load or create the watch state file.
pub fn load_state(path: &Path) -> WatchState {
    if path.exists() {
        fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    } else {
        WatchState::default()
    }
}

/// Save the watch state to disk.
pub fn save_state(state: &WatchState, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json)?;
    Ok(())
}

/// Perform a single check of all watched paths against baselines.
/// Returns the list of file checks and whether baselines were updated (new files).
pub fn check_once(config: &WatchConfig, state: &mut WatchState) -> Result<Vec<FileCheck>> {
    let mut results = Vec::new();

    for wp in &config.watch.paths {
        let path = &wp.path;
        let label = if wp.label.is_empty() {
            path.display().to_string()
        } else {
            wp.label.clone()
        };

        if !path.exists() {
            results.push(FileCheck {
                path: path.clone(),
                label,
                status: FileStatus::Missing,
                baseline_hash: None,
                current_hash: None,
            });
            continue;
        }

        let (current_hash, _size) = hash_file(path)?;
        let key = path.display().to_string();

        match state.baselines.get(&key) {
            Some(baseline) => {
                if baseline.sha256 == current_hash {
                    results.push(FileCheck {
                        path: path.clone(),
                        label,
                        status: FileStatus::Unchanged,
                        baseline_hash: Some(baseline.sha256.clone()),
                        current_hash: Some(current_hash),
                    });
                } else {
                    results.push(FileCheck {
                        path: path.clone(),
                        label,
                        status: FileStatus::Drift,
                        baseline_hash: Some(baseline.sha256.clone()),
                        current_hash: Some(current_hash),
                    });
                }
            }
            None => {
                // New file — record baseline
                state.baselines.insert(
                    key,
                    FileBaseline {
                        label: label.clone(),
                        sha256: current_hash.clone(),
                        size: _size,
                    },
                );
                results.push(FileCheck {
                    path: path.clone(),
                    label,
                    status: FileStatus::New,
                    baseline_hash: None,
                    current_hash: Some(current_hash),
                });
            }
        }
    }

    Ok(results)
}

/// Render check results to console output.
pub fn render_checks(checks: &[FileCheck]) -> String {
    let mut lines = vec![
        String::from("Sorseal — file integrity watch"),
        String::new(),
    ];
    for c in checks {
        let (icon, detail) = match c.status {
            FileStatus::Unchanged => ("PASSED", "unchanged".to_string()),
            FileStatus::New => ("PASSED", "new — baseline recorded".to_string()),
            FileStatus::Missing => ("FAILED", "file missing".to_string()),
            FileStatus::Drift => {
                let base = c.baseline_hash.as_deref().unwrap_or("?");
                let curr = c.current_hash.as_deref().unwrap_or("?");
                let short_base = &base[..12.min(base.len())];
                let short_curr = &curr[..12.min(curr.len())];
                (
                    "FAILED",
                    format!("sha256 mismatch: baseline {short_base}, current {short_curr}"),
                )
            }
        };
        lines.push(format!("{icon}  {} — {}", c.label, detail));
    }
    lines.push(String::new());
    let passed = checks.iter().filter(|c| c.passed()).count();
    let failed = checks.len() - passed;
    lines.push(format!(
        "{} files checked: {passed} passed, {failed} failed",
        checks.len()
    ));
    lines.join("\n")
}

/// Render check results as SARIF 2.1.0.
pub fn render_sarif(checks: &[FileCheck]) -> String {
    use serde_json::{json, Value};

    let results: Vec<Value> = checks
        .iter()
        .filter(|c| !c.passed())
        .map(|c| {
            let level = match c.status {
                FileStatus::Missing => "error",
                FileStatus::Drift => "error",
                _ => "none",
            };
            json!({
                "ruleId": "SORSEAL/watch",
                "level": level,
                "message": {
                    "text": format!("{} — {:?}", c.label, c.status)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": c.path.display().to_string() },
                        "region": { "startLine": 1 }
                    }
                }],
                "properties": {
                    "label": c.label,
                    "status": format!("{:?}", c.status),
                    "baseline_sha256": c.baseline_hash,
                    "current_sha256": c.current_hash
                }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sorseal",
                    "fullName": "sorseal — file integrity monitor",
                    "informationUri": "https://github.com/BreachDirect/sorseal",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": [{
                        "id": "SORSEAL/watch",
                        "name": "file-integrity",
                        "shortDescription": { "text": "Detects unauthorized file changes" },
                        "helpUri": "https://github.com/BreachDirect/sorseal#file-integrity-monitoring",
                        "properties": { "tags": ["security", "file-integrity"] }
                    }]
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).expect("SARIF is serializable")
}

/// Send alerts to configured webhooks for failed checks.
pub fn send_alerts(config: &WatchConfig, failed: &[FileCheck]) -> Result<()> {
    if failed.is_empty() {
        return Ok(());
    }

    let mut lines = vec![String::from("**sorseal watch — drift detected**")];
    for c in failed {
        lines.push(format!("- `{}` — {:?}", c.path.display(), c.status));
    }
    let text = lines.join("\n");

    for wh in &config.watch.webhooks {
        match wh {
            Webhook::Discord { url } => {
                let body = serde_json::json!({ "content": &text });
                if let Err(e) = webhook_agent().post(url).send_json(&body) {
                    eprintln!("webhook discord failed: {e}");
                }
            }
            Webhook::Telegram { token, chat_id } => {
                let url = format!("https://api.telegram.org/bot{token}/sendMessage");
                let body = serde_json::json!({
                    "chat_id": chat_id,
                    "text": &text,
                    "parse_mode": "Markdown"
                });
                if let Err(e) = webhook_agent().post(&url).send_json(&body) {
                    eprintln!("webhook telegram failed: {e}");
                }
            }
            Webhook::Post { url } => {
                let body = serde_json::json!({
                    "event": "drift",
                    "files": failed.iter().map(|c| {
                        serde_json::json!({
                            "path": c.path.display().to_string(),
                            "label": c.label,
                            "status": format!("{:?}", c.status),
                            "baseline": c.baseline_hash,
                            "current": c.current_hash
                        })
                    }).collect::<Vec<_>>()
                });
                if let Err(e) = webhook_agent().post(url).send_json(&body) {
                    eprintln!("webhook post failed: {e}");
                }
            }
        }
    }

    Ok(())
}

/// Generate a starter watch config at the given path.
pub fn generate_config(path: &Path) -> Result<()> {
    let config = WatchConfig {
        watch: WatchSettings {
            interval_secs: 300,
            paths: vec![
                WatchPath {
                    path: PathBuf::from("/etc/passwd"),
                    label: "passwd".into(),
                },
                WatchPath {
                    path: PathBuf::from("/etc/shadow"),
                    label: "shadow".into(),
                },
            ],
            webhooks: vec![],
        },
    };
    let toml = toml::to_string_pretty(&config)?;
    fs::write(path, toml)?;
    Ok(())
}

/// Run the watch loop: check periodically until interrupted.
pub fn run_loop(config: &WatchConfig, state_path: &Path) -> Result<()> {
    let mut state = load_state(state_path);
    let interval = Duration::from_secs(config.watch.interval_secs);

    println!(
        "sorseal watch: monitoring {} file(s) every {}s",
        config.watch.paths.len(),
        config.watch.interval_secs
    );

    loop {
        let checks = check_once(config, &mut state)?;
        let failed: Vec<_> = checks.iter().filter(|c| !c.passed()).cloned().collect();

        println!("{}", render_checks(&checks));

        if !failed.is_empty() {
            let _ = send_alerts(config, &failed);
        }

        save_state(&state, state_path)?;
        thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_config(dir: &Path, files: &[&str]) -> WatchConfig {
        let mut paths = Vec::new();
        for f in files {
            let p = dir.join(f);
            fs::write(&p, format!("content of {f}\n")).unwrap();
            paths.push(WatchPath {
                path: p,
                label: f.to_string(),
            });
        }
        WatchConfig {
            watch: WatchSettings {
                interval_secs: 60,
                paths,
                webhooks: vec![],
            },
        }
    }

    #[test]
    fn hash_file_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("test.txt");
        fs::write(&p, "hello world\n").unwrap();

        let (h1, s1) = hash_file(&p).unwrap();
        let (h2, s2) = hash_file(&p).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(s1, s2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn new_file_records_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp_config(tmp.path(), &["a.txt"]);
        let mut state = WatchState::default();

        let checks = check_once(&config, &mut state).unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, FileStatus::New);
        assert!(checks[0].passed());
        assert!(!state.baselines.is_empty());
    }

    #[test]
    fn unchanged_file_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp_config(tmp.path(), &["a.txt"]);
        let mut state = WatchState::default();

        // first run: baseline
        check_once(&config, &mut state).unwrap();

        // second run: unchanged
        let checks = check_once(&config, &mut state).unwrap();
        assert_eq!(checks[0].status, FileStatus::Unchanged);
        assert!(checks[0].passed());
    }

    #[test]
    fn drift_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp_config(tmp.path(), &["a.txt"]);
        let mut state = WatchState::default();

        check_once(&config, &mut state).unwrap();

        // tamper
        let p = tmp.path().join("a.txt");
        fs::write(&p, "TAMPERED\n").unwrap();

        let checks = check_once(&config, &mut state).unwrap();
        assert_eq!(checks[0].status, FileStatus::Drift);
        assert!(!checks[0].passed());
        assert!(checks[0].baseline_hash.is_some());
        assert!(checks[0].current_hash.is_some());
    }

    #[test]
    fn missing_file_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("ghost.txt");
        let config = WatchConfig {
            watch: WatchSettings {
                interval_secs: 60,
                paths: vec![WatchPath {
                    path: p,
                    label: "ghost".into(),
                }],
                webhooks: vec![],
            },
        };
        let mut state = WatchState::default();

        let checks = check_once(&config, &mut state).unwrap();
        assert_eq!(checks[0].status, FileStatus::Missing);
        assert!(!checks[0].passed());
    }

    #[test]
    fn state_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp_config(tmp.path(), &["a.txt"]);
        let state_path = tmp.path().join(WATCH_STATE_FILENAME);
        let mut state = WatchState::default();

        check_once(&config, &mut state).unwrap();
        save_state(&state, &state_path).unwrap();

        let loaded = load_state(&state_path);
        assert_eq!(loaded.baselines.len(), 1);
    }

    #[test]
    fn render_checks_output() {
        let checks = vec![
            FileCheck {
                path: PathBuf::from("/etc/passwd"),
                label: "passwd".into(),
                status: FileStatus::Unchanged,
                baseline_hash: Some("abc123".repeat(10).chars().take(64).collect()),
                current_hash: Some("abc123".repeat(10).chars().take(64).collect()),
            },
            FileCheck {
                path: PathBuf::from("/usr/bin/sshd"),
                label: "sshd".into(),
                status: FileStatus::Drift,
                baseline_hash: Some("aaa".repeat(21).chars().take(64).collect()),
                current_hash: Some("bbb".repeat(21).chars().take(64).collect()),
            },
        ];
        let out = render_checks(&checks);
        assert!(out.contains("PASSED"));
        assert!(out.contains("FAILED"));
        assert!(out.contains("2 files checked: 1 passed, 1 failed"));
    }

    #[test]
    fn sarif_omits_passes() {
        let checks = vec![
            FileCheck {
                path: PathBuf::from("/etc/passwd"),
                label: "passwd".into(),
                status: FileStatus::Unchanged,
                baseline_hash: Some("a".repeat(64)),
                current_hash: Some("a".repeat(64)),
            },
            FileCheck {
                path: PathBuf::from("/usr/bin/sshd"),
                label: "sshd".into(),
                status: FileStatus::Drift,
                baseline_hash: Some("a".repeat(64)),
                current_hash: Some("b".repeat(64)),
            },
        ];
        let sarif_str = render_sarif(&checks);
        let sarif: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "SORSEAL/watch");
    }

    #[test]
    fn generate_config_writes_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(WATCH_CONFIG_FILENAME);
        generate_config(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("interval_secs"));
        assert!(text.contains("/etc/passwd"));
    }
}
