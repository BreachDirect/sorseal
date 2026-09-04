//! sorseal CLI — `sorseal init|record|verify|report`.

#![forbid(unsafe_code)]

use anyhow::bail;
use clap::{Parser, Subcommand, ValueEnum};
use sorseal::analyze;
use sorseal::manifest::Manifest;
use sorseal::provenance::{Provenance, PROVENANCE_FILENAME};
use sorseal::sign::ATTESTATION_FILENAME;
use sorseal::{onchain, report, runner, scaffold, sign, watch};
use std::fs;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "sorseal",
    version,
    about = "Provenance for Soroban/WASM artifacts — prove deployed bytecode matches source.",
    long_about = "sorseal seals the build: it records a manifest of SHA-256 digests for your \
                  contract artifacts (WASM + source tree + toolchain + git commit), then \
                  verifies at any time that a clean rebuild reproduces those exact digests."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scaffold a sorseal.toml manifest
    Init {
        /// Project name (defaults to the crate/package name)
        #[arg(long)]
        project: Option<String>,
        /// Overwrite an existing sorseal.toml
        #[arg(long)]
        force: bool,
    },
    /// Build artifacts and write sorseal.provenance.json
    Record {
        /// Allow recording from a dirty working tree
        #[arg(long)]
        allow_dirty: bool,
        /// Manifest file
        #[arg(long, default_value = sorseal::manifest::MANIFEST_FILENAME)]
        manifest: String,
    },
    /// Rebuild artifacts and verify them against the sealed provenance
    Verify {
        /// Manifest file
        #[arg(long, default_value = sorseal::manifest::MANIFEST_FILENAME)]
        manifest: String,
        /// Provenance file
        #[arg(long, default_value = PROVENANCE_FILENAME)]
        provenance: String,
        /// Write the results as a SARIF 2.1.0 report to this path
        #[arg(long)]
        sarif: Option<String>,
    },
    /// Render the sealed provenance as a report
    Report {
        /// Provenance file
        #[arg(long, default_value = PROVENANCE_FILENAME)]
        provenance: String,
        /// Output format
        #[arg(long, value_enum, default_value = "console")]
        format: ReportFormat,
    },
    /// Generate an Ed25519 keypair for signing attestations
    Keygen {
        /// Path to write the private key
        #[arg(long, default_value = sorseal::sign::PRIVATE_KEY_EXT)]
        key: String,
        /// Path to write the public key
        #[arg(long)]
        public_key: Option<String>,
    },
    /// Sign the sealed provenance as an in-toto/SLSA v1.0 attestation (DSSE)
    Sign {
        /// Path to the Ed25519 private key
        #[arg(long)]
        key: String,
        /// Provenance file
        #[arg(long, default_value = PROVENANCE_FILENAME)]
        provenance: String,
        /// Path to write the signed attestation
        #[arg(long, default_value = ATTESTATION_FILENAME)]
        output: String,
    },
    /// Verify the signed attestation against the public key and provenance
    VerifyAttestation {
        /// Path to the Ed25519 public key
        #[arg(long)]
        public_key: String,
        /// Signed attestation file
        #[arg(long, default_value = ATTESTATION_FILENAME)]
        attestation: String,
        /// Provenance file to cross-check subjects against (defaults to
        /// sorseal.provenance.json; the check is skipped when it is absent)
        #[arg(long, default_value = PROVENANCE_FILENAME)]
        provenance: String,
    },
    /// Compare the deployed contract wasm hash on-chain against the sealed provenance
    OnchainVerify {
        /// Contract id (C... strkey or 64-char hex)
        #[arg(long)]
        contract_id: String,
        /// Soroban RPC endpoint (defaults to the Stellar mainnet RPC)
        #[arg(long)]
        rpc: Option<String>,
        /// Which artifact id to check (defaults to the first artifact)
        #[arg(long)]
        artifact: Option<String>,
        /// Provenance file
        #[arg(long, default_value = PROVENANCE_FILENAME)]
        provenance: String,
    },
    /// Fund-free, offline simulation of the on-chain verify + audit story
    ///
    /// Drives the same on-chain code paths (getLedgerEntries decode, getEvents
    /// paging, upgrade-lineage reconstruction, provenance cross-checking)
    /// against an in-memory ledger derived from your provenance, so the full
    /// seal -> deploy -> upgrade -> verify -> audit workflow is reproducible
    /// with zero funds and no network.
    SimulateOnchain {
        /// Contract id (C... strkey or 64-char hex) used as the simulated ledger
        #[arg(
            long,
            default_value = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        )]
        contract_id: String,
        /// How many upgrades the simulated contract has performed (defaults to
        /// every artifact past the first)
        #[arg(long)]
        upgrades: Option<usize>,
        /// Override the currently-deployed wasm hash (64-char hex) to simulate
        /// an unsealed/drifted deployment (audit will report FAILED)
        #[arg(long)]
        deploy_wasm: Option<String>,
        /// Provenance file
        #[arg(long, default_value = PROVENANCE_FILENAME)]
        provenance: String,
    },
    /// Statically analyze a sealed artifact's Rust source for Soroban vuln patterns
    Analyze {
        /// Artifact id to analyze (defaults to all)
        #[arg(long)]
        artifact: Option<String>,
        /// Manifest file
        #[arg(long, default_value = sorseal::manifest::MANIFEST_FILENAME)]
        manifest: String,
        /// Provenance file (used with --seal)
        #[arg(long, default_value = PROVENANCE_FILENAME)]
        provenance: String,
        /// Output format
        #[arg(long, value_enum, default_value = "console")]
        format: AnalyzeFormat,
        /// Also write the findings as a SARIF 2.1.0 report to this path
        #[arg(long)]
        sarif: Option<String>,
        /// Seal the analysis finding-digest into the provenance file
        #[arg(long)]
        seal: bool,
        /// Path suffixes to ignore when walking source (repeatable)
        #[arg(long)]
        ignore: Vec<String>,
    },
    /// Monitor files for integrity drift and alert on changes
    Watch {
        /// Run a single check and exit (for cron)
        #[arg(long)]
        once: bool,
        /// Generate a starter sorseal.watch.toml config
        #[arg(long)]
        init: bool,
        /// Config file
        #[arg(long, default_value = watch::WATCH_CONFIG_FILENAME)]
        config: String,
        /// State file
        #[arg(long, default_value = watch::WATCH_STATE_FILENAME)]
        state: String,
        /// Write results as SARIF to this path
        #[arg(long)]
        sarif: Option<String>,
    },
    /// Audit a contract's full on-chain upgrade history against sealed provenance
    OnchainAudit {
        /// Contract id (C... strkey or 64-char hex)
        #[arg(long)]
        contract_id: String,
        /// Soroban RPC endpoint (defaults to the Stellar mainnet RPC)
        #[arg(long)]
        rpc: Option<String>,
        /// First ledger to scan for upgrades (defaults to the RPC retention oldest)
        #[arg(long)]
        start_ledger: Option<u32>,
        /// Last ledger to scan for upgrades (defaults to the RPC latest)
        #[arg(long)]
        end_ledger: Option<u32>,
        /// Provenance file to cross-check versions against (defaults to
        /// sorseal.provenance.json in the current directory when present)
        #[arg(long)]
        provenance: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ReportFormat {
    Console,
    Json,
    Markdown,
}

#[derive(Clone, Copy, ValueEnum)]
enum AnalyzeFormat {
    Console,
    Markdown,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("sorseal: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Combine exit-code priorities: 2 (config/analysis error) beats 1 (findings)
/// beats 0 (clean).
fn max_code(a: u8, b: u8) -> u8 {
    a.max(b)
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    match cli.command {
        Command::Init { project, force } => {
            let cwd = std::env::current_dir()?;
            let manifest = scaffold::scaffold_manifest(&cwd, project, force)?;
            let toml_text = toml::to_string(&manifest)?;
            std::fs::write(cwd.join(sorseal::manifest::MANIFEST_FILENAME), toml_text)?;
            let n = manifest.artifacts.len();
            println!(
                "Wrote {} with {n} artifact(s).",
                sorseal::manifest::MANIFEST_FILENAME
            );
            if manifest.is_placeholder() {
                println!(
                    "No cdylib contract crates were discovered — edit the generated entry \
                     to point at your contract."
                );
            }
            Ok(0)
        }

        Command::Record {
            allow_dirty,
            manifest,
        } => {
            let cwd = std::env::current_dir()?;
            let m = Manifest::load(&cwd.join(&manifest))?;
            let p = runner::record(&m, &cwd, allow_dirty)?;
            p.save(&cwd.join(PROVENANCE_FILENAME))?;
            println!("{}", report::render_sealed(&m.project.name, &p));
            println!();
            println!("provenance written to {PROVENANCE_FILENAME}");
            Ok(0)
        }

        Command::Verify {
            manifest,
            provenance,
            sarif,
        } => {
            let cwd = std::env::current_dir()?;
            let m = Manifest::load(&cwd.join(&manifest))?;
            let p = Provenance::load(&cwd.join(&provenance))?;
            let (checks, all_pass) = runner::verify(&m, &p, &cwd)?;
            println!("{}", report::render_verify(&m.project.name, &checks));
            if let Some(path) = sarif {
                std::fs::write(
                    cwd.join(&path),
                    sorseal::sarif::render_sarif(&m.project.name, &checks),
                )
                .map_err(|e| anyhow::anyhow!("failed to write SARIF to {path}: {e}"))?;
                println!();
                println!("SARIF report written to {path}");
            }
            Ok(if all_pass { 0 } else { 1 })
        }

        Command::Report { provenance, format } => {
            let cwd = std::env::current_dir()?;
            let p = Provenance::load(&cwd.join(&provenance))?;
            match format {
                ReportFormat::Console => {
                    println!("{}", report::render_sealed(&p.project, &p));
                }
                ReportFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&p)?);
                }
                ReportFormat::Markdown => {
                    print!("{}", report::render_markdown(&p));
                }
            }
            Ok(0)
        }

        Command::Keygen { key, public_key } => {
            let cwd = std::env::current_dir()?;
            let key_path = cwd.join(&key);
            let pub_hex = sign::keygen(&key_path)?;
            let pub_path = match &public_key {
                Some(p) => cwd.join(p),
                None => {
                    let mut p = key_path.clone();
                    p.set_extension("pub");
                    p
                }
            };
            std::fs::write(&pub_path, format!("{pub_hex}\n"))?;
            println!("private key written to {}", key_path.display());
            println!("public  key written to {}", pub_path.display());
            Ok(0)
        }

        Command::Sign {
            key,
            provenance,
            output,
        } => {
            let cwd = std::env::current_dir()?;
            let signing_key = sign::load_signing_key(&cwd.join(&key))?;
            let p = Provenance::load(&cwd.join(&provenance))?;
            sign::attest(&signing_key, &p, &cwd.join(&output))?;
            println!("signed attestation written to {output}");
            Ok(0)
        }

        Command::VerifyAttestation {
            public_key,
            attestation,
            provenance,
        } => {
            let cwd = std::env::current_dir()?;
            let verifying_key = sign::load_verifying_key(&cwd.join(&public_key))?;
            let raw = std::fs::read_to_string(cwd.join(&attestation))?;
            let envelope: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("invalid attestation JSON: {e}"))?;
            let payload = sign::verify_dsse(&envelope, &verifying_key)?;
            let statement: serde_json::Value = serde_json::from_slice(&payload)
                .map_err(|e| anyhow::anyhow!("attestation payload is not valid JSON: {e}"))?;

            let mut ok = true;
            println!("signature verified against {}", public_key);
            let prov_path = cwd.join(&provenance);
            if prov_path.exists() {
                let prov = Provenance::load(&prov_path)?;
                match sign::subjects_match(&statement, &prov) {
                    Ok(true) => {
                        println!("attestation subjects match {}", prov_path.display())
                    }
                    Ok(false) => {
                        println!(
                            "WARNING: attestation subjects do NOT match {}",
                            prov_path.display()
                        );
                        ok = false;
                    }
                    Err(e) => return Err(e),
                }
            } else {
                println!(
                    "no provenance file at {} — skipping subject cross-check",
                    prov_path.display()
                );
            }
            Ok(if ok { 0 } else { 1 })
        }

        Command::Watch {
            once,
            init,
            config,
            state,
            sarif,
        } => {
            let cwd = std::env::current_dir()?;

            if init {
                let config_path = cwd.join(&config);
                watch::generate_config(&config_path)?;
                println!("wrote {config}");
                return Ok(0);
            }

            let config_path = cwd.join(&config);
            let watch_config: watch::WatchConfig = if config_path.exists() {
                let text = fs::read_to_string(&config_path)?;
                toml::from_str(&text)
                    .map_err(|e| anyhow::anyhow!("invalid {}: {e}", config_path.display()))?
            } else {
                bail!(
                    "config not found: {} — run `sorseal watch --init` first",
                    config_path.display()
                );
            };

            let state_path = cwd.join(&state);

            if once {
                let mut state = watch::load_state(&state_path);
                let checks = watch::check_once(&watch_config, &mut state)?;
                println!("{}", watch::render_checks(&checks));

                let failed: Vec<_> = checks.iter().filter(|c| !c.passed()).cloned().collect();
                if !failed.is_empty() {
                    let _ = watch::send_alerts(&watch_config, &failed);
                }

                if let Some(path) = sarif {
                    std::fs::write(cwd.join(&path), watch::render_sarif(&checks))
                        .map_err(|e| anyhow::anyhow!("failed to write SARIF to {path}: {e}"))?;
                    println!();
                    println!("SARIF report written to {path}");
                }

                watch::save_state(&state, &state_path)?;
                let all_pass = checks.iter().all(|c| c.passed());
                return Ok(if all_pass { 0 } else { 1 });
            }

            watch::run_loop(&watch_config, &state_path)?;
            Ok(0)
        }

        Command::OnchainVerify {
            contract_id,
            rpc,
            artifact,
            provenance,
        } => {
            let cwd = std::env::current_dir()?;
            let p = onchain::load_provenance(&cwd, &provenance)?;
            let rpc_url = rpc.unwrap_or_else(|| onchain::MAINNET_RPC.to_string());
            let transport = onchain::http_transport(&rpc_url);
            println!("checking contract {contract_id} against {rpc_url} ...");
            let check =
                onchain::verify_contract(&transport, &p, &contract_id, artifact.as_deref())?;
            println!("{}", onchain::render_check(&check));
            Ok(if check.match_ { 0 } else { 1 })
        }

        Command::SimulateOnchain {
            contract_id,
            upgrades,
            deploy_wasm,
            provenance,
        } => {
            let cwd = std::env::current_dir()?;
            let p = sorseal::provenance::Provenance::load(&cwd.join(&provenance))?;

            let ledger = sorseal::sim::ledger_from_provenance_with_current(
                &p,
                &contract_id,
                upgrades,
                deploy_wasm.as_deref(),
            )?;
            let transport = sorseal::sim::MockTransport::new(ledger);
            let rpc_url = "mock://local".to_string();
            let contract_hex = sorseal::onchain::normalize_contract_id(&contract_id)?;

            println!(
                "simulated on-chain contract {} ({}) — provenance has {} artifact(s)",
                contract_hex.split_at(12).0,
                rpc_url,
                p.artifacts.len()
            );
            println!("  ledger is served from the sealed provenance; no network, no funds");
            println!();

            println!("sorseal onchain-verify (simulated) ...");
            let current_artifact = p.artifacts.last().map(|a| a.id.clone());
            let check = onchain::verify_contract(
                &transport,
                &p,
                &contract_id,
                current_artifact.as_deref(),
            )?;
            println!("{}", onchain::render_check(&check));
            println!();

            println!("sorseal onchain-audit (simulated) ...");
            let (oldest, latest) = sorseal::audit::rpc_ledger_window(&transport)?;
            println!(
                "  retaining ledgers {oldest}..{latest} — performing audit of the full lineage"
            );
            let events =
                sorseal::audit::scan_upgrade_events(&transport, oldest, latest, &contract_hex)?;
            let current = onchain::fetch_deployed_wasm_hash(&transport, &contract_id)?;
            let report = sorseal::audit::build_audit(
                &contract_hex,
                events,
                current,
                Some(&p),
                &rpc_url,
                (oldest, latest),
            );
            println!("{}", sorseal::audit::render_audit(&report));
            Ok(0)
        }

        Command::Analyze {
            artifact,
            manifest,
            provenance,
            format,
            sarif,
            seal,
            ignore,
        } => {
            let cwd = std::env::current_dir()?;
            let m = Manifest::load(&cwd.join(&manifest))?;
            let ignore: Vec<&str> = ignore.iter().map(|s| s.as_str()).collect();
            let mut exit_code = 0;
            let mut provenance_for_seal = if seal {
                let prov_path = cwd.join(&provenance);
                if prov_path.exists() {
                    Some(Provenance::load(&prov_path)?)
                } else {
                    bail!(
                        "cannot --seal analysis without a provenance file at {} — run `sorseal record` first",
                        prov_path.display()
                    );
                }
            } else {
                None
            };
            let mut all_findings: Vec<analyze::Finding> = Vec::new();
            let mut artifact_analyses: Vec<String> = Vec::new();

            for a in &m.artifacts {
                if let Some(id) = &artifact {
                    if a.id != *id {
                        continue;
                    }
                }
                let source_abs = cwd.join(&a.source_root);
                let analysis = analyze::analyze_tree(&source_abs, &ignore)?;
                match format {
                    AnalyzeFormat::Console => {
                        println!(
                            "{}",
                            analyze::render_analysis(&m.project.name, &a.id, &analysis)
                        );
                    }
                    AnalyzeFormat::Markdown => {
                        print!(
                            "{}",
                            analyze::render_markdown(&m.project.name, &a.id, &analysis)
                        );
                    }
                }
                if let Some(analysis_digest) = provenance_for_seal.as_mut() {
                    let id = a.id.clone();
                    let digest = analysis.digest();
                    let worst = analysis
                        .worst_severity()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_else(|| "none".to_string());
                    analysis_digest
                        .analysis
                        .push(sorseal::provenance::ArtifactAnalysis {
                            id,
                            findings: analysis.findings.len() as u64,
                            worst_severity: worst,
                            digest,
                            analyzed_at: sorseal::clock::now_rfc3339_utc(),
                        });
                }
                if !analysis.ok || !analysis.findings.is_empty() {
                    exit_code = max_code(exit_code, if !analysis.ok { 2 } else { 1 });
                }
                artifact_analyses.push(a.id.clone());
                all_findings.extend(analysis.findings);
            }

            if let Some(sarif_path) = sarif {
                let json = sorseal::sarif::render_analysis_sarif(
                    &m.project.name,
                    &all_findings,
                    &artifact_analyses,
                );
                std::fs::write(cwd.join(&sarif_path), json)
                    .map_err(|e| anyhow::anyhow!("failed to write SARIF to {sarif_path}: {e}"))?;
                println!();
                println!("SARIF report written to {sarif_path}");
            }

            if let Some(p) = provenance_for_seal {
                let prov_path = cwd.join(&provenance);
                p.save(&prov_path)?;
                println!();
                println!("analysis digests sealed into {provenance}");
            }

            Ok(exit_code)
        }

        Command::OnchainAudit {
            contract_id,
            rpc,
            start_ledger,
            end_ledger,
            provenance,
        } => {
            let cwd = std::env::current_dir()?;
            let rpc_url = rpc.unwrap_or_else(|| onchain::MAINNET_RPC.to_string());
            let transport = onchain::http_transport(&rpc_url);
            let contract_hex = sorseal::onchain::normalize_contract_id(&contract_id)?;

            // Provenance is optional for an audit: without it we still
            // reconstruct the full lineage, just without the cross-check.
            let prov_path = cwd.join(provenance.unwrap_or_else(|| PROVENANCE_FILENAME.to_string()));
            let prov = if prov_path.exists() {
                Some(sorseal::provenance::Provenance::load(&prov_path)?)
            } else {
                println!(
                    "no provenance file at {} — auditing history only",
                    prov_path.display()
                );
                None
            };

            let (oldest, latest) = sorseal::audit::rpc_ledger_window(&transport)?;
            let start = start_ledger.unwrap_or(oldest);
            let start = if start < oldest {
                println!(
                    "WARNING  --start-ledger {start} predates RPC retention (oldest {oldest}); clamping"
                );
                oldest
            } else {
                start
            };
            let end = end_ledger.unwrap_or(latest);
            let end = end.min(latest);
            if start > end {
                bail!(
                    "--start-ledger {start} is after the effective end ledger {end} \
                     (--end-ledger {end_ledger:?} / RPC latest {latest})"
                );
            }

            println!(
                "auditing contract {contract_hex} against {rpc_url} (ledgers {start}..{end}) ..."
            );
            let events =
                sorseal::audit::scan_upgrade_events(&transport, start, end, &contract_hex)?;
            let current = onchain::fetch_deployed_wasm_hash(&transport, &contract_id)?;
            let report = sorseal::audit::build_audit(
                &contract_hex,
                events,
                current,
                prov.as_ref(),
                &rpc_url,
                (start, end),
            );
            println!("{}", sorseal::audit::render_audit(&report));
            let fail = report.provenance_supplied && !report.current_attested;
            Ok(if fail { 1 } else { 0 })
        }
    }
}
