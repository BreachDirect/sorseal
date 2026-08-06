//! sorseal CLI — `sorseal init|record|verify|report`.

use clap::{Parser, Subcommand, ValueEnum};
use sorseal::manifest::Manifest;
use sorseal::provenance::{Provenance, PROVENANCE_FILENAME};
use sorseal::sign::ATTESTATION_FILENAME;
use sorseal::{onchain, report, runner, scaffold, sign};
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
        /// Provenance file (optional; when given, subjects are cross-checked)
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
}

#[derive(Clone, Copy, ValueEnum)]
enum ReportFormat {
    Console,
    Json,
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
            let prov = Provenance::load(&cwd.join(&provenance))?;
            match sign::subjects_match(&statement, &prov) {
                Ok(true) => println!("attestation subjects match {}", provenance),
                Ok(false) => {
                    println!("WARNING: attestation subjects do NOT match {provenance}");
                    ok = false;
                }
                Err(e) => return Err(e),
            }
            Ok(if ok { 0 } else { 1 })
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
            println!("checking contract {contract_id} against {rpc_url} ...");
            let check = onchain::verify_contract(&p, &rpc_url, &contract_id, artifact.as_deref())?;
            println!("{}", onchain::render_check(&check));
            Ok(if check.match_ { 0 } else { 1 })
        }
    }
}
