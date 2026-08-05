//! sorseal CLI — `sorseal init|record|verify|report`.

use clap::{Parser, Subcommand, ValueEnum};
use sorseal::manifest::Manifest;
use sorseal::provenance::{Provenance, PROVENANCE_FILENAME};
use sorseal::{report, runner, scaffold};
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
        } => {
            let cwd = std::env::current_dir()?;
            let m = Manifest::load(&cwd.join(&manifest))?;
            let p = Provenance::load(&cwd.join(&provenance))?;
            let (checks, all_pass) = runner::verify(&m, &p, &cwd)?;
            println!("{}", report::render_verify(&m.project.name, &checks));
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
    }
}
