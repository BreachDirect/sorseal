//! sorseal — provenance for Soroban/WASM artifacts.
//!
//! Standalone CLI: seals a record of SHA-256 digests for your contract
//! artifacts (WASM + source tree + toolchain + git commit), then verifies at
//! any time that a clean rebuild reproduces those exact digests. Works on any
//! Rust/Soroban project — no dependency on other tools in the Wave toolchain.

pub mod clock;
pub mod digest;
pub mod git;
pub mod manifest;
pub mod onchain;
pub mod provenance;
pub mod report;
pub mod runner;
pub mod sarif;
pub mod scaffold;
pub mod sign;
