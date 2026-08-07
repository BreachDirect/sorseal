//! Demo Soroban contract. The only thing that changes between "releases" is
//! the constant returned by `value()`; each bump produces a distinct wasm so
//! `sorseal onchain-audit` can reconstruct the upgrade lineage on the ledger.
//!
//! Bump the constant, rebuild, `sorseal record`, and deploy the new wasm as an
//! upgrade — see scripts/demo.sh for the full workflow.

#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Demo;

#[contractimpl]
impl Demo {
    pub fn value() -> u32 {
        1_000
    }
}
