//! Demo Soroban contract. The only thing that changes between "releases" is
//! the constant returned by `value()`; each bump produces a distinct wasm so
//! `sorseal onchain-audit` can reconstruct the upgrade lineage on the ledger.
//!
//! `upgrade()` exposes the SDK's `update_current_contract_wasm` host function
//! so the demo can push new wasm through the normal on-chain upgrade path
//! (the same path that emits the `executable_update` system events the audit
//! reads). Bump the constant, rebuild, `sorseal record`, and deploy the new
//! wasm as an upgrade — see scripts/demo.sh for the full workflow.

#![no_std]
use soroban_sdk::{contract, contractimpl, BytesN, Env};

#[contract]
pub struct Demo;

#[contractimpl]
impl Demo {
    pub fn value() -> u32 {
        1_000
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
