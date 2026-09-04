//! **Intentionally vulnerable** Soroban contract used to demonstrate
//! `sorseal analyze`. Every function here contains at least one
//! known-fragile Soroban pattern so a fresh checkout can be fed to the
//! analyzer and produce findings immediately.
//!
//! THIS CONTRACT IS A TEACHING EXAMPLE. It is NOT safe to deploy with funds,
//! and it is NOT meant to be a template for production code.

#![no_std]
use soroban_sdk::{contract, contractimpl, token, Address, Env, Symbol};

#[contract]
pub struct Vulnerable;

const BALANCE: Symbol = Symbol::new("balance");
const OWNER: Symbol = Symbol::new("owner");
const LOCKED: Symbol = Symbol::new("locked");

#[contractimpl]
impl Vulnerable {
    // VULN-A (Critical): withdraws value without `require_auth`. Anyone can
    // drain whatever is held.
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let balance: i128 = env.storage().persistent().get(&BALANCE).unwrap_or(0);
        let new_balance: i128 = balance - amount; // VULN-C: unchecked subtraction
        env.storage().persistent().set(&BALANCE, &new_balance);
        token::Client::new(&env, &to).transfer(&env.current_contract_address(), &to, &amount);
    }

    // VULN-B (High): mutates state and then performs a cross-contract call
    // with no guard — a classic reentrancy shape.
    pub fn deposit_and_call(env: Env, rate: i128) -> i128 {
        let deposit: i128 = env.ledger().balance(&env.current_contract_address());
        let seed: i128 = env.storage().persistent().get(&BALANCE).unwrap_or(0);
        let compounded: i128 = seed * (1_000_000 + rate); // VULN-C: unchecked multiply
        env.storage().persistent().set(&BALANCE, &compounded);
        env.invoke_contract::<i128>(&deposit, &Symbol::new("apply"), (&deposit,))
    }

    // VULN-D (Low): panics / unwraps on a caller-reachable value path instead
    // of returning a Result.
    pub fn redeem(env: Env, share: i128) -> i128 {
        let rate: i128 = env.storage().persistent().get(&Symbol::new("rate")).unwrap();
        let principal: i128 = share * rate; // VULN-C
        if principal > 0 {
            env.storage().persistent().set(&BALANCE, &principal);
        } else {
            panic!("redeem: nothing to redeem");
        }
        principal
    }
}
