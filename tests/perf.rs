//! Performance smoke test: `sorseal analyze` against a large synthetic source
//! tree.
//!
//! Kept `#[ignore]`d so CI stays fast — run explicitly:
//!
//!     cargo test --test perf -- --ignored
//!
//! Guards against accidental quadratic blowups in the analyzer: if a refactor
//! of `src/analyze.rs` slows scanning of a monorepo-sized tree past budget,
//! this fails before it ships. The synthetic body is deliberately realistic —
//! mostly guarded "clean" code, a sparse set of findings each ~9th function —
//! so the time measures source scanning, not the cost of materializing tens of
//! thousands of findings. A clean run takes <5s in the debug profile.

use std::time::Instant;

/// Scale of the synthetic tree: ~500 files of generated contract code
/// (~200k lines). A clean run takes a few seconds in the debug profile and
/// well under a second in release.
const FILES: usize = 500;
const LINES_PER_FILE: usize = 180;
/// Budget in seconds. A clean run is well under 5s on this tree in the debug
/// profile (verified against the current analyzer); the extra headroom absorbs
/// cold shared runners while any genuinely quadratic regression will blow past
/// it by orders of magnitude.
const TIME_BUDGET_SECS: u64 = 30;

/// Write a single function's 4-line block: `vulnerable` mixes in the classic
/// flaw patterns (no auth, unchecked subtraction), otherwise it emits guarded
/// code that the rule engine should accept.
fn block_lines(state: &mut String, j: usize) {
    if j % 9 == 0 {
        state.push_str(&format!(
            "pub fn calc_{j}(env: Env, to: Address, amount: i128) -> i128 {{\n"
        ));
        state.push_str(
            "    let balance: i128 = env.storage().persistent().get(&BAL_KEY).unwrap_or(0);\n",
        );
        state.push_str("    let next: i128 = balance - amount;\n    env.storage().persistent().set(&BAL_KEY, &next);\n");
        state.push_str("    next\n}\n");
    } else {
        state.push_str(&format!(
            "pub fn op_{j}(env: Env, to: Address, amount: i128) -> Result<i128, Error> {{\n"
        ));
        state.push_str("    to.require_auth();\n");
        state.push_str(
            "    let balance: i128 = env.storage().persistent().get(&BAL_KEY).unwrap_or(0);\n",
        );
        state.push_str("    let next: i128 = balance.checked_sub(amount).unwrap_or(0);\n    env.storage().persistent().set(&BAL_KEY, &next);\n");
        state.push_str("    token::Client::new(&env, &to).transfer(&env.current_contract_address(), &to, &amount);\n");
        state.push_str("    Ok(next)\n}\n");
    }
}

fn write_tree(root: &std::path::Path) {
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    for i in 0..FILES {
        let path = src.join(format!("mod_{i:04}.rs"));
        let mut body = String::with_capacity(LINES_PER_FILE * 80);
        body.push_str("#![no_std]\nuse soroban_sdk::{Address, Env, Symbol};\nconst BAL_KEY: Symbol = Symbol::new(\"bal\");\n");
        for j in 0..LINES_PER_FILE / 4 {
            block_lines(&mut body, j);
        }
        std::fs::write(&path, body).unwrap();
    }
}

#[test]
#[ignore]
fn analyze_large_tree_within_budget() {
    let dir = tempfile::tempdir().unwrap();
    write_tree(dir.path());

    let source_root = dir.path().join("src");
    let t = Instant::now();
    let analysis = sorseal::analyze::analyze_tree(&source_root, &["target"]).unwrap();
    let elapsed = t.elapsed();

    assert!(analysis.ok, "expected the synthetic tree to be analyzed");
    assert!(
        !analysis.findings.is_empty(),
        "synthetic tree should produce findings"
    );
    assert!(
        elapsed.as_secs() < TIME_BUDGET_SECS,
        "analyze took {:.2}s on {FILES} files x {LINES_PER_FILE} lines — \
         exceeded budget of {TIME_BUDGET_SECS}s; check for a regression in \
         src/analyze.rs",
        elapsed.as_secs_f64()
    );
    eprintln!(
        "perf: analyzed {FILES} files x {LINES_PER_FILE} lines in {:.2}s ({:?} findings)",
        elapsed.as_secs_f64(),
        analysis.findings.len()
    );
}
