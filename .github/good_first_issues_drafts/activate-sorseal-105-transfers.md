## Goal
Expand detection coverage for the newest security-relevant rule: catch
**unchecked / balance-insensitive transfers** (SORSEAL-105, currently dormant)
so `analyze` flags the classic Soroban drain where a function transfers a token
balance without first reading/checking the contract's actual balance or a
guaranteed allowance.

```rust
// currently NOT flagged:
fn sweep(env: Env, to: Address) {
    let amount = SOME_CONSTANT;              // no balance read
    token::Client::new(&env, &to).transfer(&env.current_contract_address(), &to, &amount);
}
```

## Scope
- Finalize `SORSEAL-105` in `src/analyze.rs`: detect a token `.transfer(...)`
  (or `.transfer_from(...)`) call that is not preceded in its function by a
  `ledger().balance(...)` / allowance read of the same contract, indicating the
  amount is hard-coded or derived without checking available balance.
- Reuse the existing per-function analysis (see SORSEAL-102's state-mutation
  tracking) so the check is function-scoped, not just line-scoped.
- Assign severity (propose **High**); add a remediation string.
- Add a vulnerable snippet + a benign snippet (one that does read balance first)
  to the test fixtures in `src/analyze.rs` and assert only the vulnerable one fires.
- Uncomment/register the rule in the rule table (`src/analyze.rs` `RuleId` /
  severity mapping) and update the console + SARIF + Markdown renderers if they
  enumerate rules.

## Why
Missing balance/allowance checks are a leading cause of Soroban value loss.
Activating SORSEAL-105 gives `analyze` real, new findings on a class the current
rule set mostly misses, strengthening the vulnerability-scan story.

## Success criteria
- The vulnerable snippet yields a SORSEAL-105 finding; the balance-checked snippet does not.
- Rule appears in `--explain` output and SARIF rules.
- `cargo test --locked`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` pass.
