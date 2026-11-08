# Stellar work by @ToryMic

A short, honest record of my finished work in the Stellar / Soroban ecosystem.

- **sorseal** — this repository. Provenance + static security analyzer for
  Soroban/WASM: 16 rules and a sealed-provenance `drift` comparison, 141 tests
  across Linux/macOS/Windows, released as v0.2.2 with a GitHub Action and a
  published crates.io crate. CI is green, including `cargo audit` and
  `cargo deny`.
  https://github.com/BreachDirect/sorseal
- **schemalock** — declarative API contract test harness for Stellar backends;
  Python + Rust ports with a CI parity gate. Actively maintained.
  https://github.com/BreachDirect/schemalock
- **RytScan** — static security scanner for Soroban contracts with SARIF
  output and a CI merge gate. https://github.com/BreachDirect/RytScan
- **Stellar CLI** — filed a feature request asking for a command to print a
  deployed contract's live wasm hash, so developers can verify the deployed
  bytecode matches their source. https://github.com/stellar/stellar-cli/issues/2723