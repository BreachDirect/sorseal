# good-first-issue: threshold / multi-signer attestations

## Goal

Teams want more than one Ed25519 key required before a provenance record counts
as "signed". Extend `src/sign.rs` (currently single-key Ed25519 DSSE, SLSA v1.0)
so a record can be co-signed by N keys and verified against a threshold —
relevant for orgs that require 2-of-3 sign-off before a release is trusted.

## Scope

- Keep the existing single-signer path byte-for-byte compatible (no digest or
  format change for the common case).
- Add a `threshold` field to the signing options: verify accepts a set of
  public keys and a required count, and succeeds iff that many *distinct* valid
  signatures are present.
- `sorseal sign` gains `--signer` (repeatable) and `--threshold N`; keygen
  already emits keypairs — a `sign --aggregate`-style subcommand collects
  co-signatures into one DSSE envelope (or an envelope per signer).
- CLI + tests: keygen N keys, sign, tamper one signature → verify fails below
  threshold, passes at/above it.

## Why

"Provenance" in a corporate context means *whose* keys endorse the deploy.
Threshold signing is a frequently-asked capability on anything touching release
sign-off and is the natural extension of the existing attestation story.

## Success criteria

- [ ] 2-of-3 and 1-of-1 verify correctly; 0-of-N and a tampered key fail
- [ ] `SORSEAL_SKIP_*`-style bypasses none; signer must not sign the wrong
      payload (payload binding re-checked per signature)
- [ ] Single-signer `record`/`verify-attestation` round-trip unchanged (tests
      prove no digest drift)
- [ ] `cargo clippy --all-targets -- -D warnings` + full `cargo test` green

## Out of scope

Ledger/multi-sig *frame* (Stellar account multisig is a separate concerns —
this is about signs over the provenance file); key custodianship.