# good-first-issue: `npx sorseal` zero-install wrapper

## Goal

The single biggest adoption barrier is toolchain: `cargo install` requires
Rust, and the prebuilt binaries require knowing your platform + an install
step. Ship a thin `npx sorseal` wrapper that downloads the right release binary
on demand and forwards all CLI args — so a JS/TS-first Soroban team goes from
zero to `npx sorseal verify` in one command, no toolchain.

## Scope

- A minimal distribution package (this repo or a sibling, published to npm)
  with a `bin` shim (`sorseal` → `node` script).
- On first run: detect platform/arch, download the matching asset from
  `BreachDirect/sorseal` GitHub Releases (the release workflow already builds
  per-OS binaries + sha256 checksums), verify the checksum, cache under a
  per-user dir, then `spawnSync` the binary with `process.argv`.
- Flags: `--version`, `--force` (re-download), `--quiet`.
- Support Linux/macOS/Windows; document in README next to the `curl` install.

## Why

Removes the toolchain + platform friction that blocks JS-first Soroban teams,
without a rewrite. Clients the Soroban SDK is already a Node dependency for;
the wrapper makes sorseal *discoverable there*.

## Success criteria

- [ ] `npm pack`-able package; `npx sorseal analyze --explain` works offline
      after a single cache download
- [ ] Checksum verified against the release asset's `.sha256`
- [ ] Wrong-arch error is a clear message, not a garbage binary execution
- [ ] README install section shows both `curl` and `npx` lines

## Out of scope

A Rust<->JS API bridge (the binary stays the interface); installing VS Code
integration (separate issue); npm publishing credentials/hosting.