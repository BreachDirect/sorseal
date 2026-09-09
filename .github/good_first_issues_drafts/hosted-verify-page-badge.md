# good-first-issue: hosted verify-any-contract page + provenance badge

## Goal

Make provenance *shareable*. Today only someone with the repo + the CLI can
verify a deployment. Add (a) a public "verify any contract" page — paste a
Soroban contract ID, see provenance status — and (b) a README badge like a
build-status badge that links back to the verify page for a given artifact.

## Scope

- A small read-only web service (this repo suggests `actix-web` or a serverless
  function; keep it a sibling crate `web/` so the core CLI stays dependency
  light) with one endpoint: `GET /verify/<contract_id>` → `onchain-verify` /
  `onchain-audit` status (PASSED/FAILED/drift + sealed digest, without leaking
  secrets).
- The badge endpoint `GET /badge/<artifact>.svg` returns a Shield-style SVG
  (passed/drifted/unknown) embeddable in a README, linking to the verify page.
- `sorseal` gains `sorseal serve` (or the endpoint becomes a thin CLI
  subcommand wrapping the same onchain code paths) so local demos don't need a
  deploy.
- Document contract-id holders how to claim/relate a `sorseal.provenance.json`
  to the service.

## Why

A URL + badge makes the provenance story demoable and viral — the same reason
CI badges exist. It's the difference between "trust me" and "here's the link".

## Success criteria

- [ ] `GET /verify/<id>` returns validation status for a simulated/where we
      have a fixture ledger (reuse `src/sim.rs`'s MockTransport for tests)
- [ ] `/badge/<artifact>.svg` renders a correct passed/drifted badge
- [ ] `sorseal serve` demoable offline with `simulate-onchain` fixtures
- [ ] Deployment instructions (Dockerfile or serverless) are in `web/`

## Out of scope

Hosted infrastructure/domain (an issue repo operator deploys it); writing to
chain; storing provenance (the page only reads on-chain state + any public
provenance file linked by the contract owner).