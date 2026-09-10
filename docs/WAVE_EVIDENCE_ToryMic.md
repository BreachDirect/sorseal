# Stellar-related work by @ToryMic

This document collects repositories and brief descriptions (links included) for work I've done in the Stellar / Soroban ecosystem. Add this file to the sorseal repo to support Wave submissions, reviewer context, and maintainer provenance.

Note: visit each repo for full details, README, and activity history.

## Highlights

- privacy-shield-payments — https://github.com/broda-spendy/privacy-shield-payments
  - Confidential peer-to-peer stablecoin transfers on Stellar/Soroban with selective disclosure for compliance. Phase 1 (architecture & scaffolding) is complete, CI/tests passing, and detailed docs (PRD, architecture, ADRs) are included. See README and examples: https://github.com/broda-spendy/privacy-shield-payments/blob/main/README.md
  - Notable locations: `contracts/shield/` (contract skeleton), `docs/` (threat model, ADRs), `examples/` (TypeScript SDK examples for interacting with deployed contracts).

- stellar-rwa-vault-sdk — https://github.com/Maxima-Steller/stellar-rwa-vault-sdk
  - SDK for Real-World Asset (RWA) vault interactions on Stellar (TypeScript). Project contains client libraries and examples for vault integration; see repository README and package layout for details: https://github.com/Maxima-Steller/stellar-rwa-vault-sdk

- soroban-subscription-service — https://github.com/ToryMic/soroban-subscription-service
  - A Soroban smart contract framework for recurring SaaS subscription payments (built for the Stellar Wave Program).

- soroscan — https://github.com/ToryMic/soroscan
  - Open-source event indexer that turns smart contract activity into queryable GraphQL APIs, REST endpoints, and real-time webhooks (Django + Rust contract).

- SoroTask — https://github.com/ToryMic/SoroTask
  - Keeper-style scheduling utility for triggering recurring on-chain contract calls (run by bots that watch the network and trigger transactions).

- trustbridge — https://github.com/ToryMic/trustbridge
  - Decentralized identity & credential verification layer for Stellar dApps (Rust).

- StellarRoute — https://github.com/ToryMic/StellarRoute
  - DEX aggregation engine and UI for best-price routing across Stellar DEX and Soroban AMM pools.

## Other related projects (platforms, contracts, tooling)

- agri-fi — https://github.com/ToryMic/agri-fi
- soroban-state-lens — https://github.com/ToryMic/Soroban-state-lens
- soroban-subscription-service — https://github.com/ToryMic/soroban-subscription-service
- SoroTask — https://github.com/ToryMic/SoroTask
- trustbridge — https://github.com/ToryMic/trustbridge

## How this supports the Wave submission

- Demonstrates hands-on work across multiple layers of the Stellar/Soroban stack: smart contracts, tooling (indexers, test/fuzzing), on-chain utilities, and privacy/payment prototypes.
- Provides reviewers concrete links they can inspect for relevance, code quality, and ecosystem involvement.

## Next suggestions

- Add short README snippets or links from sorseal/README.md or PRD.md pointing to one or two high-impact repos above (e.g., privacy-shield-payments, stellar-rwa-vault-sdk) to show adoption and ecosystem activity.
- Consider adding a MAINTAINERS or AUTHORS section to the repo linking to GitHub profiles and summarizing relevant contributions.

---

File updated by repository collaborator for Wave submission evidence.
