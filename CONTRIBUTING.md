# Contributing to sorseal

Thank you for your interest in sorseal! We're building a provenance tool for
Soroban contracts on Stellar and welcome contributors of **all skill levels** —
from first-time open-source contributors to seasoned Rust engineers.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Contribution Labels](#contribution-labels)
- [Drips Wave 8 Contributions](#drips-wave-8-contributions)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style & Standards](#code-style--standards)
- [Adding a Feature](#adding-a-feature)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Commit Message Conventions](#commit-message-conventions)
- [Issue Reporting](#issue-reporting)
- [Good First Contributions](#good-first-contributions)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating you agree to uphold a welcoming, respectful environment for everyone.

---

## Getting Started

### Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| Rust | 1.85+ | Install via [rustup](https://rustup.rs) |
| Cargo | 1.85+ | Ships with rustup |
| wasm32 target | — | `rustup target add wasm32-unknown-unknown` (required for the e2e fixture) |

### 1. Fork & Clone

```bash
git clone https://github.com/BreachDirect/sorseal.git
cd sorseal
```

### 2. Build & Test

```bash
cargo build
cargo test
```

### 3. Run the Tool

```bash
cargo run -- init
cargo run -- record
cargo run -- verify
cargo run -- report --format markdown
```

The end-to-end demo (`scripts/demo.sh`) deploys a real contract to testnet and
runs `onchain-verify` + `onchain-audit` against it — see the README
["End-to-end demo"](#end-to-end-demo) section. It needs the `stellar` CLI
(`cargo install soroban-cli --locked`) but nothing else outside the repo.

---

## Contribution Labels

Issues are tagged by difficulty so you can pick the right entry point:

| Label | Meaning |
| --- | --- |
| 🟢 `good-first-issue` | Perfect for newcomers — small, well-scoped, guided |
| 🟡 `help-wanted` | Ready for contribution, some context needed |
| 🔵 `beginner-friendly` | Minimal project context needed |

## Drips Wave 8 Contributions

sorseal is a **Stellar Drips Wave 8** project. Contributors who solve
Wave-listed issues may earn **Wave rewards** in addition to the usual
open-source cred. When you take an issue:

1. Confirm the issue is linked to the Wave's contribution tracker.
2. State your interest in the issue thread before starting work.
3. Reference the issue (and the Wave) in your pull request so contributions can
   be attributed and rewarded.

See the [Drips Wave contributors docs](https://docs.drips.network/wave/contributors/solving-issues-and-earning-rewards)
for the current rules on points and rewards.

---

## Development Workflow

### Branching Strategy

| Branch | Purpose |
| --- | --- |
| `main` | Stable, always passing CI |
| `feature/<topic>` | New features or enhancements |
| `fix/<topic>` | Bug fixes |
| `docs/<topic>` | Documentation-only changes |
| `chore/<topic>` | Tooling, CI, dependency updates |

**Always branch off `main`:**

```bash
git checkout main
git pull origin main
git checkout -b feature/my-feature
```

Prefer rebasing over merging to keep a clean history.

---

## Code Style & Standards

CI enforces formatting, linting, and tests. Run these before every commit:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Additional guidelines:

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) for public APIs.
- Document public items with `///` doc comments.
- Avoid `unwrap()` in production paths — use `?` or explicit error handling.
- No `unsafe` code in the tool itself.
- Keep the dependency tree small: no network, TLS, date-time, or git libraries
  unless the feature genuinely requires them.

---

## Adding a Feature

1. Describe the change in an issue first — check the roadmap issues for planned
   phases (GitHub Action, signed provenance, SLSA attestations).
2. Add the module or extend an existing one in `src/`.
3. Wire the command into `src/main.rs` if it's a new CLI command.
4. Add tests (unit + e2e as appropriate) — see below.
5. Update `README.md`, `ARCHITECTURE.md`, and `PRD.md` as applicable.

---

## Testing Requirements

Every code contribution **must** include appropriate tests.

| Change type | Required tests |
| --- | --- |
| New command | e2e test driving the binary against a fixture |
| Digest / hashing change | Unit tests for determinism and exclusions |
| Bug fix | Regression test that would have caught the bug |
| Refactor | Existing tests must continue to pass |

The e2e suite (`tests/e2e.rs`) copies `tests/fixtures/echo` to a temp dir and
drives the real binary: `record` → wipe `target/` → `verify`. Keep the fixture
dependency-free so builds stay fast and reproducible on CI.

### Running Tests

```bash
cargo test                    # unit + e2e
cargo test --test e2e         # e2e only
```

---

## Pull Request Process

### Before Opening a PR

- [ ] Your branch is rebased on the latest `main`
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] New or updated tests are included
- [ ] No `todo!()` / `unimplemented!()` / debug `println!` left in production paths

### Opening the PR

1. Push your branch to your fork.
2. Open a PR against `BreachDirect/sorseal:main`.
3. Fill in the PR template (summary, motivation / linked issue, testing performed).
4. Request a review — maintainers aim to respond within **48 hours**.

---

## Commit Message Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer: "Closes #<issue>"]
```

### Types

| Type | When to use |
| --- | --- |
| `feat` | New feature or command |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code restructuring, no behaviour change |
| `test` | Adding or fixing tests |
| `chore` | Tooling, CI, dependency bumps |
| `perf` | Performance improvement |

### Example

```
feat(verify): require the sealed commit be reachable from HEAD

A seal is captured before the provenance file exists, so after committing
the seal HEAD moves on. Verify now accepts any HEAD that contains the sealed
commit; byte-level source equality is still enforced by the source digest.
```

---

## Issue Reporting

### Bug Reports

Please include:

1. **Rust version**: `rustc --version`
2. **Steps to reproduce** (minimal `sorseal.toml` + fixture)
3. **Expected vs actual behaviour** (including exit code)
4. **Relevant output** (console, JSON, or Markdown report)

Use the **Bug Report** issue template on GitHub.

### Feature Requests

- Describe the problem you're solving, not just the solution.
- Link to any related issues or discussions.
- Check the roadmap issues first — your feature may already be planned.

### Security Vulnerabilities

**Do not open a public issue.** Contact the maintainers privately via GitHub's
[Security Advisories](../../security/advisories) feature — see
[SECURITY.md](SECURITY.md).

---

## Good First Contributions

Not sure where to start?

- Issues tagged [`good-first-issue`](../../issues?q=label%3Agood-first-issue)
- Add negative-path unit tests for digest exclusions
- Harden error messages and exit-code documentation
- Expand `ARCHITECTURE.md` with worked examples

**Thank you for contributing to sorseal!** Every PR makes Stellar contract
deployments more verifiable.
