# Security Policy

## Reporting a Vulnerability

**Do not open a public issue.** If you discover a security vulnerability in
sorseal, please report it privately via GitHub's
[Security Advisories](https://github.com/BreachDirect/sorseal/security/advisories)
feature.

Please include:

- The affected version (commit, tag, or crate version)
- A description of the vulnerability and its impact
- Steps to reproduce (minimal `sorseal.toml` and fixture if applicable)
- Any suggested mitigation

We aim to acknowledge reports within **48 hours** and to triage them within
**7 days**.

## Supported Versions

| Version | Supported |
| --- | --- |
| `main` | Latest, actively developed |
| Latest release | Bug and security fixes |

## Security Model

sorseal is designed to be trustworthy even when the projects it inspects are
hostile:

- It is **offline** — no network access at runtime, so it cannot exfiltrate data.
- It spawns subprocesses only for the user's own `build_command` (run as the
  invoking user, same privileges as a normal `cargo build`) and read-only `git`
  queries.
- It does **not** use `unsafe`.
- The dependency tree is deliberately small (`clap`, `serde`, `serde_json`,
  `toml`, `sha2`, `anyhow`) and is audited weekly in CI via
  [`cargo audit`](https://github.com/BreachDirect/sorseal/actions/workflows/security.yml).

## Dependency Disclosures

Any `RUSTSEC-*` advisory affecting the dependency tree is surfaced by the
Security workflow on `main`, on pull requests, and on a weekly schedule.
