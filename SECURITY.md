# Security Policy

## Supported Versions

Only the latest commit on `main` is actively maintained. There are no versioned
releases at this time.

| Branch | Supported |
| --- | --- |
| `main` | ✅ Yes |
| older | ❌ No |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, use one of these private channels:

- **GitHub private vulnerability reporting** — use the
  [Security tab → "Report a vulnerability"](https://github.com/BreachDirect/sorseal/security/advisories)
  button in this repository. This is the preferred path.
- **Email** — if GitHub private reporting is unavailable, open an issue asking
  for a secure contact and a maintainer will respond.

### What to include

A useful report includes:

- The affected version (commit, tag, or crate version)
- A clear description of the vulnerability and its potential impact
- Steps to reproduce (minimal `sorseal.toml` and fixture if applicable)
- Affected component(s) (e.g., digest pipeline, attestation signing,
  `onchain-*` commands, CI scripts)
- Any suggested mitigation

### Response expectations

| Step | Target timeline |
| --- | --- |
| Acknowledgement of report | 48 hours |
| Initial triage and severity assessment | 5 business days |
| Fix or mitigation plan communicated to reporter | 14 days |
| Public disclosure (coordinated with reporter) | 90 days from report, or sooner if a fix is ready |

We follow a **coordinated disclosure** model. We ask reporters to keep details
private until a fix is available or the 90-day window closes, whichever comes
first. Reporters are credited in the advisory unless they prefer to remain
anonymous.

## Security Model

sorseal is designed to be trustworthy even when the projects it inspects are
hostile:

- The core path is **offline** — hashing, sealing, and verification make no
  network requests, so they cannot exfiltrate data. The sole networked command
  is `onchain-verify`, which talks only to the Soroban RPC endpoint you pass it
  (default: Stellar's public RPC) and sends nothing but the query key for the
  contract it is asked to inspect.
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

## Maintainer Conflicts of Interest

Security trust depends on assignment, triage, review, merge, severity, and
disclosure decisions being made by maintainers who can act independently.

A maintainer has a conflict of interest when they are the reporter, author,
assignee, PR author, employer, client, sponsor, close collaborator, direct
financial beneficiary, direct competitor, or prior private implementer for the
issue or PR under decision.

### Required control path

1. The conflicted maintainer discloses the conflict before taking an
   assignment, review, merge, severity, fix-readiness, or disclosure decision.
2. For public issues or PRs, disclose with a short public comment and avoid
   sensitive details. For private vulnerability reports, disclose only in the
   GitHub private vulnerability report or maintainer channel.
3. An unconflicted maintainer takes ownership before the decision continues.
4. The conflicted maintainer may provide factual context when requested, but
   must not approve, merge, assign, close, set severity, decide disclosure
   timing, or award resolution credit for the conflicted item.
