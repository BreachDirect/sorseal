# New good-first-issues (Wave 9) — draft index

This is the refreshed set of good-first-issues. The previous six drafts
(`analyze-json-output`, `analyze-fail-on-gate`, `analyze-explain-flag`,
`analyze-suppressions`, `activate-sorseal-105-transfers`, `analyze-golden-tests`)
all shipped and are no longer actionable — see `README.md` / `git log`.

The drafts below are scoped to what the repo actually needs next: rule
coverage, tooling integration, binary-level scanning, and test hardening.

| # | Title | Difficulty | File |
|---|-------|-----------|------|
| 1 | Add oracle/price-feed manipulation rule (SORSEAL-113) | intermediate | `rule-oracle-price-feed.md` |
| 2 | Add flash-loan / approve-and-exploit rule (SORSEAL-114) | intermediate | `rule-flash-loan-approve.md` |
| 3 | WASM binary-level scanning (`analyze --wasm`) | intermediate | `wasm-binary-scan.md` |
| 4 | Unit tests for manifest + git validation | beginner | `manifest-git-unit-tests.md` |
| 5 | Pre-commit hook for non-git edge cases | beginner | `hook-edge-cases.md` |
| 6 | Performance smoke test on large codebases | beginner | `perf-large-codebase.md` |

Opening order suggestion (maximize contributor onboarding + landable scope):

1. Open 4 and 5 first — smallest, test-only, no design needed.
2. Then 1 and 2 (rules) — each is a single RuleId + metadata + tests, on the
   well-trodden path established by SORSEAL-107..112.
3. Save 3 and 6 last — they touch new tooling surface and need spec sign-off.

Each draft uses the repo's existing issue format (Goal / Scope / Why / Success
criteria). Open with:

```bash
gh issue create --title "good-first-issue: ..." --body-file <file> --label "good-first-issue,enhancement"
```