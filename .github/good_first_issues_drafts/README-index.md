# New good-first-issues (Wave 9) — draft index

These six issues are ready to open on the repo. They are all scoped to the new
`sorseal analyze` feature so they look "fresh" and relevant, are independently
solvable, and map to the Vulnerability-scan + audit story that strengthens the
Wave 9 appeal.

| # | Title | Difficulty | File |
|---|-------|-----------|------|
| 1 | `analyze --format json` machine-readable output | beginner | `analyze-json-output.md` |
| 2 | `analyze --fail-on <severity>` CI gate (exit non-zero) | beginner | `analyze-fail-on-gate.md` |
| 3 | `analyze --explain <RULE>` self-documenting CLI | beginner | `analyze-explain-flag.md` |
| 4 | Inline / config suppressions for analyzed findings | intermediate | `analyze-suppressions.md` |
| 5 | Activate `SORSEAL-105` unchecked-transfer detection | intermediate | `activate-sorseal-105-transfers.md` |
| 6 | Golden-file digest tests for `analyze` | beginner | `analyze-golden-tests.md` |

Opening order suggestion (maximize contributor onboarding + landable scope):

1. Open 1, 2, 3 first — smallest, most popular surface, sets up the CI story.
2. Then 6 (protects the digest guarantee) and 4 (unblocks real users).
3. Save 5 last — it depends on a stable rule baseline (6) to be safely testable.

Each draft uses the repo's existing issue format (Goal / Scope / Why / Success
criteria), mirrors the tone of the current `good-first-issue` issues, and can be
opened with:

```bash
gh issue create --title "good-first-issue: ..." --body-file <file> --label "good-first-issue,enhancement"
```
