# New good-first-issues (Wave 9) — draft index

This index tracks the *currently open* good-first-issues for sorseal. Issues
whose drafts shipped are removed from this table (we keep their salt in
`git log`/`RULES.md` — e.g. the oracle/flash-loan/WASM-scanning drafts became
`SORSEAL-113..116`, and the manifest/git + perf drafts landed as tests).

**Shipped since the last refresh (closed, not actionable):**
`rule-oracle-price-feed` → `SORSEAL-113`, `rule-flash-loan-approve` →
`SORSEAL-114`, `wasm-binary-scan` → `SORSEAL-115/116` + `analyze --wasm`,
`manifest-git-unit-tests` → landed unit tests, `perf-large-codebase` →
`tests/perf.rs`, plus `analyze-json/fail-on/explain/suppressions/105/golden`.
`src/analyze.rs` is now the well-trodden path for adding a rule.

| # | Title | Difficulty | File |
|---|-------|-----------|------|
| 1 | Taint / data-flow pass to raise heuristic-rule confidence | hard | `taint-dataflow-confidence.md` |
| 2 | User-extensible rules via config | intermediate | `extensible-rules-config.md` |
| 3 | `npx sorseal` zero-install wrapper | intermediate | `npx-wasm-wrapper.md` |
| 4 | VS Code extension (inline analyze squiggles) | intermediate | `vscode-extension.md` |
| 5 | Hosted verify-any-contract page + provenance badge | intermediate | `hosted-verify-page-badge.md` |
| 6 | Threshold / multi-signer attestations | hard | `threshold-attestations.md` |
| 7 | Golden regression tests for the provenance path | beginner | `provenance-golden-tests.md` |
| 8 | `sorseal hook` edge-case coverage | beginner | `hook-edge-cases.md` |

Opening order suggestion (maximize contributor onboarding + landable scope):

1. Open 8 then 7 first — smallest, test-only, no design needed.
2. Then 2 and 3 (config rule engine / wrapper) — each is contained and has a
   clear test surface.
3. Save 1, 4, 5, 6 last — they touch new design surface (data flow, editor
   integration, web/demo, crypto) and need spec sign-off from maintainers.

Each draft uses the repo's existing issue format (Goal / Scope / Why / Success
criteria). Open with:

```bash
gh issue create --title "good-first-issue: ..." --body-file <file> --label "good-first-issue,enhancement"
```