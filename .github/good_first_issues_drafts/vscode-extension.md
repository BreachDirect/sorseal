# good-first-issue: VS Code extension (inline analyze squiggles)

## Goal

Surface `sorseal analyze` findings inline in the editor — the highest "wow"
move for a security tool, because detection lands at the moment code is written
rather than a separate CLI step. A minimal VS Code extension wraps the sorseal
binary (or `npx sorseal`) and publishes diagnostics.

## Scope

- Extension activates on Rust workspace open; runs `sorseal analyze` (via the
  local binary or `npx sorseal`'s cached download) against the open workspace.
- Maps findings → `Diagnostic`s with severity mapped from finding severity and
  rule id/confidence in the message; decorate with squiggles and a hover
  showing remediation.
- Re-analyze on save (debounced) or on demand from the command palette
  (`Sorseal: Run analysis`); output channel for the raw report.
- A `sorseal.enableWasmScan` setting toggles `--wasm` (needs a built artifact).

## Why

Tools people keep *open* are the tools they trust. Editor integration converts
analyze results from a periodic CI report into live guidance, which is also the
best showcase of the severity-vs-confidence axis of the report.

## Success criteria

- [ ] Squiggles + hover remediation on a workspace containing
      `examples/vulnerable-contract` without any extra setup
- [ ] Findings update on save; debounce keeps it below a keystroke-lag budget
- [ ] No findings → status bar shows "sorseal: clean"
- [ ] Packaged with `vsce package`; README section links the walkthrough

## Out of scope

Language-server protocol work (leveraging the CLI output is enough); anything
requiring network at runtime beyond an optional binary download.