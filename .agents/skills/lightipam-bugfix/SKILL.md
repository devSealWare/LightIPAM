---
name: lightipam-bugfix
description: Use when fixing a LightIPAM bug with the smallest safe code change, regression coverage, and validation. Not for new features or refactors.
---

# LightIPAM Bugfix

A disciplined bug/fix loop for LightIPAM (Go / PostgreSQL / Tailwind / Docker
Compose). The goal is the smallest change that provably fixes the bug, with a test
that fails before and passes after. Read [`AGENTS.md`](../../../AGENTS.md) first — its
invariants still apply.

## Workflow

1. **Reproduce or characterize the bug first.** Turn the report into a concrete
   failing input or steps. If you cannot reproduce it, say so and state the most likely
   cause before changing anything. Do not "fix" by guessing.
2. **Locate the root cause, not the symptom.** Trace from the observed behavior to the
   responsible code (`internal/app` handlers, `internal/store` queries,
   `internal/ipam`/`macaddr` helpers, `internal/scanner/*`). Prefer understanding over
   patching over the top.
3. **Add a regression test when feasible.** Put it next to the code
   (`*_test.go`). The codebase keeps parsing/validation/decision logic **pure and
   unit-tested** (e.g. `evaluateLockout`, `parseBulkRequest`, `windowAllows`,
   `validateScanScope`) — a bug in that shape should get a table-driven case. Confirm
   it fails for the right reason first.
4. **Make the smallest safe fix.** Touch only what the bug requires. Match surrounding
   style. Remove only orphans your change creates; if you spot unrelated dead code or a
   second latent bug, flag it as a follow-up — don't fix it here.
5. **Hold the invariants.** Don't move work into the app that belongs in the
   scanner-agent, don't add inline JS/CSS, don't add a dependency, don't materialize IP
   ranges. If the correct fix would cross an invariant, stop and raise it.
6. **Validate.** Run [`docs/agent/VALIDATION.md`](../../../docs/agent/VALIDATION.md)
   Tier 0 (`go test ./...`, `go vet`, `gofmt`, `build:css`). Add Tier 2 runtime smoke
   if the bug is only visible at runtime.
7. **Docs only if behavior changed.** A user-visible behavior change updates the
   relevant doc (README / `docs/SCANNER_*`); an internal fix usually needs none.

## Done when

- The regression test fails on the old code and passes on the new code.
- `go test ./...`, `go vet ./...`, and `gofmt -l internal cmd` are all clean.
- The diff contains nothing beyond the fix and its test.
