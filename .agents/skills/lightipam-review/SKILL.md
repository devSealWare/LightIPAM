---
name: lightipam-review
description: Use to review a LightIPAM pull request or diff against the project's architecture, security, scanner-boundary, test, and docs invariants. Review-only — do not edit unless explicitly asked.
---

# LightIPAM Review

Review a change against LightIPAM's invariants and surface problems by severity. This
skill is **review-only**: produce findings, do not modify code unless the request
explicitly asks you to apply fixes.

## Workflow

1. **Summarize the PR** in one or two sentences: what it changes and why.
2. **Identify the changed surfaces** — which packages/files/areas
   (`internal/app`, `internal/store`, `internal/ui`, `internal/scanner/*`, migrations,
   `compose.yaml`, docs, CI). Note the blast radius.
3. **Walk [`docs/agent/CODE_REVIEW.md`](../../../docs/agent/CODE_REVIEW.md) top to
   bottom.** In particular check:
   - **Architecture / security invariants** — did scanning capability, a raw socket,
     nmap, packet capture, or a network capability move into the `app` container?
   - **Scanner boundary** — are both `ValidateJobForAgent` and `ValidateAgentScope`
     intact? Do scan failures stay explainable (no misleading empty success)?
   - **Sparse storage** — no materializing full IP ranges; overlaps still blocked.
   - **UI / CSP** — no inline JS/CSS; generated CSS not hand-edited without the Tailwind
     source.
   - **Migrations** — additive, ordered, embedded; nothing destructive without a major bump.
4. **Check tests and docs.** Is there a regression test for a fix / coverage for new
   behavior? Do README / `docs/SCANNER_*` / ADRs match the change?
5. **Look for stale agent docs.** Do `AGENTS.md`, `docs/agent/PROJECT_STATE.md`,
   `docs/ROADMAP.md`, and `CHANGELOG.md` still agree after this change? Flag any
   "planned vs shipped" contradiction.
6. **Look for scope creep** — drive-by refactors, unrelated reformatting, an
   unjustified new dependency, speculative abstraction.

## Output

Group findings by severity, most severe first, each with `file:line` and a concrete
failure scenario where relevant:

- **Blocking** — violates an invariant, breaks a build/test, or is a correctness bug.
- **Should-fix** — a real problem that ought to be addressed before merge.
- **Nit** — style/readability; non-blocking.
- **Follow-up issue** — worth doing, but out of scope for this PR (suggest spinning off).

If nothing is wrong, say so plainly and note what you verified. Do not invent findings
to fill the list.
