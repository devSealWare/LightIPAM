---
name: lightipam-doc-sync
description: Use after a LightIPAM feature ships or a plan changes, to reconcile the docs so no file says something is planned while another says it shipped. Keeps agent docs compact and non-duplicated.
---

# LightIPAM Doc Sync

LightIPAM keeps state in several files by design; this skill makes them agree after a
change and prevents duplicated state from rotting. Prose lives where it belongs — agent
files point to it rather than copying it.

## When to run

After a feature ships, a plan changes, an ADR merges, or a release is cut — any time
the answer to "where are we now?" moved.

## Files to reconcile

- [`AGENTS.md`](../../../AGENTS.md) — invariants and workflow (should rarely change).
- [`CLAUDE.md`](../../../CLAUDE.md) — must stay a thin shim over `AGENTS.md`; it must
  **not** accumulate project state.
- [`docs/agent/PROJECT_STATE.md`](../../../docs/agent/PROJECT_STATE.md) — the
  agent-facing "now" snapshot (release, migration number, phase, limitations).
- [`README.md`](../../../README.md) — features and "Limitations" / "Project status".
- [`CHANGELOG.md`](../../../CHANGELOG.md) — shipped history (source of truth for what shipped).
- [`docs/ROADMAP.md`](../../../docs/ROADMAP.md) — phases and planned work.
- [`docs/adr/`](../../../docs/adr) — the ADR for the decision (add or cross-link it).
- `docs/SCANNER_*` and [`docs/SECURITY.md`](../../../docs/SECURITY.md) — for scanner/security changes.

## Rules

1. **No contradictions.** Nothing may be "planned" in one file and "shipped" in
   another. Reconcile toward reality; `CHANGELOG.md` wins on "did it ship?".
2. **No duplicated state.** Do not copy release history or long status prose into
   `AGENTS.md`/`CLAUDE.md`. Agent files link to `CHANGELOG.md` / `PROJECT_STATE.md` /
   `ROADMAP.md`; state lives in exactly one place.
3. **Keep agent docs compact.** If an edit makes an agent file long, that state
   probably belongs in `PROJECT_STATE.md`, the changelog, or an ADR instead.
4. **Update the memory/index only where it exists.** Fix the source-of-truth files;
   don't scatter new copies.

## Workflow

1. Identify what changed (feature X shipped / plan Y changed / ADR Z merged).
2. Update `CHANGELOG.md` (if shipped) and `docs/agent/PROJECT_STATE.md` (release,
   migration number, phase, limitations) first — they anchor the truth.
3. Fan out: adjust `README.md`, `docs/ROADMAP.md`, and the relevant `docs/SCANNER_*` /
   `docs/SECURITY.md` to match; ensure the ADR exists and is cross-linked.
4. Confirm `AGENTS.md`/`CLAUDE.md` still need no change (they usually don't); if they
   do, it is an invariant/workflow change, not a status update.
5. Grep for the old status wording to catch stray copies, and re-read for any remaining
   "planned vs shipped" mismatch.

## Done when

Every file above tells the same story, agent files stayed compact, and no release
history was duplicated into them.
