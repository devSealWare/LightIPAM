@AGENTS.md

# Claude Code Notes

This repo uses [`AGENTS.md`](AGENTS.md) as the canonical cross-agent contract
(imported above). Read it first — the architecture and security invariants there
are binding.

**Do not duplicate project state in this file.** Current status, validation, and
review guidance live in their own single-source files:

- [`docs/agent/PROJECT_STATE.md`](docs/agent/PROJECT_STATE.md) — where the project is now.
- [`docs/agent/VALIDATION.md`](docs/agent/VALIDATION.md) — how to validate a change.
- [`docs/agent/CODE_REVIEW.md`](docs/agent/CODE_REVIEW.md) — the review checklist.
- [`docs/agent/PROMPT_TEMPLATES.md`](docs/agent/PROMPT_TEMPLATES.md) — reusable task prompts.
- [`CHANGELOG.md`](CHANGELOG.md) — shipped release history.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — roadmap and planned direction.

## Working with Claude Code

- **Plan before non-trivial edits.** Use plan mode (or restate problem → assumptions
  → non-goals → smallest plan) before touching code. Keep diffs surgical.
- **Surface uncertainty instead of guessing.** If a requirement is ambiguous or two
  interpretations exist, ask or flag it — do not pick silently and run with it.
- **Use the focused skills** in [`.agents/skills/`](.agents/skills) for task-specific
  workflows: `lightipam-bugfix`, `lightipam-scanner-change`, `lightipam-review`,
  `lightipam-doc-sync`, `lightipam-release-prep`.
- **Keep docs in sync** when behavior or status changes (see the "Documentation sync"
  section of `AGENTS.md`).
