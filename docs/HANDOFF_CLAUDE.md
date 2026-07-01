# Handoff Prompt for Coding Agents

A short prompt to bring Claude Code, Codex, Copilot, or another agent up to speed.
It intentionally **does not** restate project status — that would rot. The canonical
files carry the current truth; this prompt just points at them.

```text
You are working in the GitHub repository devSealWare/LightIPAM.

Read AGENTS.md first — it is the canonical cross-agent contract (project identity,
architecture and security invariants, workflow, validation, and PR rules). Then read,
as relevant to your task:
- docs/agent/PROJECT_STATE.md   (where the project is now: release, migrations, phase, limits)
- docs/agent/VALIDATION.md      (how to validate a change)
- docs/agent/CODE_REVIEW.md     (what review will check)
- README.md, docs/ARCHITECTURE.md, docs/SECURITY.md
- docs/SCANNER_PROTOCOL.md, docs/SCANNER_AGENT.md, docs/SCANNER_DISCOVERY.md
  (required before any scanner/discovery change)
- docs/ROADMAP.md, CHANGELOG.md, docs/adr/  (direction, shipped history, decisions)

The non-negotiable rule: the web app stays unprivileged — no raw sockets, nmap,
packet capture, or trunked scanning in the app container. All privileged/active
discovery lives in the scanner-agent only.

Working agreement: branch from main, make surgical changes, add/update tests and docs,
run validation, open a PR via gh, and stop — the maintainer says when to merge. Confirm
which item to pick up before starting; Phases 1-6 are complete, so the next phase is
open (see docs/agent/PROJECT_STATE.md and docs/ROADMAP.md).

Use the focused skills in .agents/skills/ for task-specific workflows: lightipam-bugfix,
lightipam-scanner-change, lightipam-review, lightipam-doc-sync, lightipam-release-prep.
```
