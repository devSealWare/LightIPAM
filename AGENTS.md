# LightIPAM Agent Contract

This file is the canonical instruction file for AI coding agents (Claude Code,
Codex, Copilot, and future agents) working on LightIPAM. It is intentionally
compact and durable. Task-specific status and history live elsewhere (see
[Documentation sync](#documentation-sync)); do not duplicate them here.

## Project

LightIPAM is a lightweight IP address management (IPAM) system with a clean
server-rendered web UI and optional, tightly-scoped active network discovery. It
targets small-business networks first while staying credible for larger
environments. It ships as three Docker Compose services:

- **`app`** — the unprivileged web UI, auth, IPAM inventory, audit log, and scan
  orchestration. Runs with **zero Linux capabilities** and bundles no scanning tools.
- **`scanner-agent`** — an optional, isolated network sensor. The **only**
  component allowed a network capability (`NET_RAW`, for nmap), and only when enabled.
- **`db`** — PostgreSQL, using native `inet`/`cidr`/`macaddr` types.

Stack: Go standard library `net/http`, `pgx/v5`, embedded SQL migrations,
server-rendered HTML templates, hand-written Tailwind CSS. No large frameworks.

## Read first

Before making changes, inspect the files relevant to your task:

- `AGENTS.md` (this file) — the contract and invariants.
- `docs/agent/PROJECT_STATE.md` — where the project is *now* (release, phase, limits).
- `docs/agent/VALIDATION.md` — how to validate a change locally.
- `docs/agent/CODE_REVIEW.md` — the review checklist your change must survive.
- `README.md` — product overview and run instructions.
- `docs/ARCHITECTURE.md`, `docs/SECURITY.md` — design and threat model.
- `docs/SCANNER_PROTOCOL.md`, `docs/SCANNER_AGENT.md`, `docs/SCANNER_DISCOVERY.md`
  — required reading before any scanner/discovery change.
- `docs/ROADMAP.md`, `CHANGELOG.md`, `docs/adr/` — direction, shipped history, decisions.

## Architecture invariants

These do not change without an ADR and maintainer approval:

- **The web app stays unprivileged.** No raw sockets, no nmap execution, no packet
  capture, no trunked-network scanning, no added Linux capabilities in the `app`
  container. It runs with `cap_drop: ALL`.
- **The scanner-agent owns all privileged/active discovery.** nmap (and its
  `NET_RAW`) live only there. SNMP, NetBIOS/mDNS, DNS, and DHCP-file discovery are
  unprivileged (plain UDP/DNS or a file read) and also live in the agent, never the app.
- **App↔agent is mTLS with two-sided allowlist enforcement.** Keep both the
  app-side check (`ValidateJobForAgent`) and the agent-side check (`ValidateAgentScope`)
  valid on any scan-path change.
- **PostgreSQL native network types are part of the design** (`inet`/`cidr`/`macaddr`);
  overlap/containment is enforced in the database (`cidr && $1`).
- **IPv4 address storage is sparse.** Only touched records exist; never materialize
  every IP in a subnet. Overlapping subnets are globally blocked.
- **The UI is server-rendered.** Strict CSP, **no inline JS/CSS**. Progressive
  enhancement only: any script is a same-origin file under `internal/ui/static`.
  Tailwind source is `internal/ui/assets/app.css`; the committed generated CSS is
  `internal/ui/static/app.css` (regenerate it, do not hand-edit it).
- **The audit log is append-only** (DB triggers block update/delete) and is the
  change feed that drives webhooks.
- **No large frontend/backend frameworks and no new dependency without maintainer
  approval** — usually an ADR. Prefer the Go stdlib and existing patterns.

## Agent workflow

For non-trivial work:

1. **Restate the problem** in your own words.
2. **List assumptions.** If any is load-bearing and uncertain, ask instead of guessing.
3. **List non-goals** so the change stays scoped.
4. **Propose the smallest safe plan.** Prefer reusing existing store methods,
   validators, and templates over new abstractions.
5. **Make surgical changes only.** No drive-by refactors or reformatting; every
   changed line should trace to the task. If you spot unrelated dead code, flag it —
   don't delete it.
6. **Add or update tests** — a regression test for a bug, coverage for new behavior.
   Keep parsing/validation logic pure and unit-tested (the codebase convention).
7. **Add or update docs** when behavior changes (see [Documentation sync](#documentation-sync)).
8. **Run validation** (see below) and report exactly what passed and what did not.
9. **Summarize the changed files** and why.

Surface uncertainty, tradeoffs, and inconsistencies early. Do not make assumptions
on the maintainer's behalf and run with them silently.

## Validation

See `docs/agent/VALIDATION.md` for the full tiered sequence and troubleshooting.
The short form: `npm run build:css`, `go build ./...`, `go vet ./...`,
`go test ./...`, `gofmt -l internal cmd` (must be empty), then
`docker compose build` and `docker compose --profile scanner build`. Never claim a
command passed that you did not run.

## Documentation sync

When behavior or status changes, keep these consistent (the `lightipam-doc-sync`
skill automates this check). Each has a single job — do not duplicate state between them:

- `CHANGELOG.md` — shipped release history (source of truth for what shipped).
- `docs/ROADMAP.md` — phases and planned direction.
- `docs/adr/` — one numbered ADR per architectural decision.
- `docs/agent/PROJECT_STATE.md` — the agent-facing "where are we now?" snapshot.
- `README.md` and the relevant `docs/SCANNER_*` / `docs/SECURITY.md` for the area touched.

No file may say something is *planned* while another says it *shipped*.

## Do not

- Do **not** move scanning capability, raw sockets, nmap, packet capture, or network
  capabilities into the `app` container.
- Do **not** materialize full IP ranges; keep address storage sparse.
- Do **not** add inline JS/CSS or weaken the CSP.
- Do **not** introduce a heavy framework or a new dependency without maintainer sign-off.
- Do **not** hand-edit generated CSS (`internal/ui/static/app.css`) — edit the
  Tailwind source and rebuild.
- Do **not** perform drive-by refactors or broad reformatting.
- Do **not** commit stray root binaries (`/server`, `/scanner-agent`) or dev certs
  under `deploy/scanner-certs/`.
- Do **not** silently skip or hide a failing test — report it.

## PR rules

- **One issue/task per branch**, branched from `main`.
- **No drive-by refactors** and **no unjustified dependency additions**.
- Fill in `.github/pull_request_template.md`, including the security/scanner checklist.
- Run validation and state honestly what you ran.
- **Do not merge your own PR** — the maintainer decides when to merge (PRs are squash-merged).
