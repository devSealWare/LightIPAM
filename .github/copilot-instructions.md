# GitHub Copilot Instructions — LightIPAM

The canonical contract for all AI coding agents in this repo is
[`AGENTS.md`](../AGENTS.md). Read it before suggesting changes. This file repeats
only the highest-risk invariants Copilot must never violate.

## Non-negotiable invariants

- **The web app stays unprivileged.** Never add raw sockets, nmap execution, packet
  capture, or Linux network capabilities to the `app` container.
- **The scanner-agent owns network discovery.** All active/privileged discovery
  (nmap + `NET_RAW`, SNMP, NetBIOS/mDNS, DNS, DHCP) lives in `scanner-agent`, never
  the app. Keep both the app-side (`ValidateJobForAgent`) and agent-side
  (`ValidateAgentScope`) allowlist checks intact.
- **Keep the UI server-rendered and lightweight.** Strict CSP — no inline JS/CSS and
  no frontend framework. Any script is a same-origin file under `internal/ui/static`;
  edit the Tailwind source (`internal/ui/assets/app.css`), never the generated
  `internal/ui/static/app.css`.
- **Sparse IPv4 storage.** Never materialize every address in a subnet.

## Working style

- **No unrelated refactors.** Keep diffs surgical; every changed line should trace to
  the task. Match the surrounding code's style.
- **No new dependency or heavy framework** without maintainer approval (usually an ADR).
- **Update tests and docs** when behavior changes.
- **Run validation** before proposing a PR — see
  [`docs/agent/VALIDATION.md`](../docs/agent/VALIDATION.md).
