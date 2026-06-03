# Claude Handoff Notes

You are working on `devSealWare/LightIPAM`, a Go/PostgreSQL/Tailwind/Docker Compose IPAM application.

## High-Level Goal

Build Light IPAM into a secure, visually polished, lightweight IP address management system with optional active network discovery. It should serve small business users first while keeping architectural decisions credible for enterprise environments.

## Important Security Direction

The web app must remain unprivileged. Do not add raw socket access, Nmap execution, packet capture, or direct trunked-network scanning to the web app container.

Network discovery belongs in a separate scanner-agent component. The agent may later receive narrow Linux capabilities such as `NET_RAW`, but only the agent should have that risk profile.

## Current State

Phase 1 manual IPAM foundation is complete and merged to `main`.

The app has:

- First-admin bootstrap page.
- Local login/logout.
- Argon2id password hashing.
- Sessions and CSRF checks.
- PostgreSQL embedded migrations.
- Tailwind UI.
- Dashboard.
- Subnet CRUD.
- Sparse address create/edit/delete.
- Device CRUD.
- MAC address tracking.
- Automatic private rotating MAC tagging.
- Best-effort built-in OUI vendor matching.
- Immutable audit logs and audit UI.
- Sidebar/navigation shell.
- Confirmation flows for destructive actions.

## Current Implementation Style

The code avoids large frameworks. Continue using:

- Go standard library HTTP routing.
- `pgx` for PostgreSQL.
- Embedded migrations in `internal/db/migrations.go`.
- Store methods in `internal/store`.
- Handlers in `internal/app`.
- Templates in `internal/ui/templates`.
- Tailwind source in `internal/ui/assets/app.css`.
- Generated CSS in `internal/ui/static/app.css`.

## Current Issue

None in progress. The initial backlog (issues #1–#10) is fully merged to `main`,
and **Roadmap Phase 3 is complete** — #10 (Nmap Discovery MVP) plus conflict-aware
reconciliation (migration 7) finished the "last-seen tracking and conflict
detection" item. Two Phase 3 follow-ups also merged (#18): per-agent auto-import
(migration 8: `scan_agents.auto_import`) and a structured scan-result detail UI.
Next candidate work is Roadmap Phase 4 (Network Context) or the remaining
follow-ups listed under "Next" below.

Issue #10 (merged) scope:

- Agent runs nmap (`internal/scanner/agent/nmap.go`, `Discoverer` interface),
  depth bounded by scan mode (passive → none, light → `-sn`, standard → `-sV`,
  deep → `+ -O`). Injectable command runner keeps arg-building/XML-parsing tests
  hermetic.
- `NET_RAW` granted to the agent compose service only; agent image bundles nmap
  and runs as root. App image stays nmap-free with zero capabilities.
- DB migration 6: `scan_discoveries`. Observations upsert into a **review
  queue** (`/discoveries`); an operator imports (→ address + optional device/MAC
  in the containing subnet) or dismisses. Nothing auto-mutates IPAM.
- **App-pull enrollment.** Agent `GET /register` self-describes; the app
  auto-enrolls the bundled agent on boot (`SCANNER_AGENT_ENDPOINT`) and offers a
  `/agents` "Discover" form, both creating a `pending` agent for one-click
  approval. See ADR 0005, `docs/SCANNER_DISCOVERY.md`.

## Scanner Protocol (merged, issue #7)

`internal/scanner/protocol.go` defines the versioned protocol: agent
registration, mTLS identity, scan job/result schemas, lifecycle states, and
allowlist validation. `ValidateJob` checks job structure; `ValidateJobForAgent`
is the app-side check (active + agent_id + allowlist containment);
`ValidateAgentScope` is the agent-side check (allowlist containment only). See
`docs/SCANNER_PROTOCOL.md`.

## Scanner Agent (merged, issue #8; discovery added in #10)

`cmd/scanner-agent` + `internal/scanner/agent` run the mTLS agent
(`GET /healthz`, `GET /register`, `POST /jobs`). It is no longer a no-op: active
modes run nmap. `internal/scanner/pki` + `cmd/scanner-certs` generate the dev CA
and certs. See `docs/SCANNER_AGENT.md`, ADR 0003.

## Scanner Discovery (merged, issue #10)

`internal/scanner/agent/nmap.go` is the nmap-backed `Discoverer`. The
orchestrator persists successful observations via `store.UpsertDiscovery`; the
app exposes `/discoveries` (import/dismiss) plus app-pull agent enrollment
(`/agents/discover`, `/agents/{id}/approve`, boot-time auto-enroll). See
`docs/SCANNER_DISCOVERY.md`, ADR 0005.

Phase 3 follow-ups (merged, #18):

- **Per-agent auto-import** (`scan_agents.auto_import`, migration 8). When set,
  `orchestrator.maybeAutoImport` imports an agent's non-conflicting, still-pending
  observations straight into IPAM; conflicts and subnet-less hosts stay in the
  `/discoveries` queue. Toggle on the agent form; "Auto-import" badge on `/agents`.
- **Scan result detail UI.** `/scans/{id}` parses the stored agent result
  (`app.parseScanResult`) into per-host cards (MAC, OS, services table, evidence);
  raw JSON kept in a collapsed block.

## Verification

Run:

```sh
npm run build:css
go test ./...
docker compose build
docker compose up -d
docker compose exec app wget -qO- http://127.0.0.1:8080/healthz
```

For the scanner agent + discovery (issues #8/#10):

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs
docker compose --profile scanner build   # builds the nmap agent image
docker compose --profile scanner up -d
```

The app auto-enrolls the bundled agent (pending) on boot; approve it under
`/agents`, then run a scan from `/scans`. Discovered hosts appear under
`/discoveries`. Agent allowlist is `AGENT_ALLOWED_CIDRS` (defaults
`192.168.0.0/16,10.0.0.0/8`); scan targets must fall inside it.

## Next (Phase 3 complete)

The initial backlog and Roadmap Phase 3 are done, plus two Phase 3 follow-ups:

- **Per-agent auto-import (done).** `scan_agents.auto_import` (migration 8). When
  set, the orchestrator imports an agent's non-conflicting, still-pending
  observations straight into IPAM (`maybeAutoImport`); conflicts always stay in
  the `/discoveries` queue. Toggle it on the agent form; the agents list shows an
  "Auto-import" badge.
- **Scan result detail UI (done).** `/scans/{id}` parses the stored agent result
  (`parseScanResult`) and renders per-host cards — MAC, OS, a services table
  (port/state/service/product/version), and evidence — with the raw JSON kept in
  a collapsed block.

Remaining candidate follow-ups, roughly in priority order:

- **Phase 4 (Network Context):** SNMP inventory, LLDP/CDP neighbors, DHCP lease
  ingestion, DNS enrichment, VLAN/interface mapping. Each new source should reuse
  the discovery review-queue + reconciliation pattern and stay in the agent, not
  the app.
- **Phase 5 (Production Hardening):** managed certificate issuance/rotation
  (replacing the dev CA), OIDC/MFA, encrypted secrets, backup/restore.

When starting the next issue, branch from `main`, and confirm with the user
which item to pick up (the backlog file no longer drives the order).

