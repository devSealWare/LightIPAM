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

Issue #9 is in progress: app-side scan orchestration (manual + scheduled scan
jobs, app-as-mTLS-client, lifecycle, scan audit trail). Issues #7 (protocol) and
#8 (no-op agent container) are merged to `main`. Still no active Nmap scanning.

Issue #9 scope:

- DB migration 5: `scan_agents`, `scan_schedules`, `scan_jobs`.
- `internal/scanner/dispatch`: app-side mTLS client that POSTs jobs to agents.
- `internal/scanner/orchestrator`: validates, enqueues, dispatches async, records
  lifecycle + audit, and runs an in-process schedule ticker.
- App UI: `/scans` (list + run), `/agents` (CRUD), `/schedules` (CRUD + run-now).
- App mounts its mTLS client cert (`/certs/app.crt` etc.); dispatch disables
  cleanly if absent.

## Scanner Protocol (merged, issue #7)

`internal/scanner/protocol.go` defines the versioned protocol: agent
registration, mTLS identity, scan job/result schemas, lifecycle states, and
allowlist validation. `ValidateJob` checks job structure; `ValidateJobForAgent`
is the app-side check (active + agent_id + allowlist containment);
`ValidateAgentScope` is the agent-side check (allowlist containment only). See
`docs/SCANNER_PROTOCOL.md`.

## Scanner Agent (merged, issue #8)

`cmd/scanner-agent` + `internal/scanner/agent` run a no-op mTLS agent
(`GET /healthz`, `POST /jobs`). `internal/scanner/pki` + `cmd/scanner-certs`
generate the dev CA and certs. See `docs/SCANNER_AGENT.md`, ADR 0003.

## Verification

Run:

```sh
npm run build:css
go test ./...
docker compose build
docker compose up -d
docker compose exec app wget -qO- http://127.0.0.1:8080/healthz
```

For the scanner agent (issue #8):

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs
docker compose --profile scanner up -d --build
```

## Next After Issue #9

After scan orchestration is reviewed/merged, start issue #10 (Nmap Discovery MVP):

- Implement active discovery inside the scanner agent (Nmap), gated by scan mode.
- Add `NET_RAW` to the agent image/Compose service only — app stays unprivileged.
- IPv4 host discovery, TCP service detection, OS probing where reliable.
- Rate limits; turn agent observations into auto-created or review-queued IPAM
  records (the app already stores raw results in `scan_jobs.result`).

