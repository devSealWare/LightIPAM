# Light IPAM Agent Guide

This file is for AI coding agents working on Light IPAM. It captures the current state, implementation patterns, and next priorities so future work can continue without rediscovering project context.

## Product

Light IPAM is a lightweight IP address management system for small business through enterprise use. The deployment target is Docker Compose on one Docker host for the initial release. The long-term architecture keeps the web app unprivileged and puts privileged active network discovery into a separate scanner-agent container.

## Current State

Phase 1 manual IPAM foundation is merged to `main`.

Implemented:

- Go backend with `net/http`.
- PostgreSQL via `pgx`.
- Embedded Go migrations.
- Tailwind CSS via npm.
- Docker multi-stage build.
- Docker Compose app and PostgreSQL services.
- First-admin web bootstrap.
- Local login/logout.
- Argon2id password hashing.
- Session cookies and CSRF checks.
- Security headers.
- Default site migration.
- Optional VLAN metadata on subnets.
- Global subnet overlap blocking.
- IPv4-only subnet/address validation, including `/31` and `/32`.
- Sparse address records only: touched/reserved/assigned/deprecated/conflict/discovered records are stored.
- Subnet CRUD.
- Address create/edit/delete.
- Device CRUD.
- MAC address tracking.
- Address-to-device assignment.
- Locally administered unicast MAC detection for private/rotating MACs.
- Automatic `Private MAC` tagging.
- Small built-in OUI vendor matcher for MVP.
- Immutable audit logs with UI filters.
- Database triggers preventing audit log update/delete.
- Navigation shell/sidebar.
- Confirmation pages for destructive actions.

## Repository Structure

- `cmd/server/main.go`: process entrypoint, config load, database connect/migrate, HTTP server lifecycle.
- `internal/app`: HTTP routes, handlers, form parsing, auth/session checks.
- `internal/auth`: password hashing and random token helpers.
- `internal/config`: environment-driven config.
- `internal/db`: PostgreSQL connection and embedded migrations.
- `internal/ipam`: IPv4/CIDR parsing and utility functions.
- `internal/macaddr`: MAC normalization, private MAC detection, vendor matching.
- `internal/store`: database query layer.
- `internal/ui`: embedded templates and static CSS.
- `internal/ui/assets/app.css`: Tailwind source.
- `internal/ui/static/app.css`: generated CSS committed for embedding.
- `docs`: product, architecture, roadmap, backlog, ADRs.

## Stack

- Language: Go.
- Web: server-rendered HTML templates.
- Styling: Tailwind CSS.
- Database: PostgreSQL.
- Auth: local admin account for MVP.
- Deployment: Docker Compose.
- GitHub: issues and PRs are tracked in `devSealWare/LightIPAM`.

## Development Commands

```sh
npm run build:css
go test ./...
docker compose build
docker compose up -d
docker compose exec app wget -qO- http://127.0.0.1:8080/healthz
```

If Go cache access is blocked in a sandbox, rerun tests with the normal Go build cache permission.

## Design Rules

- Keep the app container unprivileged.
- Do not put raw packet or privileged scanning behavior in the web app.
- Scanner functionality belongs in a separate agent process/container.
- Keep address storage sparse; do not materialize every IP in every subnet.
- Block overlapping subnets globally for MVP.
- Keep audit logs append-only.
- Prefer simple server-rendered flows until a workflow clearly needs HTMX or targeted JavaScript.
- Keep Tailwind classes readable and avoid turning the app into a heavy SPA.

## Scanner Components

- `internal/scanner`: versioned protocol types and allowlist validation
  (issue #7). `ValidateJobForAgent` is the app-side check; `ValidateAgentScope`
  is the agent-side check.
- `internal/scanner/agent`: agent receive/report handler (`GET /healthz`,
  `GET /register`, `POST /jobs`) plus mTLS TLS config builders. `nmap.go` is the
  nmap-backed `Discoverer`; passive jobs stay no-op (issues #8/#10).
- `internal/scanner/pki` + `cmd/scanner-certs`: development CA and agent/app
  certificates.
- `cmd/scanner-agent`: the agent process (mTLS HTTPS). Bundles nmap and runs
  with `NET_RAW` only (issue #10).
- `internal/scanner/dispatch`: the app-side mTLS client that POSTs jobs and
  pulls `/register` for enrollment (issues #9/#10).
- `internal/scanner/orchestrator`: app-side coordinator — validate, enqueue,
  dispatch async, record lifecycle + audit, run the schedule ticker, persist
  observations as discoveries, and auto-enroll the bundled agent.
- App routes: `/scans`, `/agents` (+ `/agents/discover`, `/agents/{id}/approve`),
  `/schedules`, and `/discoveries` (import/dismiss). Migration 5 adds
  `scan_agents`/`scan_schedules`/`scan_jobs`; migration 6 adds `scan_discoveries`.
- `Dockerfile.scanner` + the `scanner-agent` Compose service (behind the
  `scanner` profile): nmap image, `cap_drop: ALL` + `cap_add: NET_RAW`. The app
  service stays at zero capabilities.

See `docs/SCANNER_AGENT.md`, `docs/SCANNER_PROTOCOL.md`, `docs/SCANNER_DISCOVERY.md`,
and ADRs 0002/0003/0004/0005.

## Current State of the Scanner Track

Issue #10 (Nmap Discovery MVP) is **merged to `main`** (PR #15, commit
`4f695c9`). The agent runs real nmap scans (depth bounded by mode); successful
observations land in the `/discoveries` review queue, where an operator imports
them into subnets/devices or dismisses them. Agents enroll by app-pull (auto on
boot via `SCANNER_AGENT_ENDPOINT`, or the `/agents` "Discover" form) as `pending`
for one-click approval. The app remains unprivileged (zero capabilities, no
nmap). The initial backlog (issues #1–#10) is now complete.

## Next

No issue is in progress. Roadmap Phase 3 is complete except conflict-aware
reconciliation. Candidate follow-ups, roughly in priority order:

- Conflict-aware reconciliation: flag IP/MAC conflicts and state changes when a
  discovery overlaps an existing address, instead of a plain upsert/import.
- Per-agent auto-import trust setting (skip the review queue).
- Richer scan-result detail UI (service/OS evidence beyond raw JSON).
- Phase 4 (Network Context): SNMP, LLDP/CDP, DHCP, DNS enrichment, VLAN mapping —
  each reusing the discovery review-queue pattern, kept in the agent.
- Phase 5 (Production Hardening): managed cert issuance/rotation, OIDC/MFA.

Branch from `main` and confirm the next item with the user before starting.

