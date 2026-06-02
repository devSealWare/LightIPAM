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
  (issue #7, merged). `ValidateJobForAgent` enforces the dual job/agent
  allowlist contract.
- `internal/scanner/agent`: no-op agent receive/report handler plus mTLS
  server/client TLS config builders.
- `internal/scanner/pki` + `cmd/scanner-certs`: development CA and agent/app
  certificates.
- `cmd/scanner-agent`: the agent process (mTLS HTTPS, `GET /healthz`,
  `POST /jobs`). No active scanning yet.
- `Dockerfile.scanner` + the `scanner-agent` Compose service (behind the
  `scanner` profile) build and run the agent unprivileged.

See `docs/SCANNER_AGENT.md`, `docs/SCANNER_PROTOCOL.md`, and ADRs 0002/0003.

## Current Branch Plan

Issue #8 is in progress: scanner-agent container with a no-op receive/report
loop over mTLS. The app stays unprivileged; the agent drops all capabilities
and performs no scanning.

## After Issue #8

Proceed to issue #9: app-side scan orchestration.

- App-side manual and scheduled scan job dispatch.
- App acts as the mTLS client to the agent.
- Scan status lifecycle and immutable scan audit trail.
- Still no active Nmap probing (issue #10).

