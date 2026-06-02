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

Issue #8 is in progress: add the scanner-agent container with a no-op job
receive/report loop. Issue #7 (scanner agent protocol) is merged to `main`.

Issue #8 scope (a no-op agent only — no Nmap, no active scanning):

- `cmd/scanner-agent`: mTLS HTTPS server exposing `GET /healthz` and `POST /jobs`.
- `internal/scanner/agent`: receive/report handler, mTLS server/client TLS config,
  client-identity check, no-op job processing via `scanner.ValidateJobForAgent`.
- `internal/scanner/pki` + `cmd/scanner-certs`: dev CA, agent server cert, app
  client cert.
- `Dockerfile.scanner` and a `scanner-agent` Compose service behind the `scanner`
  profile (drops all caps, read-only). App stays unprivileged.
- Docs: `docs/SCANNER_AGENT.md`, `docs/adr/0003-scanner-agent-container.md`.

## Scanner Protocol (merged, issue #7)

`internal/scanner/protocol.go` defines the versioned protocol: agent
registration, mTLS identity, scan job/result schemas, lifecycle states, and
allowlist validation. `ValidateJob` checks job structure; `ValidateJobForAgent`
enforces the dual job/agent allowlist contract. See `docs/SCANNER_PROTOCOL.md`.

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

## Next After Issue #8

After the scanner-agent container is reviewed/merged, start issue #9:

- App-side manual and scheduled scan job dispatch.
- App acts as the mTLS client to the agent (`POST /jobs`).
- Scan status lifecycle and immutable scan audit trail.
- Still no active Nmap probing (that is issue #10).

