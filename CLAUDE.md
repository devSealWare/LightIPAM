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

Issue #7 is next: define scanner agent protocol.

The protocol should be concrete enough for implementation but should not add active scanning yet.

Expected protocol shape:

- Agent registration model.
- Agent identity and mTLS model.
- Scan job schema.
- Scan result schema.
- Explicit IPv4 allowlist per scan.
- Scan lifecycle states.
- Error/result evidence.
- Versioned protocol package or docs.

## Suggested Implementation

Add:

- `docs/SCANNER_PROTOCOL.md`
- `docs/adr/0002-scanner-agent-protocol.md`
- `internal/scanner/protocol.go`
- `internal/scanner/protocol_test.go`

Keep this PR focused on contracts. Do not implement the scanner container or Nmap execution yet.

## Verification

Run:

```sh
npm run build:css
go test ./...
docker compose build
docker compose up -d
docker compose exec app wget -qO- http://127.0.0.1:8080/healthz
```

## Next After Issue #7

After the protocol is reviewed/merged, start issue #8:

- Add scanner-agent container.
- Add `cmd/scanner-agent`.
- Add Compose service.
- Implement no-op job receive/report loop.
- Keep app unprivileged.

