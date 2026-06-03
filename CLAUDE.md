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

Issue #10 is in progress on branch `codex/nmap-discovery-mvp`: the Nmap
Discovery MVP. Issues #7 (protocol), #8 (no-op agent container), and #9 (scan
orchestration) are merged to `main`. With #10, the agent now performs real
active discovery and observations flow into a review queue.

Issue #10 scope (this branch):

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

## Scanner Discovery (issue #10, this branch)

`internal/scanner/agent/nmap.go` is the nmap-backed `Discoverer`. The
orchestrator persists successful observations via `store.UpsertDiscovery`; the
app exposes `/discoveries` (import/dismiss) plus app-pull agent enrollment
(`/agents/discover`, `/agents/{id}/approve`, boot-time auto-enroll). See
`docs/SCANNER_DISCOVERY.md`, ADR 0005.

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

## Next After Issue #10

After this branch is reviewed/merged, candidate follow-ups:

- Per-agent "auto-import trusted discoveries" setting (skip the review queue).
- Reconcile discoveries against existing addresses (flag conflicts/state changes)
  rather than plain upsert.
- Managed certificate issuance/rotation (roadmap Phase 5), replacing the dev CA.
- Scan result detail UI for service/OS evidence beyond the raw JSON.

