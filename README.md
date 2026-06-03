# Light IPAM

Light IPAM is a lightweight IP address management system with a clean web UI and
optional, tightly-scoped active network discovery. It targets small-business
networks first while keeping its architecture credible for larger environments.

The design is intentionally split so risk stays isolated:

- **`app`** — the unprivileged web UI, auth, IPAM inventory, audit log, and scan
  orchestration. Runs with **zero Linux capabilities** and no scanning tools.
- **`scanner-agent`** — an optional, isolated network sensor that runs nmap for
  discovery/service/OS detection. It is the **only** component granted a network
  capability (`NET_RAW`), and only when enabled.
- **`db`** — PostgreSQL, using native `inet`/`cidr`/`macaddr` types.

## Features

**Manual IPAM**
- First-admin bootstrap, local login/logout, Argon2id password hashing, sessions
  and CSRF protection, strict security headers.
- Subnet CRUD with global overlap blocking and optional VLAN metadata.
- Sparse IPv4 address records (`/31` and `/32` supported), device CRUD, MAC
  tracking with private/rotating-MAC detection and best-effort OUI vendor lookup.
- Immutable, append-only audit log with UI filters.

**Discovery (optional, agent-driven)**
- mTLS between app and agent; the app is always the client. Two-sided allowlist
  enforcement (app-side + agent-side).
- nmap-backed host discovery, TCP service detection, and OS probing, with scan
  depth bounded by mode (`passive` → none, `light` → `-sn`, `standard` → `-sV`,
  `deep` → `+ -O`) and rate limiting.
- Manual and scheduled scans (in-process scheduler) with a full job lifecycle and
  audit trail.
- **Review queue** (`/discoveries`): observations never auto-mutate IPAM. Each is
  reconciled against managed records — flagged **new**, **match**, or **conflict**
  (e.g. a changed MAC, or a deprecated address still responding) — and an operator
  imports or dismisses it. Managed addresses get live `last_seen_at` tracking.
- **Near-automatic agent enrollment**: the app pulls an agent's identity from its
  `/register` endpoint (auto on boot for the bundled agent, or via the `/agents`
  "Discover" form) and adds it as `pending` for one-click approval.

## Stack

- Backend: Go standard library `net/http`, `pgx` for PostgreSQL, embedded Go
  migrations. No large frameworks.
- Frontend: server-rendered HTML templates with hand-written Tailwind CSS. No
  client-side JavaScript framework; strict CSP (no inline JS/CSS).
- Database: PostgreSQL 16.
- Discovery: nmap, wrapped by the scanner agent.
- Deployment: Docker Compose.

## Run it

App + database only (no discovery):

```sh
docker compose up --build -d
```

Open `http://localhost:8080` and create the first admin from the bootstrap page.

With the scanner agent (active discovery):

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs   # one-time dev mTLS material
docker compose --profile scanner up --build -d
```

The app auto-enrolls the bundled agent as `pending`; approve it under **Agents**,
create a subnet, then run a scan from **Scans**. Discovered hosts appear under
**Discoveries**. Scan targets must fall within the agent's `AGENT_ALLOWED_CIDRS`
(default `192.168.0.0/16,10.0.0.0/8`).

> The `scanner` Compose profile is required to start the agent — a plain
> `docker compose up` runs only `app` + `db`.

## Verify

```sh
npm run build:css
go test ./...
docker compose build
docker compose --profile scanner build
```

## Security model

The web app must stay unprivileged: no raw sockets, no nmap, no packet capture.
All active scanning lives in the scanner agent, which is the sole holder of
`NET_RAW`. See [docs/SECURITY.md](docs/SECURITY.md) and
[docs/SCANNER_DISCOVERY.md](docs/SCANNER_DISCOVERY.md).

## Project status

Phase 1 (Manual IPAM), Phase 2 (Scanner Agent Foundation), and Phase 3 (Nmap
Discovery MVP) are complete. See the roadmap for what's next.

- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)
- [Scanner Protocol](docs/SCANNER_PROTOCOL.md) · [Scanner Agent](docs/SCANNER_AGENT.md) · [Scanner Discovery](docs/SCANNER_DISCOVERY.md)
- Architecture decisions: [docs/adr](docs/adr)
