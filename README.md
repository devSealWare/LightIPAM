# Light IPAM

Light IPAM is a lightweight IP address management system with a clean web UI and
optional, tightly-scoped active network discovery. It targets small-business
networks first while keeping its architecture credible for larger environments.

The design is intentionally split so risk stays isolated:

- **`app`** — the unprivileged web UI, auth, IPAM inventory, audit log, and scan
  orchestration. Runs with **zero Linux capabilities** and no scanning tools.
- **`scanner-agent`** — an optional, isolated network sensor that runs nmap
  (staged host-discovery → service/OS detection) and SNMP (ARP-table harvesting +
  device inventory) for discovery. nmap is the **only** thing granted a network
  capability (`NET_RAW`), and only when enabled; SNMP is plain UDP/161 and needs
  no extra privilege.
- **`db`** — PostgreSQL, using native `inet`/`cidr`/`macaddr` types.

## Features

**Manual IPAM**
- First-admin bootstrap, local login/logout, Argon2id password hashing, sessions
  and CSRF protection, strict security headers.
- Subnet CRUD with global overlap blocking and optional VLAN metadata.
- Sparse IPv4 address records (`/31` and `/32` supported), device CRUD, MAC
  tracking with private/rotating-MAC detection and best-effort OUI vendor lookup.
- Devices grouped by subnet, global search across subnets/addresses/devices/MACs,
  and per-table selectable columns.
- Immutable, append-only audit log with UI filters.

**Discovery (optional, agent-driven)**
- mTLS between app and agent; the app is always the client. Two-sided allowlist
  enforcement (app-side + agent-side).
- **Staged nmap** — a fast host-discovery sweep finds live hosts first, then only
  those get service/OS detection (version probing just the open ports). Scan
  **depth** is a Light / Standard / Deep mode (top-1000 → +exhaustive versions+OS
  → all ports), applied to the nmap scan types only.
- **SNMP backends (unprivileged, UDP/161):** `arp_table` harvests IP↔MAC bindings
  from a gateway's ARP cache (recovering MACs across a router), and
  `snmp_inventory` reads a device's own identity (name/OS) and the MACs of its
  interfaces.
- **Combined** scan runs deep nmap + ARP + SNMP inventory in one job, merged into
  one picture per host; an unreachable SNMP target is *skipped* (ignored), not
  failed.
- Manual and scheduled scans (in-process scheduler) with a full job lifecycle,
  audit trail, per-host result detail, and generous per-type scan timeouts.
- **Review queue** (`/discoveries`): observations never auto-mutate IPAM. Each is
  reconciled against managed records — flagged **new**, **match**, or **conflict**
  (e.g. a changed MAC, or a deprecated address still responding) — and an operator
  imports or dismisses it. Managed addresses get live `last_seen_at` tracking.
- **Auto-import & merge-on-rescan:** a trusted agent can auto-import
  non-conflicting hosts, and every scan re-syncs its findings onto already-imported
  devices so different scan types accumulate into one complete record.
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

> If host port 8080 is already taken, publish elsewhere without editing
> `compose.yaml`: copy `.env.example` to `.env` and set e.g. `APP_PORT=31415`,
> then `docker compose up -d`. The `.env` is gitignored, so it survives upgrades.

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
Discovery MVP) are complete. **Phase 4 (Network Context) is underway:** SNMP
ARP-table harvesting and SNMP device inventory have shipped, alongside a combined
all-sources scan, staged nmap scanning, and dynamic per-type scan timeouts. See
the roadmap for what's next.

- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)
- [Scanner Protocol](docs/SCANNER_PROTOCOL.md) · [Scanner Agent](docs/SCANNER_AGENT.md) · [Scanner Discovery](docs/SCANNER_DISCOVERY.md)
- Architecture decisions: [docs/adr](docs/adr)
