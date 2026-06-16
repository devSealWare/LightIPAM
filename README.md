# Light IPAM

Light IPAM is a lightweight IP address management system with a clean web UI and
optional, tightly-scoped active network discovery. It targets small-business
networks first while keeping its architecture credible for larger environments.

The design is intentionally split so risk stays isolated:

- **`app`** — the unprivileged web UI, auth, IPAM inventory, audit log, and scan
  orchestration. Runs with **zero Linux capabilities** and no scanning tools.
- **`scanner-agent`** — an optional, isolated network sensor that runs nmap
  (staged host-discovery → service/OS detection), SNMP (ARP-table harvesting,
  device inventory, and LLDP/CDP neighbor harvesting over UDP/161), and NetBIOS/mDNS
  name resolution (UDP/137 and UDP/5353) for discovery. nmap is the **only** thing
  granted a network capability (`NET_RAW`), and only when enabled; the SNMP and name
  backends are plain unicast UDP and need no extra privilege.
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
  from a gateway's ARP cache (recovering MACs across a router), `snmp_inventory`
  reads a device's own identity (name/OS) and the MACs of its interfaces, and
  `lldp_cdp` reads a switch/router's LLDP/CDP neighbor caches to map which devices
  are wired to which ports.
- **Name resolution (unprivileged):** `name_lookup` asks a host directly for its
  name over NetBIOS (UDP/137) and unicast mDNS (UDP/5353), recovering hostnames for
  devices with no DNS PTR record; NetBIOS works across subnets.
- **Combined** scan runs deep nmap + ARP + SNMP inventory + NetBIOS/mDNS names +
  LLDP/CDP neighbors in one job, merged into one picture per host; an enrichment
  target that does not answer (or a CIDR, which these unicast queries cannot
  expand) is *skipped* (ignored), not failed.
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
- Discovery: nmap plus stdlib SNMP (`gosnmp`), NetBIOS, and mDNS, wrapped by the
  scanner agent.
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

## Limitations

What is intentionally **not** built yet (and roughly where it lands on the
[roadmap](docs/ROADMAP.md)):

- **IPv4 only** — no IPv6 addressing or discovery anywhere in the stack.
- **Single admin role** — no RBAC, no MFA, no OIDC yet (Phase 5).
- **Dev mTLS CA only** — certificates are generated by `cmd/scanner-certs`; there
  is no managed issuance or rotation yet (Phase 5).
- **No backup/restore tooling** and **no secret encryption at rest** yet (Phase 5).
- **SNMP is v2c only** (the config is shaped for v3); one read community per agent.
- **The SNMP, LLDP/CDP, and NetBIOS/mDNS backends are unverified against real
  hardware** — they pass hermetic unit tests but await a live shakedown. mDNS
  cross-subnet resolution is best-effort by design (the protocol is link-local).
- **nmap does TCP only** — no UDP scanning or NSE scripting.
- **LLDP/CDP imports need a management IP** — a neighbor that advertises no
  management address (common for endpoints) is not placed in IPAM from `lldp_cdp`
  alone; pair it with `arp_table`/nmap.
- **No CSV/bulk import-export** in the UI yet, and remaining Phase 4 enrichment
  (DHCP leases, DNS, VLAN/interface mapping) is still to come.

## Project status

Phase 1 (Manual IPAM), Phase 2 (Scanner Agent Foundation), and Phase 3 (Nmap
Discovery MVP) are complete. **Phase 4 (Network Context) is underway:** SNMP
ARP-table harvesting, SNMP device inventory, NetBIOS/mDNS name resolution, and
LLDP/CDP neighbor harvesting have shipped, alongside a combined all-sources scan,
staged nmap scanning, and dynamic per-type scan timeouts. See the roadmap for
what's next.

- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Scanner Protocol](docs/SCANNER_PROTOCOL.md) · [Scanner Agent](docs/SCANNER_AGENT.md) · [Scanner Discovery](docs/SCANNER_DISCOVERY.md)
- Architecture decisions: [docs/adr](docs/adr)
