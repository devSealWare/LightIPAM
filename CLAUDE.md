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
**Roadmap Phase 4 is underway:** two SNMP sources are merged — ARP-table
harvesting (`arp_table` scan type, ADR 0006) and device inventory
(`snmp_inventory` scan type, ADR 0007) — see "Scanner SNMP ARP Discovery" and
"Scanner SNMP Inventory" below. Next candidate work is the rest of Phase 4
(LLDP/CDP, DHCP leases, DNS enrichment, NetBIOS/mDNS names, VLAN/interface
mapping) or the follow-ups under "Next" below.

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

## Scanner SNMP ARP Discovery (merged, Phase 4, ADR 0006)

`internal/scanner/agent/snmp.go` adds a second `Discoverer` backend: the
`arp_table` scan type harvests IP↔MAC bindings from a gateway/L3 device's
`ipNetToMediaTable` (`1.3.6.1.2.1.4.22.1.2`) over SNMP, recovering MACs for
subnets the agent cannot reach at Layer 2 (ARP does not cross routers). A
`DiscoveryRouter` (`router.go`) routes `arp_table` → SNMP and everything else →
nmap. **Unprivileged: UDP/161, no `NET_RAW`** — the agent's capability set is
unchanged. Targets are the gateway IPs to query; emitted observations are
filtered to the job allowlist. gosnmp behind an injectable `snmpSession`/dialer
keeps parsing/filtering hermetically testable. v2c read community lives on the
agent (`AGENT_SNMP_COMMUNITY`, default `public`; also `AGENT_SNMP_VERSION/PORT/
TIMEOUT/RETRIES`), never the app DB; `SNMPConfig` is shaped for SNMPv3 later.
SNMP observations reuse the existing review-queue + reconciliation path; the
`UpsertDiscovery` services column now preserves an earlier non-empty list when a
new (MAC-only) observation has none, so SNMP + nmap merge on the same IP. See
`docs/SCANNER_DISCOVERY.md`, ADR 0006.

## Scanner SNMP Inventory (merged, Phase 4, ADR 0007)

`internal/scanner/agent/snmp.go` gained a second SNMP behavior: the
`snmp_inventory` scan type asks a device about *itself* (vs. `arp_table`, which
asks about its neighbors). Per target it does one SNMP `Get` of the system group
(`sysDescr/sysObjectID/sysUpTime/sysContact/sysName/sysLocation`) and walks
`ipAdEntIfIndex` (IP→ifIndex), `ifPhysAddress` (ifIndex→MAC) and `ifDescr`
(ifIndex→name), joining them into **one observation per in-scope IP the device
owns** — name → hostname, sysDescr → OSDetail, a coarse `classifyOSFamily` guess,
and the owning interface's MAC. sysLocation/contact/uptime + sysObjectID ride as
evidence. `Discover` now shares the job preamble then dispatches by type
(`discoverARP` / `discoverInventory`); the `DiscoveryRouter` registers the one
`SNMPDiscoverer` for both `arp_table` and `snmp_inventory`. System-`Get` failure
is a per-target `snmp_failed`; the table walks are best-effort; a reachable device
owning no in-scope address records itself against the in-scope target IP. Vendor
still comes from the import-time OUI lookup (real interface MACs), not a
`sysObjectID` table. **No new privilege, no new dependency (gosnmp from #41), no
DB migration** — observations reuse the same review-queue + reconciliation, so an
inventory record, an ARP MAC, and an nmap service scan merge on one IP. New scan
type added to `scanTypeOptions()` and the scan-form help text. See
`docs/SCANNER_DISCOVERY.md`, ADR 0007.

Phase 3 follow-ups (merged, #18):

- **Per-agent auto-import** (`scan_agents.auto_import`, migration 8). When set,
  `orchestrator.maybeAutoImport` imports an agent's non-conflicting, still-pending
  observations straight into IPAM; conflicts and subnet-less hosts stay in the
  `/discoveries` queue. Toggle on the agent form; "Auto-import" badge on `/agents`.
- **Scan result detail UI.** `/scans/{id}` parses the stored agent result
  (`app.parseScanResult`) into per-host cards (MAC, OS, services table, evidence);
  raw JSON kept in a collapsed block.

## Recent UI / IPAM work (merged to `main`)

- **#35 Global search** across subnets, addresses, devices, MACs (`/search`,
  `store.Search`, `search.go`).
- **#36 MAC vendor carry-through** — nmap's OUI vendor flows through discovery
  into device/MAC records.
- **#37 nmap egress pinning** — `EgressOptions` (`-e`/`-S`) pins probes to the
  LAN interface for consistent cross-subnet scans on a dual-homed agent
  (`AGENT_SCAN_SOURCE_IP` / `AGENT_SCAN_INTERFACE`).
- **#38 Devices tab grouped by subnet** + name-at-import; per-device "lowest IP"
  via `LEFT JOIN LATERAL` (`DeviceGroup`, `Device.PrimarySubnet*`).
- **#39 Host IP display** — single-host `ip_addresses`/discovery `inet` render via
  PostgreSQL `host()` (no redundant `/32`); real `subnets.cidr` keeps its prefix.
  Devices tab gained a dedicated monospace IP column (`Device.PrimaryIP`, `+N`
  badge, `sub` template func).
- **#40 Selectable table columns** — per-table "Columns" dropdown on Subnets and
  Devices, persisted in `localStorage`. Served JS `internal/ui/static/columns.js`
  (`ui.StaticJS`, embedded; route `GET /static/columns.js`), referenced from
  `base.html`. Progressive enhancement (all columns render server-side); strict
  CSP unchanged (same-origin script, no inline JS). Menu markup lives in the
  templates so Tailwind generates its classes.
- **#43 Merge scan findings into imported devices** — a device used to be written
  only at first import, so whichever scan imported first won and later scans never
  reached the device (an nmap-then-ARP pair for a host a router away left it
  missing either its services or its MAC; an OS guess from a later nmap never
  appeared). Now `orchestrator.syncImported` → `store.SyncImportedDiscovery`
  re-syncs the merged discovery findings (OS, services, source, newly seen MAC +
  vendor) onto the linked device on **every** scan when the discovery is already
  imported and non-conflicting — independent of `auto_import` (importing was
  already the operator's decision; sync creates no new IPAM records). Never
  renames, never wipes a richer value with an empty one, skips conflicts;
  per-job `scan.discovery.synced` audit. The `importDiscoveryDevice` re-import
  path got the same empty-services guard. Devices imported before this self-heal
  on their next scan. See `docs/SCANNER_DISCOVERY.md` "Merge-on-rescan".

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

- **Phase 4 (Network Context):** SNMP ARP-table harvesting (ADR 0006) and SNMP
  device inventory (interfaces/sysDescr, ADR 0007) are **done**. Remaining:
  LLDP/CDP neighbors, DHCP lease ingestion, DNS enrichment, NetBIOS/mDNS names,
  VLAN/interface mapping. Each new source should reuse the discovery
  review-queue + reconciliation pattern and stay in the agent, not the app.
- **Phase 5 (Production Hardening):** managed certificate issuance/rotation
  (replacing the dev CA), OIDC/MFA, encrypted secrets, backup/restore.

When starting the next issue, branch from `main`, and confirm with the user
which item to pick up (the backlog file no longer drives the order).

