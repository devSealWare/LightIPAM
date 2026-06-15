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
**Roadmap Phase 4 is underway:** three agent-side discovery sources beyond nmap
are merged — SNMP ARP-table harvesting (`arp_table` scan type, ADR 0006), SNMP
device inventory (`snmp_inventory` scan type, ADR 0007), and NetBIOS/mDNS name
resolution (`name_lookup` scan type, ADR 0010) — see "Scanner SNMP ARP
Discovery", "Scanner SNMP Inventory", and "Scanner NetBIOS/mDNS Names" below. On
top of those, the scan experience was overhauled (#44/#45, ADRs 0008/0009): a
`combined` scan now runs deep nmap + ARP + SNMP inventory + NetBIOS/mDNS names
merged per host (a silent enrichment pass is ignored not failed), scan modes are
simplified to Light/Standard/Deep, nmap runs **staged** (host discovery →
service/OS on live hosts only), and scan timeouts are dynamic per-type via the
shared `scanner.ScanBudget` (fixing multi-host "context deadline exceeded"). See
the #44/#45 bullets under "Recent UI / IPAM work". Next candidate work is the rest
of Phase 4 (LLDP/CDP, DHCP leases, DNS enrichment, VLAN/interface mapping) or the
follow-ups under "Next" below.

Issue #10 (merged) scope:

- Agent runs nmap (`internal/scanner/agent/nmap.go`, `Discoverer` interface),
  depth bounded by scan mode (passive → none, light → `-sn`, standard → `-sV`,
  deep → `+ -O`). **Mode mapping and single-pass behavior superseded by #44/#45
  (ADRs 0008/0009): modes are now Light/Standard/Deep and nmap runs staged — see
  the #44/#45 bullets below.** Injectable command runner keeps
  arg-building/XML-parsing tests hermetic.
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

## Scanner NetBIOS/mDNS Names (merged, Phase 4, ADR 0010)

`internal/scanner/agent/names.go` adds a third unprivileged `Discoverer`:
`NameDiscoverer` handles the `name_lookup` scan type by asking a host *directly*
for its name, recovering names for hosts with no DNS PTR record (the common
small-business case). Per target it sends a **NetBIOS** node-status query
(NBSTAT, UDP/137 — a Windows/Samba host returns its machine name + workgroup;
unicast, so it **works across subnets**) and a **unicast mDNS** reverse PTR query
(UDP/5353 — an Apple/Linux/IoT responder returns its `.local` name; link-local, so
cross-subnet is best-effort), folding both into **one observation**: NetBIOS leads
the hostname, mDNS fills it only if NetBIOS was silent, both ride as evidence
(`netbios`/`mdns`). Targets must be single hosts; a CIDR or a host answering
neither protocol is a per-target `name_unresolved` notice, never a job failure.
The NetBIOS/DNS wire formats (first-level name encoding, DNS labels, compression
pointers) are built/parsed with the **standard library — no new dependency** —
behind an injectable `udpExchanger` so encoders/parsers are unit-tested without a
socket (mirrors gosnmp behind `snmpSession`). **Ordinary unicast UDP, no
`NET_RAW`** — capability set unchanged; ports/timeout via `AGENT_NETBIOS_PORT`/
`AGENT_MDNS_PORT`/`AGENT_NAME_TIMEOUT`. Registered on the `DiscoveryRouter` and
folded into `combined` as a third best-effort enrichment pass
(`NewCombinedDiscoverer(nmap, snmp, names)`; `runOptional` now takes the
discoverer). Observations reuse the same review-queue + reconciliation, so a name
merges onto the same discovery row (and device) as nmap services, an ARP MAC, and
an SNMP inventory record. New scan type in `scanTypeOptions()`, `optionLabel`,
`scan_form.js`, and the scan-form help text. See `docs/SCANNER_DISCOVERY.md`,
ADR 0010.

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
- **#44 Combined-all scan + simpler scan modes** (ADR 0008). `combined` now runs
  all three backends in one job: a deep nmap scan (all ports, `-sV` + `-O`) plus
  best-effort SNMP `arp_table` and `snmp_inventory` of the targets, merged per
  host (`CombinedDiscoverer` in `internal/scanner/agent/combined.go`;
  `mergeObservations`). nmap is the core (its failure fails the job); a silent
  SNMP device or a CIDR target is *ignored*, not failed — notices carry the new
  `scanner.CodeScanIgnored` (`scan_ignored`) code, `orchestrator.headlineError`
  keeps them out of the job's headline error, and `/scans/{id}` shows them in a
  muted "Skipped" section (`app.partitionScanErrors`, `PageData.ScanNotices`).
  **Modes simplified** to Light (top-1000 `-sV`), Standard (top-1000 +
  `--version-all` + `-O`) and Deep (all ports `-p-` with `-sV` + `-O`); `passive`
  is still a valid protocol value but dropped from the UI. **Deep is tuned for
  speed** (`timingArgs`): it keeps `-sV` service detection but drops the slow
  `--version-all` and runs the all-port sweep with `-T4 --max-retries 2`, plus
  `--min-rate 1000` when no operator rate is pinned, and is exempt from the
  conservative default `--max-rate 100` cap that still applies to shallow modes. Mode is an nmap-only depth
  knob — `arp_table`/`snmp_inventory`/`combined` ignore it and the form hides the
  picker (`app.modeForType` normalizes server-side, so it works JS-off). Dynamic
  show/hide + per-type hint via same-origin `internal/ui/static/scan_form.js`
  (`ui.ScanFormJS`, route `GET /static/scan_form.js`); strict CSP unchanged.
  Friendly `optionLabel` text on the type/mode `<select>`s. Combined is registered
  on the agent router in `cmd/scanner-agent/main.go`.
- **#45 Staged nmap + dynamic timeouts** (ADR 0009). `NmapDiscoverer.Discover` now
  scans in two stages: a fast `-sn -T4` **host-discovery** sweep finds live hosts
  (short-circuiting a dead range with no port scan), then only those hosts get a
  `-Pn` **service/OS** pass that version-probes just the open ports; the stages
  merge per IP (`hostDiscoveryArgs` + `serviceScanArgs`, reusing `mergeObservations`;
  `nmapArgs` is gone). `host_discovery` is stage 1 only; SNMP types are unaffected.
  **Timeouts are now dynamic + generous and the dispatch-deadline bug is fixed.**
  `ScanJob.TimeoutSeconds` is per-host; the form leaves it blank and
  `app.defaultTimeoutForType` fills a per-type default (host_discovery 120 /
  service_detection 600 / os_probe 900 / combined 1200 / arp_table 180 /
  snmp_inventory 300). `scanner.ScanBudget(perHost, targets)` (new
  `internal/scanner/budget.go`, with `EstimateTargetHosts`, cap raised 2h→4h)
  derives the whole-job budget; **both** the agent's supervising context and the
  app's dispatch context use it (app adds 60s grace), so a multi-host scan no
  longer trips "context deadline exceeded" — previously the app gave up after
  `perHost + 10s` while the agent needed `perHost × hosts`. Agent's local
  `scanBudget`/`estimateTargetHosts` removed in favor of the shared funcs. Form's
  timeout field shows the per-type default as a placeholder (`scan_form.js`).

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

- **Phase 4 (Network Context):** SNMP ARP-table harvesting (ADR 0006), SNMP
  device inventory (interfaces/sysDescr, ADR 0007), and NetBIOS/mDNS name
  resolution (`name_lookup`, ADR 0010) are **done**. Remaining: LLDP/CDP
  neighbors, DHCP lease ingestion, DNS enrichment, VLAN/interface mapping. Each
  new source should reuse the discovery review-queue + reconciliation pattern and
  stay in the agent, not the app.
- **Phase 5 (Production Hardening):** managed certificate issuance/rotation
  (replacing the dev CA), OIDC/MFA, encrypted secrets, backup/restore.

When starting the next issue, branch from `main`, and confirm with the user
which item to pick up (the backlog file no longer drives the order).

