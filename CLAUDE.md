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
- Multi-select bulk edit (status/VLAN/tag/clear-device/delete) on the Subnets,
  Addresses, and Devices tables (Phase 4.5, ADR 0016).
- Basic CSV import/export of subnets, addresses, and devices with a validated
  dry-run preview and all-or-nothing apply (Phase 4.5, ADR 0016).
- **Operator-defined custom fields** (text) per entity type — an admin **Custom
  fields** Settings tab defines them; each subnet/address/device form edits the
  values and the detail page shows them (sparse storage, audited, zero-impact until
  a field is defined). Closed the last unbuilt Phase 1 item in the Phase 5 audit
  (2026-06-19); schema tables predated it (migration 1). See ADR 0019.
- Login throttling + account lockout, idle+absolute session timeouts, a
  per-session origin (IP/User-Agent) record, a tabbed **Settings page** (Security
  tab) with active-session review + "log out everywhere", all auth/session policy
  **editable at runtime** (persisted in `app_settings`, env = boot defaults), and a
  `/readyz` readiness probe (Phase 5, ADR 0017).
- **Admin vs. read-only roles** (migration 14, central authorize middleware),
  **TOTP MFA** with recovery codes (migration 15, sealed secret, RFC-vector tested),
  **OIDC SSO** (auth-code + PKCE, sealed client secret, migration 16),
  **encrypted secrets at rest** (`internal/secret`, AES-256-GCM), **pg_dump
  backup/restore** (Backup tab + `docs/BACKUP_RESTORE.md`), and an **app-managed CA**
  (migration 17) that issues + rotates short-lived agent mTLS certs (the agent
  hot-reloads them). Settings grew Users & Roles, Authentication, Agent certificates,
  and Backup & Restore tabs; a per-user `/account` page handles MFA + password +
  session review (Phase 5, ADR 0018). **Phase 5 exit criteria met — ready for Phase 6.**

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

None in progress. A full Phase 1–5 audit (2026-06-19) confirmed the repo is ready
for Phase 6: build/test/vet/`docker compose build` all green, migrations 1–17
ordered, all 10 scan types wired end-to-end, and the Phase 5 security code (secret
sealing, TOTP, OIDC PKCE, managed CA, backups, lockout, roles + last-admin guards)
verified correct. The audit's one finding — **custom fields**, listed in Phase 1 /
backlog #2 & #5 but only ever present as schema — was built and merged as part of the
audit (ADR 0019).

The initial backlog (issues #1–#10) is fully merged to `main`,
and **Roadmap Phase 3 is complete** — #10 (Nmap Discovery MVP) plus conflict-aware
reconciliation (migration 7) finished the "last-seen tracking and conflict
detection" item. Two Phase 3 follow-ups also merged (#18): per-agent auto-import
(migration 8: `scan_agents.auto_import`) and a structured scan-result detail UI.
**Roadmap Phase 4 (Network Context) is complete.** Beyond nmap the agent now has
five unprivileged discovery sources, all reusing the discovery review-queue +
reconciliation and merging per host: SNMP ARP-table harvesting (`arp_table`, ADR
0006), SNMP device inventory **with 802.1Q VLAN + interface mapping** (`snmp_inventory`,
ADRs 0007/0013), NetBIOS/mDNS name resolution (`name_lookup`, ADR 0010), DNS
forward/reverse enrichment (`dns_lookup`, ADR 0012), DHCP lease ingestion
(`dhcp_leases`, ADR 0014), and LLDP/CDP neighbor harvesting (`lldp_cdp`, ADR 0011) —
see the "Scanner …" sections below. The scan experience was overhauled (#44/#45,
ADRs 0008/0009) and a single `combined` scan runs deep nmap + ARP + SNMP inventory
(VLAN) + NetBIOS/mDNS names + DNS names + DHCP leases + LLDP/CDP neighbors merged per
host (a silent/unconfigured enrichment pass is ignored not failed); scan modes are
simplified to Light/Standard/Deep, nmap runs **staged** (host discovery → service/OS
on live hosts only), and scan timeouts are dynamic per-type via the shared
`scanner.ScanBudget`. The scan form leads with **Combined** (the default,
`<optgroup>`-grouped over the single-source advanced scans). **Combined enriches the
hosts nmap discovers** (ADR 0015): it expands a CIDR via the deep nmap stage and runs
the per-host SNMP/name/DNS passes against those live hosts (unioned with any bare-IP
targets), concurrently (`enrichWorkers`) with an SNMP short-circuit (ARP/LLDP run only
when a host answers SNMP) and collapsed skip-notices — fixing the prior bug where a
combined scan of a CIDR ran nmap-only and recovered no MACs/SNMP inventory. DHCP runs
over the whole range. VLAN findings backfill the containing subnet's VLAN when empty
(migration 11), so they reach the Subnets and Devices pages. Next candidate work is
Phase 5 (Production Hardening) or the follow-ups under "Next" below.

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

Scans run manually (`/scans`) or on a **schedule** (`/schedules`, Phase 2 /
backlog #9): `scan_schedules` (migration 5) holds an interval per enabled
schedule, and `orchestrator.StartScheduler`/`RunDueSchedules` (an in-process
ticker, `SCAN_SCHEDULER_TICK_SECONDS`) enqueues a job for each schedule whose
`next_run_at` has passed.

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

## Scanner LLDP/CDP Neighbors (merged, Phase 4, ADR 0011)

`internal/scanner/agent/neighbors.go` adds a fourth discovery behavior, a *third*
on the existing `SNMPDiscoverer`: the `lldp_cdp` scan type maps physical
topology — which devices are wired to which switch ports. Targets are the
switch/router IPs to query; per target the agent walks the Cisco **CDP** cache
(`cdpCacheTable`) and the vendor-neutral **LLDP** remote table (`lldpRemTable` +
`lldpRemManAddrTable`) over UDP/161 and emits one observation per neighbor. CDP
carries the neighbor IP/device-id/platform/port directly; LLDP carries the IP in
its management-address table (joined to the neighbor row by the shared
`timeMark.localPort.remIndex` index), the system name/desc, the remote port, and —
when the chassis id is MAC-typed — the neighbor's **MAC**. A neighbor seen via both
protocols (or via two switches) merges by IP (`mergeObservations`); the reporting
device + protocol + remote port ride as evidence (`cdp`/`lldp`). Only neighbors
with a management IP are emitted (IPAM keys on an address); IPv4 only. **No new
privilege, dependency, or migration** — UDP/161, `gosnmp` already in tree, OID
parsing behind the same injectable `snmpSession` (hermetic PDU tests). The
`DiscoveryRouter` registers the one `SNMPDiscoverer` for `arp_table`,
`snmp_inventory`, **and** `lldp_cdp`; `combined` runs it as a fourth best-effort
pass (reusing its `snmp` field, no constructor change). A device unreachable over
SNMP is a per-target `snmp_failed`; a reachable switch with no neighbors is a clean
empty result. Observations reuse the same review-queue + reconciliation, so a
neighbor merges onto the same discovery row (and device) as nmap services, an ARP
MAC, an SNMP inventory record, and a name. **Also:** `SyncImportedDiscovery` now
backfills an imported address's hostname when empty, so a name from `name_lookup`
or an LLDP/CDP neighbor's system name reaches an already-imported host (never
overwriting an existing hostname). New scan type in `scanTypeOptions()`,
`defaultTimeoutForType` (300s), `modeForType` (no-depth), `optionLabel`,
`scan_form.js`, and the scan-form help text. See `docs/SCANNER_DISCOVERY.md`,
ADR 0011.

## Scanner DNS Names (merged, Phase 4, ADR 0012)

`internal/scanner/agent/dns.go` (`DNSDiscoverer`) adds the `dns_lookup` scan type:
per target it does a reverse (PTR) lookup to name the IP, then a forward (A) lookup
to confirm the name maps back, emitting one observation per host with a PTR record
and the forward-confirmation result as `dns` evidence (a stale/mismatched PTR is
surfaced, not trusted, but the name is kept). Where `name_lookup` (NetBIOS/mDNS)
names hosts with **no** DNS record, this reads the authoritative DNS the network
already runs. Unprivileged UDP/TCP/53 via `*net.Resolver` behind an injectable
`NameResolver` (hermetic tests); `AGENT_DNS_SERVER` picks an explicit resolver
(default system), `AGENT_DNS_TIMEOUT` bounds each lookup. Single-host targets only
(a CIDR/no-PTR is a per-target `dns_unresolved` notice, never a job failure). Folded
into `combined` (the `CombinedDiscoverer` was refactored to an ordered list of
best-effort enrichment passes); reuses the same review-queue + reconciliation. No
schema change. New scan type wired through the form, router, and docs.

## Scanner VLAN + Interface Mapping (merged, Phase 4, ADR 0013)

`snmp_inventory` (no new scan type) now reads each interface's 802.1Q access VLAN and
operational status in `internal/scanner/agent/snmp.go` (`walkVLANs`): best-effort
Q-BRIDGE-MIB walks (`dot1qPvid` keyed by bridge port, joined through
`dot1dBasePortIfIndex` to ifIndex; `dot1qVlanStaticName` for names) plus
`ifOperStatus`, stamping each owned IP's observation with its interface's VLAN
(interface name/status + VLAN ride as evidence). `scanner.Observation.VLAN` carries
it; `scan_discoveries.vlan` (migration 11) stores it, preserved across merges like
the service list. On import **and** every re-sync, a discovered VLAN backfills the
**containing subnet's** VLAN when it has none (`backfillSubnetVLAN`, `cidr >>= ip`),
never overwriting an operator value — so VLAN findings reach the Subnets page; the
device's linked-addresses list shows each address's subnet VLAN, the scan detail and
discovery queue show the VLAN. Unprivileged (UDP/161), no new dependency, parsing
behind the same injectable `snmpSession`.

## Scanner DHCP Leases (merged, Phase 4, ADR 0014)

`internal/scanner/agent/dhcp.go` (`DHCPDiscoverer`) adds the `dhcp_leases` scan type:
the agent reads the DHCP server's lease file and emits one observation per **active**
lease — the authoritative IP↔MAC binding plus the client-supplied hostname. Two
formats parsed behind an injectable `leaseReader` (hermetic fixture tests): ISC
dhcpd's `dhcpd.leases` blocks (active-only, last block per IP wins) and dnsmasq's
leases file; `AGENT_DHCP_LEASE_FORMAT` picks one or auto-sniffs. The job's targets
scope which IP ranges to ingest (`scopeFromTargets`); the allowlist still bounds them.
`AGENT_DHCP_LEASE_FILE` (mounted read-only) names the file — reading it needs no
privilege. Opt-in and never fatal: an unconfigured file is a clear `dhcp_unconfigured`
notice (combined → muted Skipped line). Folded into `combined` as a fifth enrichment
pass; reuses the same review-queue + reconciliation. No schema change. New scan type
wired through the form, router, and docs.

Phase 3 follow-ups (merged, #18):

- **Per-agent auto-import** (`scan_agents.auto_import`, migration 8). When set,
  `orchestrator.maybeAutoImport` imports an agent's non-conflicting, still-pending
  observations straight into IPAM; conflicts and subnet-less hosts stay in the
  `/discoveries` queue. Toggle on the agent form; "Auto-import" badge on `/agents`.
- **Scan result detail UI.** `/scans/{id}` parses the stored agent result
  (`app.parseScanResult`) into per-host cards (MAC, OS, services table, evidence);
  raw JSON kept in a collapsed block.

## Auth & Session Hardening (merged, Phase 5, ADR 0017)

The first Phase 5 slice — authentication + session hardening only (MFA, OIDC, and
roles are separate later slices). The web app stays unprivileged; no client JS added;
the strict CSP is unchanged.

- **Login throttling + lockout.** Migration 12 adds `login_attempts` (one row per
  failed login, keyed by username **and** client IP). `evaluateLockout`
  (`internal/app/lockout.go`) is a **pure, unit-tested** decision: a login locks when
  either key reaches `LoginMaxAttempts` failures within `LoginWindow` and the latest
  failure is still within `LoginLockout` (more restrictive key wins; cooldown clears
  the lock even before failures age out). Store: `RecordLoginFailure`,
  `RecentLoginFailures` (both keys in one `count(*) FILTER` query), `ClearLoginFailures`
  on success. A locked attempt returns HTTP 429 with a generic message (no
  enumeration).
- **Timing-oracle fix.** On user-not-found, `loginSubmit` now runs
  `auth.VerifyDecoy(password)` — an Argon2 verify against a fixed decoy hash (computed
  once at startup, standard params) — so the not-found path costs the same as the
  wrong-password path.
- **Session hardening.** Migration 12 adds `sessions.last_seen_at`, `client_ip`,
  `user_agent`. `CreateSession` captures IP/UA + an absolute expiry; `GetSession(id,
  idleCutoff)` refreshes `last_seen_at` and enforces both **idle** and **absolute**
  bounds in one atomic CTE. **Settings → Security tab** (`GET /settings/security`,
  `GET /settings` redirects to it) lists active sessions (created, last seen, IP, UA,
  "this device") and offers **"log out everywhere"**
  (`POST /settings/security/logout-all`), CSRF-protected and audited. "Settings"
  sidebar link under System (replaces the standalone security page).
- **Runtime-editable policy.** Migration 13 adds a key/value `app_settings` table
  (`store.GetAppSettings`/`SetAppSettings`). The Security tab edits lockout (max
  attempts / window / lockout), session timeouts (idle / absolute), and the **"log out
  everywhere" behavior** (keep-this-device vs sign-out-all). `internal/app/settings.go`
  holds `SecuritySettings` (env defaults overlaid with stored values, cached behind an
  `RWMutex`, refreshed on save) and the pure, unit-tested `parseSecuritySettingsForm`;
  `lockoutPolicy`/`idleCutoff`/`establishSession` read the cache, so edits apply
  immediately. Keep-current uses `store.DeleteOtherUserSessions`. Update is audited
  (`settings.security.updated`).
- **Readiness.** `GET /healthz` stays liveness; **`GET /readyz`** pings the DB
  (`store.Ping`) and reports the applied migration version (`store.MigrationVersion`),
  503 when the DB is down. The app compose service health-checks `/readyz`.
- **Audit + config.** New events `auth.login.failed`, `auth.login.locked`,
  `session.revoked_all`, `settings.security.updated` (via an `auditMeta` JSON-metadata
  helper). Boot defaults in `internal/config`: `LOGIN_MAX_ATTEMPTS` (5),
  `LOGIN_ATTEMPT_WINDOW` (15m), `LOGIN_LOCKOUT` (15m), `SESSION_ABSOLUTE_TIMEOUT`
  (12h), `SESSION_IDLE_TIMEOUT` (30m), `LOGOUT_EVERYWHERE_KEEPS_CURRENT` (false) —
  each overridable at runtime from the Settings page. The IP key is the real
  `RemoteAddr` (not spoofable `X-Forwarded-For`); behind a proxy, terminate it so
  `RemoteAddr` is the client. See ADR 0017.

## Recent UI / IPAM work (merged to `main`)

- **#35 Global search** across subnets, addresses, devices, MACs (`/search`,
  `store.Search`, `search.go`).
- **#36 MAC vendor carry-through** — nmap's OUI vendor flows through discovery
  into device/MAC records (`scan_discoveries.vendor`, migration 10).
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
  appeared). Migration 9 added `devices.os_family`, `devices.os_detail`,
  `devices.services`, and `devices.discovery_source`; now
  `orchestrator.syncImported` → `store.SyncImportedDiscovery`
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

## Next (Phases 3 and 4 complete)

The initial backlog and Roadmap Phases 3 and 4 are done, plus two Phase 3 follow-ups:

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

- **Carried forward from earlier phases (done, Phase 4.5, ADR 0016).** The one
  earlier-phase item the audit (2026-06-17) found unbuilt — **bulk edit + CSV
  import/export** for the manual-IPAM UI (scoped in Phase 1, `docs/MVP.md`, backlog
  #4) — is now shipped. Multi-select bulk status/VLAN/tag/clear-device/delete on the
  Subnets/Addresses/Devices tables (JS-off + JS-on via `internal/ui/static/bulk.js`,
  audited, deletes through `confirm.html`); store bulk methods in
  `internal/store/bulk.go`, handlers + the pure `parseBulkRequest` in
  `internal/app/bulk.go`. CSV import/export of subnets/addresses/devices
  (`internal/app/portability.go`, `internal/store/portability.go`): export columns
  match the forms, import validates every row against the same IPv4/overlap/sparse/
  state rules, shows a dry-run preview (`/import`), and applies all-or-nothing in one
  transaction on confirm. The basic CSV on-ramp, distinct from the Phase 6 NetBox
  format.
  - *(Done in the same audit pass)* the Phase 1 dashboard "review queue" and "scan
    status" widgets, which shipped as static placeholders (the scan panel still read
    "planned for Phase 2"), are now wired to live data — pending-discovery count +
    `/discoveries` link, and recent scan jobs with status badges.
- **Phase 4 (Network Context) — complete.** All sources are done and reuse the
  discovery review-queue + reconciliation, in the agent: SNMP ARP-table harvesting
  (ADR 0006), SNMP device inventory + 802.1Q VLAN/interface mapping (ADRs 0007/0013),
  NetBIOS/mDNS name resolution (`name_lookup`, ADR 0010), DNS forward/reverse
  enrichment (`dns_lookup`, ADR 0012), DHCP lease ingestion (`dhcp_leases`, ADR 0014),
  and LLDP/CDP neighbor harvesting (`lldp_cdp`, ADR 0011). A `combined` scan runs them
  all and enriches the hosts nmap discovers (ADR 0015). Possible Phase-4 polish if
  desired: tagged/trunk VLAN membership (only access PVID is mapped today),
  per-interface speed/alias, and an SNMP/API-based DHCP source for appliances that do
  not expose a lease file.
- **Phase 5 (Production Hardening) — complete (ADRs 0017 + 0018).** First slice (ADR
  0017): auth + session hardening + the runtime-editable Security tab + `/readyz`.
  Second slice (ADR 0018): admin/viewer **roles** (migration 14), **TOTP MFA** +
  recovery codes (migration 15), **OIDC SSO** auth-code + PKCE (migration 16),
  **encrypted secrets at rest** (`internal/secret`), **pg_dump backup/restore**
  (`internal/backup`), and an **app-managed CA** for agent mTLS cert issuance/rotation
  (migration 17) with agent hot-reload. The Phase 5 exit criteria are met. The one
  deferred increment is **online agent-pull cert enrollment** (agent renews its own
  cert over a bootstrap channel) — today the managed CA issues and the agent hot-reloads
  operator-deployed certs. Runbooks: `docs/BACKUP_RESTORE.md`, `docs/DISASTER_RECOVERY.md`,
  `docs/KEY_ROTATION.md`.
- **Settings panel build-out.** The Settings page is the product's configuration
  surface; `docs/SETTINGS.md` is the canonical plan. **Done** tabs: Security, Users &
  Roles, Authentication, Agent certificates, Backup & Restore. **Still planned**:
  General, Scanning/nmap, Discovery, Notifications (Phase 6), and richer Data & Audit —
  each can land independently. The **agent-secret boundary** holds (SNMP communities,
  nmap egress pinning, DHCP lease paths, agent allowlist stay on the agent — never the
  app DB or the panel).

When starting the next issue, branch from `main`, and confirm with the user
which item to pick up (the backlog file no longer drives the order). Phase 5 is
done; the next phase is **Phase 6 (Advanced Automation)** — see `docs/ROADMAP.md`.
