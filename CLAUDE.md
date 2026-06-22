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
  dry-run preview and all-or-nothing apply (Phase 4.5, ADR 0016), plus a
  **NetBox-compatible** CSV format on the same Import/Export page (Phase 6 slice (d),
  ADR 0023).
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
- **Policy / Health checks** (Phase 6 slice (a), ADR 0020) — a read-only `/policy`
  view (sidebar under System, visible to viewers) that runs hygiene checks on demand:
  overlapping subnets (an invariant verifier — create/import already block overlaps),
  stale managed addresses/devices not seen within a configurable threshold (device
  staleness derived from linked addresses' `last_seen_at`, so **no migration**), and
  unmanaged/conflicting discovered services (reusing the `scan_discoveries` reconcile
  classification). Findings are grouped by severity and link to the offending record; a
  dashboard count widget links to `/policy`; a runtime-editable **Policy** Settings tab
  (admin-only) enables/disables each check + sets the stale threshold + include-never-
  seen, via the `app_settings` pattern (`settings.policy.updated` audit). App-side only,
  no new privilege, no client JS. See the "Policy / Health checks" section below.
- **Scheduled scan windows** (Phase 6 slice (b), ADR 0021) — a scan schedule may
  restrict firing to a **window**: a time-of-day range plus a weekday set, read in the
  schedule's own IANA timezone, layered on top of the existing interval cadence. A due
  schedule outside its window is **skipped that tick and re-checked next tick**
  (`next_run_at` not advanced), so it fires once the window opens. The gate is a pure,
  unit-tested `windowAllows` (handles midnight-wrap, no-time/no-day, and the
  empty-window = always-allowed back-compat default). **Migration 18** adds
  `window_start_min`/`window_end_min` (minutes since midnight, NULL = no time
  restriction), `window_days` (`0=Sun..6=Sat` int[], empty = any day), and `window_tz`
  (default UTC). The schedule form gains native time/day/timezone fields (no client
  JS) and the schedules table shows the window (`ScanSchedule.WindowLabel`).
  `cmd/server` embeds `time/tzdata` so zone lookups work on the Alpine image.
  Per-schedule config — no Settings tab, no new privilege. See the "Scheduled scan
  windows" section below.
- **Change webhooks** (Phase 6 slice (c), ADR 0022) — an admin registers outbound
  webhook endpoints on a **Notifications** Settings tab; the app POSTs an HMAC-signed
  JSON payload to each enabled, subscribed endpoint when a matching change is audited.
  The **audit log is the change feed**: a single mutex-guarded `store.SetAuditHook`
  (registered on both the app's and the orchestrator's store) fans events out via the
  new `internal/webhook` dispatcher, with a pure `categoryForAction` mapping audited
  actions to four subscribable categories (ipam/discovery/scan/security; empty = all).
  Delivery is async with a fresh context and gated to a no-op when no webhook is enabled
  (cached `Active()`); each attempt is recorded in a bounded `webhook_deliveries` log
  (**migration 19** adds `webhooks` + that log). The per-webhook signing secret is
  **sealed at rest** (`internal/secret`); the form never echoes it (blank = keep). Pure
  `parseWebhookForm`/`categoryForAction`/`sign` unit-tested + an httptest test covers
  the real POST/headers/signature. App-side only, no new privilege, no client JS. See
  the "Change webhooks" section below.
- **Discovery subnet auto-create + Import all** (discovery-UX follow-up, ADR 0026) —
  importing a discovered host whose address has no managed subnet opens a
  server-rendered, pure-CSS modal that **is** the subnet form, pre-filled with the
  host's containing **`/24`** (`suggestSubnetCIDR`) and the scanned VLAN; on save the
  subnet is created (the edited CIDR is validated to still contain the host) and the
  import resumes. An **Import all** header control imports the whole **pending,
  non-conflicting** `/discoveries` queue in one click — hosts lacking a subnet are
  **grouped by `/24`** (`missingSubnetGroups`) and prompted one modal at a time,
  re-checking after each until none remain, then everything imports
  (`store.ListPendingImportTargets` drives the gate; conflicts are excluded). Routes
  `POST /discoveries/import-all` + `POST /discoveries/subnet`; reuses `CreateSubnet` +
  `ImportDiscovery` and their audit events — no migration, no new privilege, no client
  JS. See the "Discovery subnet auto-create + Import all" section below.

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

None in progress. **Phase 6 (Advanced Automation) is COMPLETE.** All five slices are
merged: (a) **Policy / Health checks** (ADR 0020), (b) **Scheduled scan windows** (ADR
0021), (c) **Change webhooks** (ADR 0022), (d) **NetBox-compatible import/export** (ADR
0023), and (e) **Machine API + CLI** (ADR 0024). See the Current State bullets and the
matching sections below. The user chose a **CLI** over a Terraform provider for slice (e)
(a provider can be added later against the same stable `/api/v1`). Next would be a new
phase — confirm direction with the user before starting.

One discovery-UX follow-up has since merged on top of Phase 6: **subnet auto-create on
import + "Import all"** (ADR 0026) — see the Current State bullet and the matching
section below. App-side only, no migration.

A full Phase 1–5 audit (2026-06-19) confirmed the repo was ready
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

## Policy / Health checks (merged, Phase 6, ADR 0020)

The first Phase 6 slice and the recommended starting point: a read-only **Policy /
Health** view that flags data-hygiene problems on demand. Fully app-side — no new
privilege, no scanner surface, **no client JS**, **no migration** (it reuses
`subnets`, `ip_addresses`, `scan_discoveries`, and the `app_settings` store).

- **Three checks**, in `internal/app/policy.go` as **pure, unit-tested** functions over
  plain store snapshots (mirroring `evaluateLockout` / `parseBulkRequest`):
  `evaluateOverlaps` (pairwise CIDR overlap/containment — critical; an invariant
  verifier since create/CSV-import already block overlaps via `cidr && $1`),
  `evaluateStaleRecords` (assigned/reserved addresses + devices whose `last_seen_at` is
  older than the threshold → warning; never-seen → info, opt-in), and
  `evaluateUnmanagedServices` (pending `scan_discoveries`: `conflict` → critical reusing
  the stored conflict note, `new` with services → warning — reusing the ADR 0007
  reconcile classification). Plus `summarizeFindings` and `parsePolicySettingsForm`.
- **Store layer** `internal/store/policy.go`: thin snapshot queries (`PolicySubnets`,
  `PolicyAddressRecords`, `PolicyDeviceRecords` — device staleness derived from the max
  `last_seen_at` of linked addresses, `PolicyDiscoveryRecords`) **and** the shared result
  types (`PolicyFinding`, `PolicyFindingGroup`, `PolicySummary`), placed in `store` so
  `ui` renders them without an `app→ui→app` cycle (the `ImportResult` precedent).
- **`/policy` page** (`app.policyIndex`, `requireSession` — any role incl. viewer),
  sidebar link under System, findings grouped by check + severity, each linking to the
  offending subnet/address/device/discovery. `app.computePolicy` runs only enabled checks
  and is shared with the **dashboard widget** (severity-colored count → `/policy`).
- **Policy Settings tab** (admin-only, `GET/POST /settings/policy`): enable/disable each
  check, stale threshold (days), include-never-seen — `app_settings`-persisted, cached
  behind `settingsMu` (`PolicySettings`, refreshed on save), audited
  `settings.policy.updated`. Boot default `POLICY_STALE_AFTER` (720h). See ADR 0020.

## Scheduled scan windows (merged, Phase 6, ADR 0021)

The second Phase 6 slice: a scan **schedule** can restrict firing to a **window** — a
time-of-day range plus a weekday set, read in the schedule's own IANA timezone — on top
of the existing interval cadence. The interval still decides when a run is *due*; the
window decides whether a due run may *fire*. App-side only — no new privilege, no
scanner surface, **no client JS**. The web app stays unprivileged; this changes only
**when** the in-process scheduler dispatches.

- **Pure decision** in `internal/scanner/orchestrator/windows.go`:
  `windowAllows(scanWindow, now) bool` (unit-tested, no DB/clock) with
  `windowFromSchedule(store.ScanSchedule) scanWindow`. Semantics, all chosen so an
  empty window reproduces the pre-window always-allowed behaviour: unset bounds → any
  time; empty day set → any day; half-open `[start,end)`; `start==end` → whole day;
  `start>end` **wraps past midnight** (22:00–06:00); the weekday filter is evaluated
  against now's **local** weekday (so a wrap window's after-midnight tail belongs to the
  new day — documented in ADR 0021).
- **Gate** in `orchestrator.RunDueSchedules`: a due schedule outside its window is
  **skipped this tick without advancing `next_run_at`** (skip-and-recheck), so it stays
  due and fires on the next tick once the window opens. Keeps `RunDueSchedules` cheap.
- **Migration 18** adds to `scan_schedules`: `window_start_min`/`window_end_min`
  (minutes since midnight, NULL = no time restriction — integers, not Postgres `time`,
  since the tree uses no `pgtype`), `window_days int[]` (`0=Sun..6=Sat`, empty = any
  day), `window_tz` (default `UTC`). All-unset = no window = unchanged existing
  schedules.
- **Store** (`internal/store/scans.go`): `ScanSchedule`/`ScanScheduleInput` gain the
  window fields (carried through Create/Update/Get/List/ListDue); `WindowLabel()` /
  `HasWindow()` render and detect a window ("Mon–Fri 01:00–05:00 UTC", "Any time"), with
  pure `formatWeekdays` (contiguous-run compression) tested in `scans_test.go`.
- **Form/handlers** (`internal/app/scans.go`): pure, unit-tested `parseScheduleWindow`
  (both-or-neither time, `HH:MM` range-check, weekday set ⊆ 0–6, IANA-zone validation)
  folded into `scheduleInputFromRequest`; round-tripped in `scheduleFormFromSchedule`.
  `schedule_form.html` gains a "Run window (optional)" section — native
  `<input type="time">`, seven `window_day` checkboxes, and a `window_tz` text input
  with a `<datalist>` (works JS-off). `schedules.html` shows a Window column.
- **tzdata**: `cmd/server/main.go` blank-imports `time/tzdata` so `time.LoadLocation`
  resolves zones on the Alpine app image (no `/usr/share/zoneinfo`). Per-schedule
  config, not a Settings tab; the window rides the existing `scan.schedule.created` /
  `scan.schedule.updated` audit events. See ADR 0021.

## Change webhooks (merged, Phase 6, ADR 0022)

The third Phase 6 slice: outbound HMAC-signed change notifications. An admin registers
webhook endpoints on a **Notifications** Settings tab; the app POSTs a JSON payload to
each enabled, subscribed endpoint when a matching change is audited. App-side only — no
new privilege, no scanner surface, **no client JS**. The only secret (the per-webhook
HMAC signing key) is **sealed at rest** with the app encryption key, like the OIDC
secret and managed-CA key.

- **Audit log = change feed.** `store.CreateAuditLog` is the single chokepoint every
  IPAM edit and scan-lifecycle event funnels through (app handlers **and** the
  orchestrator), so one `store.SetAuditHook` (mutex-guarded — the scheduler goroutine
  writes audits before the hook is registered) captures the whole change surface. The
  hook is set on **both** store instances (app's + orchestrator's) in `app.New`.
- **`internal/webhook`.** `Dispatcher` (store + sealer + http client) with pure,
  unit-tested helpers: `categoryForAction` maps an audited action → one of four
  subscribable categories (`ipam`/`discovery`/`scan`/`security`; CSV exports and routine
  auth events are deliberately undelivered), `matches` (empty subscription = all),
  `sign` (HMAC-SHA256 hex), `EventFromAudit`. `Deliver` runs async with a fresh context
  and is gated to a no-op via a cached atomic `Active()` (refreshed on startup + every
  webhook CRUD), so the hot path costs nothing when no webhook is enabled.
- **Payload/headers.** Body = the marshaled `Event` (`event`, `category`,
  `subject_type`, `subject_id`, `actor_user_id`, audit `metadata` as a nested object,
  `instance`, `timestamp`); headers `X-LightIPAM-Event/Category/Timestamp` and, when
  signed, `X-LightIPAM-Signature: sha256=<hmac>`. An httptest test asserts the real
  POST/headers/signature/body.
- **Migration 19**: `webhooks` (`secret_sealed`, `events text[]`, `enabled`) +
  `webhook_deliveries` (bounded to the last 20 per webhook on insert). Store CRUD +
  `RecordWebhookDelivery`/`ListWebhookDeliveries`/`CountEnabledWebhooks` in
  `internal/store/webhooks.go`; `Webhook.EventsLabel()` for display.
- **Notifications tab** (`internal/app/notifications.go`, admin-only,
  `GET/POST /settings/notifications` + per-webhook `/{id}`, `/{id}/test`,
  `/{id}/delete`): add/edit (inline) webhooks, an event-category picker (shared
  `webhook_events` template partial), "Send test" (synchronous `TestDeliver`), and the
  recent delivery log. Pure `parseWebhookForm` validator (name, `http(s)://` URL,
  category set; secret returned separately for sealing — blank on edit keeps the stored
  one). Audited `settings.notifications.created/updated/deleted/tested`. Best-effort,
  at-most-once delivery (no retry queue this slice; the log + "Send test" surface
  failures). See ADR 0022.

## NetBox-compatible import/export (merged, Phase 6, ADR 0023)

The fourth Phase 6 slice: read/write CSV in **NetBox**'s column format alongside the
native CSV (ADR 0016). App-side only — no schema change, no new privilege, no client JS.

- **Import is a pure translation, not a second pipeline.** `translateNetBoxImport(entity,
  header, records)` (`internal/app/netbox.go`, pure + unit-tested) maps NetBox columns +
  value semantics into the **canonical Light IPAM columns**, preserving row count/order
  so the dry-run line numbers still match the file; `validateImport` then runs the
  **existing** `validateSubnets`/`validateAddresses`/`validateDevices`, dry-run preview,
  and all-or-nothing transactional apply unchanged. A missing required NetBox column
  (`prefix`/`address`/`name`) is a file error. The `format` rides through on
  `store.ImportResult.Format` (hidden field on the apply form) so the confirmed apply
  re-translates the same file. Value maps: `mapNetBoxIPStatus` (active/dhcp/slaac →
  assigned, reserved, deprecated), `stripMask` (NetBox `addr/mask` → host).
- **Export** emits NetBox-named CSV via three handlers (`prefix,status,vlan_vid,site,
  description` / `address,status,dns_name,description` / `name,status,description`), with
  `reverseNetBoxIPStatus` and `netboxAddressString` (host + containing-subnet mask, /32
  fallback) mapping values back. Routes
  `GET /{subnets,addresses,devices}/export.netbox.csv`.
- **UI**: the Import/Export page gains a per-type **Format** selector (Light IPAM/NetBox)
  and **Export NetBox** links; the preview shows an "Interpreted as NetBox" note + the
  translated rows. **Documented lossy edges** (NetBox prefixes have no name → carried in
  `description`; NetBox devices need role/type/site Light IPAM doesn't model) in
  `docs/NETBOX.md`; the IPAM core round-trips. See ADR 0023.

## Machine API + CLI (merged, Phase 6, ADR 0024)

The fifth and final Phase 6 slice: a token-authenticated JSON API + a stdlib-only CLI, so
automation can manage IPAM. The user chose a **CLI over a Terraform provider** (a provider
can be added later against the same stable API). App stays unprivileged; no client JS.

- **API tokens (migration 20).** `api_tokens` stores a **SHA-256 hash** (`auth.HashToken`)
  of each `lipam_<random>` token — plaintext shown once. **Self-service on the Account
  page** (`POST /account/tokens`, `/account/tokens/{id}/delete`): any user mints/revokes
  their own; a token inherits the owner's role. `store.AuthenticateAPIToken` resolves a
  presented hash → user and refreshes `last_used_at` in one statement.
- **JSON API under `/api/v1`** (`internal/app/api.go`): CRUD for subnets, addresses
  (nested under a subnet for list/create, flat by id for get/update/delete), devices, plus
  `whoami`. Each handler wrapped by `apiHandler(write bool, fn)` → authenticates the
  `Authorization: Bearer` token (401), enforces admin role for writes (403), then runs.
  **Cookie-free ⇒ CSRF-exempt** (the cookie `authorize` middleware passes API requests
  through; the per-handler check is the gate). Reuses the **existing store methods +
  validation** (overlap/containment/state enum); mutations are **audited** (so they also
  fan out to change webhooks, ADR 0022). `decodeJSON` bounds the body + rejects unknown
  fields. Pure validators `subnetReq.toInput`/`addressReq.toInput` unit-tested.
- **`cmd/lightipam-cli`**: stdlib-only binary. Config via flags/env (`LIGHTIPAM_URL`/
  `LIGHTIPAM_TOKEN`/`LIGHTIPAM_INSECURE`; global flags precede the command). Verbs:
  `whoami` + `list`/`get`/`create`/`update`/`delete` for subnets/addresses/devices.
  `create`/`update` build a JSON body from only the `--field` flags set (partial update;
  `--vlan` as a JSON number); non-2xx prints the API `error` + non-zero exit. Pure
  `parseFields` unit-tested; the full token→CRUD→401/204 chain verified end-to-end against
  the running app. See `docs/API.md`.

## Discovery subnet auto-create + Import all (merged, ADR 0026)

A discovery-UX follow-up on top of Phase 6: turn a freshly-scanned network into managed
IPAM in a few clicks. App-side only — no new privilege, no scanner surface, **no client
JS**, **no migration** (it reuses `subnets`/`scan_discoveries` and the existing
`CreateSubnet` + `ImportDiscovery` paths).

- **Subnet auto-create on import.** Importing a discovery whose address falls outside
  every managed subnet used to dead-end on `ErrNoContainingSubnet`; now `discoveryImport`
  redirects to `/discoveries?resolve_one={id}`, which opens a **server-rendered, pure-CSS
  modal** that is the subnet form pre-filled with the host's containing **`/24`**
  (`suggestSubnetCIDR`, pure + unit-tested) and the scanned VLAN when known. On save
  (`POST /discoveries/subnet`, `flow=import-one`) the subnet is created and the host is
  imported in the same request. The edited CIDR is validated to still **contain the host**
  (`ipam.Contains`) before creation, so a mistyped range is an in-modal error, not a
  silent re-failure.
- **Import all.** A header control (`POST /discoveries/import-all`, admin-gated, shown
  with a live count) imports every **pending, non-conflicting** discovery
  (`store.ListPendingImportTargets` — returns each target's IP/VLAN and a `HasSubnet`
  computed with the same `cidr >>=` containment the import uses). If any target lacks a
  subnet the flow **does not import**; it walks the missing subnets through the same modal,
  **grouped by `/24`** (`missingSubnetGroups`, pure + unit-tested, ascending network
  order), **re-checking after each** (`flow=import-all` loops via
  `/discoveries?resolve=1`) until none remain, then imports everything and lands on an
  "Imported N hosts" banner. **Conflicts are excluded** — resolving a conflict stays an
  individual operator decision (mirrors auto-import).
- **Shape.** The modal is a fixed overlay (`glass-panel`, Discoveries sky accent,
  `role="dialog"`/`aria-modal`, backdrop/Cancel link back to `/discoveries`,
  `autofocus` on the name field). All mutations are POST with redirect-after-POST, so a
  refresh never re-submits. View model `ui.DiscoverySubnetPrompt`; handlers + helpers in
  `internal/app/discoveries.go`; the modal + Import-all control + success banner in
  `internal/ui/templates/discoveries.html`. Audited via the existing `subnet.created` /
  `scan.discovery.imported` events (so they also fan out to change webhooks). See ADR 0026.

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

On native-Linux Docker hosts the cert keys (`0600`, operator-owned) are unreadable
to the `cap_drop: ALL` containers (no `CAP_DAC_OVERRIDE`), so the agent used to
crash on boot (`read server key … permission denied`) and the app logged `scanner
dispatch disabled` — macOS/Docker Desktop masks this. Fixed seamlessly by a one-shot
`cert-perms` compose service running `deploy/fix-cert-perms.sh` before app/agent
(chowns `agent.key`→root, `app.key`→the app's pinned uid 100, keeps `0600`,
re-runs every `up` so it self-heals after cert regen, no-op when certs absent). The
app uid/gid are pinned in `Dockerfile`. Manual fallback: `./deploy/fix-cert-perms.sh`.
See ADR 0025 and `docs/SCANNER_AGENT.md` "Certificate file ownership on Linux".

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
- **Phase 6 (Advanced Automation) — COMPLETE.** All five slices merged: (a) **Policy /
  Health checks** (ADR 0020), (b) **Scheduled scan windows** (ADR 0021, migration 18),
  (c) **Change webhooks** (ADR 0022, migration 19), (d) **NetBox-compatible import/export**
  (ADR 0023, no schema change), and (e) **Machine API + CLI** (ADR 0024, migration 20) —
  see the sections above. A Terraform **provider** could be a future increment against the
  now-stable `/api/v1` (the CLI is the reference client); confirm with the user before any
  new phase.
- **Settings panel build-out.** The Settings page is the product's configuration
  surface; `docs/SETTINGS.md` is the canonical plan. **Done** tabs: Security, Users &
  Roles, Authentication, Agent certificates, Backup & Restore, Custom fields, **Policy**,
  **Notifications** (change webhooks, ADR 0022). **Still planned**: General,
  Scanning/nmap, Discovery, and richer Data & Audit — each can land independently. The
  **agent-secret boundary** holds (SNMP communities, nmap egress pinning, DHCP lease
  paths, agent allowlist stay on the agent — never the app DB or the panel).

When starting new work, branch from `main`, and confirm with the user which item to
pick up (the backlog file no longer drives the order). Phases 1–5 are done and
**Phase 6 (Advanced Automation) is complete** (all five slices (a)–(e) merged) — see
`docs/ROADMAP.md`. The next phase is open; confirm direction with the user.
