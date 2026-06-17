# Roadmap

## Phase 1: Manual IPAM MVP

- Authentication, sessions, and admin bootstrap.
- Default site, optional VLAN metadata, subnets, and sparse address records.
- Address status workflow: available, reserved, assigned, deprecated, conflict.
- Devices, MAC addresses, private MAC tagging, basic OUI vendor matching, tags, and custom fields.
- Subnet utilization and address grid.
- Address editing, navigation shell, dashboard widgets, empty states, and confirmation flows.
- Dashboard with global search, subnet widgets, review widget, recent changes, and scan status.
- Bulk edit and import/export foundation. *(Done in Phase 4.5 — see "Carried forward from earlier phases" below.)*
- Audit log.

## Phase 2: Scanner Agent Foundation

- Scanner agent registration.
- App-to-agent mTLS.
- Allowed scan scopes.
- Manual and scheduled scan jobs.
- Immutable scan audit trail.
- Optional review mode for detected changes.

## Phase 3: Nmap Discovery MVP — complete

- ICMP and TCP host discovery. ✅
- Nmap-backed OS and service detection. ✅
- Findings review queue (`/discoveries`). ✅
- Last-seen tracking on managed addresses. ✅
- Conflict detection: discoveries are reconciled against managed records and
  flagged new/match/conflict (changed MAC, deprecated-but-responding, MAC seen
  on another address). ✅

Follow-ups merged on top of Phase 3 (#18):

- Per-agent auto-import for trusted agents (`scan_agents.auto_import`); conflicts
  always stay in the review queue. ✅
- Structured scan-result detail UI (per-host services/OS/evidence). ✅

## Phase 4: Network Context

- SNMP ARP-table harvesting (**done**, ADR 0006). The `arp_table` scan type
  queries a gateway/L3 device's `ipNetToMediaTable` over SNMP to recover IP↔MAC
  bindings for subnets the agent cannot reach at Layer 2. Unprivileged (UDP/161,
  no `NET_RAW`); reuses the discovery review-queue + reconciliation pattern.
- SNMP device inventory (**done**, ADR 0007). The `snmp_inventory` scan type reads
  a device's system group (name, OS, location) and its interface/IP tables to
  recover the device's own identity and the MACs of its interfaces.
- Combined all-sources scan + scan-experience polish (**done**, ADRs 0008/0009):
  one `combined` job runs deep nmap + ARP + SNMP inventory, merged per host, with
  unreachable SNMP ignored not failed; simplified Light/Standard/Deep modes;
  staged nmap (host discovery → service/OS on live hosts only); and dynamic,
  generous per-type scan timeouts.
- NetBIOS and mDNS/Bonjour hostname resolution (**done**, ADR 0010). The
  `name_lookup` scan type asks a host directly for its name over NetBIOS (UDP/137)
  and unicast mDNS (UDP/5353), recovering names for SMB, Apple, and IoT devices
  with no DNS PTR record; NetBIOS works across subnets. Folded into the `combined`
  scan as a best-effort enrichment pass. Unprivileged unicast UDP, no new
  dependency; reuses the discovery review-queue + reconciliation, in the agent.
- LLDP/CDP neighbor ingestion (**done**, ADR 0011). The `lldp_cdp` scan type reads
  a switch/router's LLDP (`lldpRemTable` + `lldpRemManAddrTable`) and CDP
  (`cdpCacheTable`) neighbor caches over SNMP to map physical topology — which
  devices are wired to which ports. Targets are the switch/router IPs; each neighbor
  with a management address becomes an IP-keyed observation (name, platform/OS, and
  an LLDP MAC-typed chassis id). Unprivileged (UDP/161, no `NET_RAW`); folded into
  the `combined` scan; reuses the discovery review-queue + reconciliation, in the
  agent.
- DNS forward/reverse enrichment (**done**, ADR 0012). The `dns_lookup` scan type
  resolves each host's name from the network's authoritative DNS (reverse PTR) and
  forward-confirms it, naming managed hosts that already have a DNS record and
  flagging a stale/mismatched PTR. Unprivileged UDP/TCP/53; folded into `combined`;
  reuses the discovery review-queue + reconciliation, in the agent.
- VLAN and interface mapping (**done**, ADR 0013). The `snmp_inventory` scan now
  reads each interface's 802.1Q access VLAN (Q-BRIDGE-MIB `dot1qPvid`, joined to the
  interface through the bridge-port table) and operational status, mapping a host's
  IP → interface → VLAN. A discovered VLAN backfills the containing subnet's VLAN
  when it has none (never overwriting an operator value), so the mapping reaches the
  Subnets and Devices pages. Unprivileged (UDP/161), no new scan type.
- DHCP lease ingestion (**done**, ADR 0014). The `dhcp_leases` scan type reads the
  DHCP server's lease file (ISC dhcpd or dnsmasq, mounted read-only on the agent) for
  the authoritative IP↔MAC binding and client-supplied hostname of each active lease.
  Opt-in and never fatal (an unconfigured file is a clear notice / muted Skipped
  line); folded into `combined`; reuses the discovery review-queue + reconciliation,
  in the agent.

**Phase 4 is complete.** The six Network-Context sources — SNMP ARP (`arp_table`),
SNMP inventory + VLAN/interface (`snmp_inventory`), NetBIOS/mDNS names
(`name_lookup`), DNS names (`dns_lookup`), DHCP leases (`dhcp_leases`), and LLDP/CDP
neighbors (`lldp_cdp`) — all merge per host through one review/import path, and a
single `combined` scan runs them all. The combined scan **enriches the hosts nmap
discovers** (ADR 0015): it expands a CIDR through the deep nmap stage, then runs the
per-host SNMP/name/DNS passes against the live hosts (concurrently, with an SNMP
short-circuit and collapsed skip-notices), so a combined scan of a CIDR recovers
MACs and SNMP inventory instead of degrading to nmap-only.

## Carried forward from earlier phases

A full audit (2026-06-17) found these items scoped to earlier phases that were not
yet built. They are unblocked (the data model is stable) and tracked here so they
are not lost between phases:

- **Bulk edit + CSV import/export (done, Phase 4.5).** Listed under Phase 1 and in
  `docs/MVP.md` ("Bulk edit and import/export should be available in the UI early")
  and backlog #4. Now built: multi-select bulk status/field/tag/delete on the
  Subnets/Addresses/Devices tables (JS-off + JS-on, audited, destructive actions
  through `confirm.html`), and CSV import/export of subnets, addresses, and devices —
  export columns match the forms, import validates **every** row against the same
  IPv4/overlap/sparse/state rules, shows a dry-run preview with per-row errors, and
  applies all-or-nothing in one transaction on confirm. The basic CSV on-ramp,
  distinct from the Phase 6 NetBox-compatible format. See ADR 0016.
- **Dashboard live widgets (done, 2026-06-17).** The Phase 1 "review widget" and
  "scan status" dashboard panels shipped as static placeholders (the scan panel still
  read "planned for Phase 2"). They are now wired to live data: the review queue shows
  the real pending-discovery count and links to `/discoveries`, and scan status lists
  recent jobs with their status badges.

## Phase 5: Production Hardening

Goal: make Light IPAM safe to run as the system of record in a real small-business or
enterprise environment — hardening identity, secrets, the certificate lifecycle, and
data durability. Keep the web app unprivileged; keep all elevated scan capability in
the agent.

### Identity & access

- **OIDC SSO** (authorization-code + PKCE) as an optional alternative/addition to
  local login; map the OIDC subject to a Light IPAM user.
- **MFA (TOTP)** for local accounts, with recovery codes. The auth design already
  leaves room for this (`docs/MVP.md`).
- **Roles beyond the single admin** — at minimum admin vs. read-only operator, so a
  viewer cannot mutate IPAM or scan config.
- **Session hardening** — configurable idle/absolute timeouts, "log out everywhere,"
  and login rate-limiting / lockout.

### Secrets & certificates

- **Managed agent certificate issuance + rotation**, replacing the hand-run dev CA
  (`cmd/scanner-certs`): app-issued short-lived agent certs that auto-renew before
  expiry, with revocation (short TTLs or a CRL). Today the dev CA never rotates.
- **Encrypted secrets at rest** — SNMP communities, the OIDC client secret, and DB
  credentials sealed with a key from env/KMS rather than stored or passed in plaintext.
- **Rotation for the app's own keys** (session/CSRF signing keys) with a documented
  runbook.

### Data durability & operations

- **Backup & restore** — a documented `pg_dump`/`pg_restore` flow plus an
  app/CLI-triggered backup and a tested restore path; capture the schema-migration
  version with each backup.
- **Readiness/health depth** — extend `/healthz` (or add `/readyz`) to report DB
  reachability, applied-migration status, and agent reachability for orchestration.
- **Disaster-recovery runbook** covering compose, volumes, and certificates.

### Multi-tenancy (only if needed)

- Organization/tenant separation of IPAM data, users, and agents — deferred unless a
  deployment requires it.

**Exit criteria:** an operator can stand up Light IPAM with SSO + MFA, agents that
rotate their own certificates, secrets that are never stored in plaintext, and a
tested backup/restore path.

## Phase 6: Advanced Automation

- Scheduled scan windows.
- Change webhooks.
- NetBox-compatible import/export.
- Terraform provider or CLI.
- Policy checks for overlapping subnets, stale records, and unmanaged services.
