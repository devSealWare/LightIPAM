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
- **Custom fields (done, Phase 5 audit, ADR 0019).** A Phase 1–5 audit (2026-06-19)
  found custom fields — listed under Phase 1 and in backlog #2/#5 — claimed merged but
  never actually built: the `custom_fields`/`custom_field_values` tables existed
  (migration 1) but no code or UI used them. Now built: an admin **Custom fields**
  Settings tab defines text fields per entity type (subnet/address/device), and each
  entity's form/detail page edits and shows the values (sparse storage, audited,
  zero-impact until a field is defined). No schema change. See ADR 0019.

## Phase 5: Production Hardening

Goal: make Light IPAM safe to run as the system of record in a real small-business or
enterprise environment — hardening identity, secrets, the certificate lifecycle, and
data durability. Keep the web app unprivileged; keep all elevated scan capability in
the agent.

### Identity & access

- **OIDC SSO (done, ADR 0018).** Authorization-code + PKCE via `go-oidc`/`oauth2`;
  state/PKCE/nonce in a sealed cookie, ID-token + nonce verified. `users.oidc_subject`
  (migration 16) binds the IdP subject to a local user; login resolves by subject, then
  username (linking), then optionally auto-provisions a read-only viewer. Configured on
  the admin **Authentication** settings tab with the client secret sealed at rest.
- **MFA (TOTP) (done, ADR 0018).** RFC 6238 TOTP (stdlib, RFC-vector tested) with
  single-use recovery codes; the per-user secret is sealed at rest (migration 15). Login
  gains a signed pending-MFA second step; self-service enrollment (QR + manual key),
  recovery-code display, and disable live on the `/account` page.
- **Roles beyond the single admin (done, ADR 0018).** `users.role` admin vs. read-only
  viewer (migration 14); a central middleware blocks viewers from all mutations, the
  Settings area is admin-only, and a **Users & Roles** tab manages accounts.
- **Session hardening (done, ADR 0017).** Idle **and** absolute session timeouts,
  per-session client IP + User-Agent capture, a tabbed **Settings page** (Security
  tab) listing active sessions with a "log out everywhere" control, and login
  throttling / account lockout (`login_attempts`, migration 12) keyed by username and
  client IP with a pure, unit-tested lock decision. All of this policy — lockout
  thresholds, session timeouts, and whether "log out everywhere" keeps the current
  device — is **editable at runtime** from the Settings page (persisted in
  `app_settings`, migration 13; env provides the boot defaults). The
  username-enumeration timing oracle in the login handler is closed with a decoy
  Argon2 verify. New auth audit events (`auth.login.failed`, `auth.login.locked`,
  `session.revoked_all`, `settings.security.updated`).

### Configurability & the settings panel

Light IPAM should be **highly configurable from the UI**, not just from environment
variables. The tabbed **Settings** page introduced with session hardening (ADR 0017)
is the home for that, backed by the runtime `app_settings` store (env values seed the
boot defaults). The **Security** tab is done; the rest below are planned. Each
runtime-tunable tab follows the same pattern — a pure, unit-tested form validator,
values cached and refreshed on save, and an audited `settings.<tab>.updated` event.
The full design, the per-tab field list, and the **agent-secret boundary** (SNMP
communities, nmap egress pinning, DHCP lease paths, and the agent allowlist stay on
the agent, never in the app DB or this panel) live in **`docs/SETTINGS.md`**.

Planned tabs (sequenced with the phases that unlock them):

- **Security** — login lockout, session timeouts, "log out everywhere" behavior,
  active-session review. **Done** (ADR 0017). Future fields: password policy,
  secure-cookie enforcement, MFA/OIDC toggles.
- **General** — instance name, default site, table page size, date/time format,
  default theme.
- **Users & Roles** — manage accounts and admin vs. read-only operator (this phase's
  "roles beyond the single admin" item).
- **Authentication** — OIDC SSO and MFA (TOTP) configuration (this phase's SSO/MFA
  items); the OIDC client secret is sealed (encrypted at rest).
- **Scanning (nmap)** — app-side scan **dispatch defaults**: default scan type/mode,
  per-type timeouts, optional nmap rate/timing cap, default targets/allowlist, and the
  scheduler tick. Agent-local nmap/SNMP/DHCP credentials and raw-socket config stay on
  the agent.
- **Discovery** — auto-import policy, reconciliation/conflict handling, and
  review-queue + last-seen retention.
- **Agents** — enrollment defaults and managed certificate issuance/rotation (this
  phase's cert-lifecycle item); the `/agents` page exists today.
- **Backup & Restore** — trigger/schedule `pg_dump`, run a tested restore, capture the
  migration version (this phase's backup/restore item).
- **Notifications** — change webhooks (**done**, ADR 0022) and, later, alert
  thresholds. Outbound HMAC-signed JSON to subscribed endpoints, driven by the audit
  log as the change feed.
- **Custom fields** — define operator-managed text attributes per entity type
  (subnet/address/device), edited on each record's form. **Done** (ADR 0019).
- **Data & Audit** — audit-log retention/export and the CSV / NetBox import-export
  entry points (CSV import/export already exists).

### Secrets & certificates

- **Managed agent certificate issuance + rotation (done, ADR 0018).** The app owns a CA
  (private key sealed at rest, migration 17) that signs short-lived agent/app mTLS
  leaves, replacing the hand-run dev CA as the issuing authority. The **Agent
  certificates** settings tab issues downloadable bundles (configurable CN/SANs/TTL),
  downloads the CA, and rotates the CA; the scanner agent hot-reloads a rotated cert
  without a restart. Revocation relies on short TTLs (the accepted alternative to a CRL).
  *Follow-up: online agent-pull enrollment so an agent renews its own cert over a
  bootstrap channel without operator file deployment.*
- **Encrypted secrets at rest (done, ADR 0018).** `internal/secret` seals the TOTP
  secret, the OIDC client secret, and the managed-CA key with AES-256-GCM
  (`APP_ENCRYPTION_KEY`, or derived from `APP_SECRET`). SNMP communities remain
  **agent-local** by design and never reach the app DB.
- **Rotation for the app's own keys** — documented in `docs/KEY_ROTATION.md`
  (`APP_SECRET`, `APP_ENCRYPTION_KEY`, managed CA, and leaf certs).

### Data durability & operations

- **Backup & restore (done, ADR 0018).** `internal/backup` takes on-demand `pg_dump`
  (custom-format) snapshots into `BACKUP_DIR`, each filename capturing the schema-
  migration version. The admin **Backup & Restore** tab creates/lists/downloads/deletes
  them; restore is documented and scripted (`docs/BACKUP_RESTORE.md`,
  `deploy/restore.sh`) with migrations rolling an older dump forward on boot. The app
  image bundles `postgresql16-client` and keeps zero Linux capabilities.
- **Readiness/health depth (done, ADR 0017).** `/healthz` stays the liveness probe;
  `/readyz` is added to ping the DB and report the applied-migration version (503 when
  the DB is unreachable), and the app compose service health-checks it. Agent
  reachability in the probe remains a future enhancement.
- **Disaster-recovery runbook (done).** `docs/DISASTER_RECOVERY.md` covers compose,
  volumes (`pgdata`/`backups`), secrets, and scanner-agent certificates.

### Multi-tenancy (only if needed)

- Organization/tenant separation of IPAM data, users, and agents — deferred unless a
  deployment requires it.

**Exit criteria — met (ADRs 0017 + 0018).** An operator can stand up Light IPAM with
SSO + MFA, a managed CA that issues short-lived agent certs which the agent hot-reloads
on rotation, secrets sealed at rest, and a tested backup/restore path — on top of
admin/viewer roles, login throttling, session hardening, and a runtime-editable
Settings panel. The one explicitly-deferred increment is **online agent-pull
certificate enrollment** (the agent renewing its own cert over a bootstrap channel);
today the managed CA issues and the agent hot-reloads operator-deployed certs. Phase 5
is complete enough to begin **Phase 6**.

## Phase 6: Advanced Automation

- **Policy checks (done, ADR 0020).** A read-only **Policy / Health** view (`/policy`)
  that runs hygiene checks on demand: overlapping subnets (an invariant verifier — the
  create/import paths already block overlaps), stale managed addresses/devices not seen
  within a configurable threshold (device staleness derived from linked addresses'
  `last_seen_at`, so no schema change), and unmanaged/conflicting discovered services
  (reusing the `scan_discoveries` reconcile classification). Pure, unit-tested check
  functions over store snapshots; findings grouped by severity and linked to the
  offending record; a dashboard count widget; and a runtime-editable **Policy** Settings
  tab (enable/disable each check, stale threshold, include-never-seen) following the
  `app_settings` pattern. App-side only, no new privilege, no client JS, no migration.
- **Scheduled scan windows (done, ADR 0021).** A schedule may restrict firing to a
  window — a time-of-day range plus a weekday set, read in the schedule's own IANA
  timezone — layered on top of the existing interval cadence. A due schedule outside
  its window is skipped that tick and re-checked on the next one (`next_run_at` is not
  advanced), so it fires once the window opens. The decision is a pure, unit-tested
  `windowAllows` (handles midnight-wrap, no-time/no-day, and the empty-window =
  always-allowed back-compat case); migration 18 adds `window_start_min` /
  `window_end_min` (minutes since midnight, NULL = no restriction), `window_days`
  (0=Sun..6=Sat, empty = any day), and `window_tz` (default UTC). The schedule form
  gains native time/day/timezone fields (no client JS) and the schedules table shows
  the window. `cmd/server` embeds `time/tzdata` so zone lookups work on the Alpine
  image. Per-schedule config, no Settings tab, no new privilege.
- **Change webhooks (done, ADR 0022).** An admin registers outbound webhook endpoints
  on a **Notifications** settings tab; the app POSTs an HMAC-signed JSON payload to each
  enabled, subscribed endpoint when a matching change is audited. The audit log is the
  change feed — a single mutex-guarded `store` audit hook (on both store instances) fans
  events out via `internal/webhook`, with a pure `categoryForAction` mapping audited
  actions to subscribable categories (ipam / discovery / scan / security). Delivery is
  asynchronous and gated to a no-op when no webhook is enabled; each attempt is recorded
  in a bounded `webhook_deliveries` log (migration 19 adds `webhooks` + that log). The
  per-webhook signing secret is sealed at rest (`internal/secret`); pure
  `parseWebhookForm`/`categoryForAction`/`sign` are unit-tested and an httptest test
  covers the real POST + signature. App-side only, no new privilege, no client JS.
- **NetBox-compatible import/export (done, ADR 0023).** A **NetBox** CSV format
  alongside the native one: a per-type format selector + Export NetBox links. A NetBox
  upload is a **pure, unit-tested translation** (`translateNetBoxImport`) into the
  canonical Light IPAM columns, so it reuses the exact same dry-run preview, validators,
  and all-or-nothing transactional apply — no second pipeline. Exports emit NetBox
  column names (prefixes / IP addresses / devices) with values mapped back. The model
  edges that don't align (prefix has no name, devices need role/type/site) are
  documented and lossy by design; the IPAM core round-trips. See `docs/NETBOX.md`. No
  schema change, no new privilege, no client JS.
- **Machine API + CLI (done, ADR 0024).** A token-authenticated JSON API under
  `/api/v1` (subnets, addresses, devices CRUD + `whoami`) and a stdlib-only
  `lightipam-cli` that consumes it. Per-user **bearer API tokens** (migration 20, SHA-256
  hashed, shown once, self-service on the Account page) carry the owner's role, so the
  existing admin/viewer authorization applies: reads need any valid token, writes need an
  admin token. The API reuses the existing store methods + validation, is audited, and
  fans out to change webhooks like the UI. The user chose a CLI over a Terraform provider
  (lightweight, in-repo, no heavy dependency); a provider can be added later against the
  same stable API. See `docs/API.md`. No client JS, app stays unprivileged.

**Phase 6 (Advanced Automation) is complete.** Policy/health checks (ADR 0020),
scheduled scan windows (ADR 0021), change webhooks (ADR 0022), NetBox-compatible
import/export (ADR 0023), and the machine API + CLI (ADR 0024) are all merged.

## Discovery UX follow-up

- **Subnet auto-create on import + "Import all" (done, ADR 0026).** Importing a
  discovered host with no managed subnet opens a server-rendered, pure-CSS modal
  pre-filled with the exact network the scan targeted (the containing scan-job target
  CIDR, falling back to a `/24` only for a bare-IP scan) and the scanned VLAN; on save
  the subnet is created and the import resumes. An **Import all** control imports the
  whole pending, non-conflicting `/discoveries` queue in one click, grouping any missing
  subnets by their suggested network and prompting for each (re-checking until none remain) before
  importing everything. App-side only, no migration, no new privilege; reuses the
  existing `CreateSubnet` + `ImportDiscovery` paths and their audit events.

## Planned

- **Routing-aware scanner egress + scan diagnostics (planned, ADR 0027).** A field
  report showed that a macvlan scanner (which pins every nmap probe to the macvlan
  source IP) silently finds **zero hosts** when pointed at a *routed* subnet, because
  the source pin and the kernel route disagree — the scan returns `succeeded` with no
  observations. The plan makes egress **routing-aware by default**: a new
  `AGENT_SCAN_PIN_MODE` (default `auto`) pins a target only when it is L2-adjacent to
  the scan source interface and lets routed targets follow the default route, so one
  macvlan agent handles same-subnet *and* routed scans **with no operator config
  change** (`always` restores the old unconditional pin; `off` disables it). Alongside:
  self-explaining zero-host/mismatch notices, an agent `GET /diagnostics` view surfaced
  on `/agents/{id}`, classified app→agent dispatch errors (DNS / TCP / TLS / HTTP — the
  confusing `lookup scanner-agent ... no such host` becomes "container not running"), a
  `scanner-agent --healthcheck` + Compose healthcheck, and docs (bridge-vs-macvlan
  decision matrix, troubleshooting, a one-scanner-per-VLAN example). The no-code docs
  safety net (macvlan routed-subnet warning, decision matrix, troubleshooting) ships
  with the ADR; the behavioral changes are sequenced in ADR 0027. App stays unprivileged,
  no client JS, no new mandatory dependency, no migration.
