# Light IPAM Agent Guide

This file is for AI coding agents working on Light IPAM. It captures the current state, implementation patterns, and next priorities so future work can continue without rediscovering project context.

## Product

Light IPAM is a lightweight IP address management system for small business through enterprise use. The deployment target is Docker Compose on one Docker host for the initial release. The long-term architecture keeps the web app unprivileged and puts privileged active network discovery into a separate scanner-agent container.

## Current State

**Phases 1-6 are all complete** and merged to `main` (migrations 1-20). Phase 1
(manual IPAM), scanner Phases 2-4 (foundation + nmap MVP + Network Context — see
"Current State of the Scanner Track" below), Phase 4.5 (bulk edit + CSV), Phase 5
(Production Hardening), and Phase 6 (Advanced Automation) are done. The next phase is
open; confirm direction with the user before starting.

Implemented (manual IPAM):

- Go backend with `net/http`.
- PostgreSQL via `pgx`.
- Embedded Go migrations.
- Tailwind CSS via npm.
- Docker multi-stage build.
- Docker Compose app and PostgreSQL services.
- First-admin web bootstrap.
- Local login/logout.
- Argon2id password hashing.
- Session cookies and CSRF checks.
- Security headers.
- Default site migration.
- Optional VLAN metadata on subnets.
- Global subnet overlap blocking.
- IPv4-only subnet/address validation, including `/31` and `/32`.
- Sparse address records only: touched/reserved/assigned/deprecated/conflict/discovered records are stored.
- Subnet CRUD.
- Address create/edit/delete.
- Device CRUD.
- MAC address tracking.
- Address-to-device assignment.
- Locally administered unicast MAC detection for private/rotating MACs.
- Automatic `Private MAC` tagging.
- Small built-in OUI vendor matcher for MVP.
- Immutable audit logs with UI filters.
- Database triggers preventing audit log update/delete.
- Navigation shell/sidebar.
- Confirmation pages for destructive actions.
- Multi-select bulk edit (status/VLAN/tag/clear-device/delete) on the Subnets,
  Addresses, and Devices tables (Phase 4.5, ADR 0016).
- Basic CSV import/export of subnets, addresses, and devices with a validated
  dry-run preview and all-or-nothing transactional apply (Phase 4.5, ADR 0016).
- Operator-defined custom fields (text) per entity type, managed on an admin
  **Custom fields** Settings tab and edited/shown on each subnet/address/device
  (sparse, audited; schema from migration 1). Phase 5 audit, ADR 0019.

Implemented (Phase 5 — Production Hardening, ADRs 0017/0018):

- Login throttling + account lockout (`login_attempts`, migration 12), idle +
  absolute session timeouts with per-session IP/User-Agent capture, active-session
  review + "log out everywhere", all auth/session policy editable at runtime
  (`app_settings`, migration 13), and a `/readyz` readiness probe.
- Admin vs. read-only **viewer roles** (migration 14, central authorize
  middleware), **TOTP MFA** with recovery codes (migration 15, sealed secret),
  **OIDC SSO** (auth-code + PKCE, sealed client secret, migration 16).
- **Encrypted secrets at rest** (`internal/secret`, AES-256-GCM), **pg_dump
  backup/restore** (`internal/backup` + Backup tab), and an **app-managed CA**
  (migration 17) issuing/rotating short-lived agent mTLS certs (agent hot-reload).
- A tabbed **Settings** page (Security, Users & Roles, Authentication, Agent
  certificates, Backup & Restore, Custom fields, Policy, Notifications) and a
  per-user `/account` page.

Implemented (Phase 6 — Advanced Automation, ADRs 0020-0024):

- **Policy / Health checks** (`/policy`, ADR 0020): overlapping subnets, stale
  records, unmanaged/conflicting discovered services; pure check functions over
  store snapshots, a dashboard widget, and a runtime-editable Policy Settings tab.
- **Scheduled scan windows** (migration 18, ADR 0021): a schedule may restrict
  firing to a time-of-day + weekday window in its own IANA timezone.
- **Change webhooks** (migration 19, ADR 0022): HMAC-signed JSON to subscribed
  endpoints, driven by the audit log via a `store.SetAuditHook` and
  `internal/webhook`; signing secret sealed at rest.
- **NetBox-compatible import/export** (ADR 0023): a pure translation into the
  canonical columns reusing the existing validators/preview/apply, plus NetBox
  exports.
- **Machine API + CLI** (migration 20, ADR 0024): a token-authenticated JSON API
  under `/api/v1` (`internal/app/api.go`) and a stdlib-only `cmd/lightipam-cli`;
  per-user bearer tokens carry the owner's role.

## Repository Structure

- `cmd/server/main.go`: process entrypoint, config load, database connect/migrate, HTTP server lifecycle.
- `internal/app`: HTTP routes, handlers, form parsing, auth/session checks.
- `internal/auth`: password hashing and random token helpers.
- `internal/config`: environment-driven config.
- `internal/db`: PostgreSQL connection and embedded migrations.
- `internal/ipam`: IPv4/CIDR parsing and utility functions.
- `internal/macaddr`: MAC normalization, private MAC detection, vendor matching.
- `internal/store`: database query layer.
- `internal/ui`: embedded templates and static assets (CSS + progressive-
  enhancement JS).
- `internal/ui/assets/app.css`: Tailwind source.
- `internal/ui/static/app.css`: generated CSS committed for embedding.
- `internal/ui/static/*.js`: same-origin progressive-enhancement scripts
  (`columns.js` selectable table columns, `scan_form.js` dynamic scan form,
  `bulk.js` multi-select bulk edit); no inline JS, strict CSP.
- `internal/auth`: password hashing (Argon2id), random/API-token helpers, and TOTP.
- `internal/secret`: AES-256-GCM sealing of small secrets (OIDC/TOTP/CA/webhook).
- `internal/backup`: on-demand `pg_dump` snapshot/restore helpers.
- `internal/webhook`: change-webhook dispatcher fed by the audit hook.
- `internal/scanner` + `cmd/scanner-agent` + `cmd/scanner-certs`: the scanner
  protocol, agent, app-side dispatch/orchestrator, and PKI (managed CA + dev certs;
  see "Scanner Components").
- `cmd/lightipam-cli`: stdlib-only CLI client for the `/api/v1` machine API.
- `docs`: product, architecture, roadmap, backlog, ADRs.

## Stack

- Language: Go.
- Web: server-rendered HTML templates.
- Styling: Tailwind CSS.
- Database: PostgreSQL.
- Auth: local accounts (admin/viewer roles), TOTP MFA, and OIDC SSO.
- Deployment: Docker Compose.
- GitHub: issues and PRs are tracked in `devSealWare/LightIPAM`.

## Development Commands

```sh
npm run build:css
go test ./...
gofmt -l internal cmd
docker compose build
docker compose --profile scanner build
docker compose up -d
docker compose exec app wget -qO- http://127.0.0.1:8080/healthz
```

If Go cache access is blocked in a sandbox, rerun tests with the normal Go build cache permission.

## Design Rules

- Keep the app container unprivileged.
- Do not put raw packet or privileged scanning behavior in the web app.
- Scanner functionality belongs in a separate agent process/container.
- Keep address storage sparse; do not materialize every IP in every subnet.
- Block overlapping subnets globally for MVP.
- Keep audit logs append-only.
- Prefer simple server-rendered flows until a workflow clearly needs HTMX or targeted JavaScript.
- Keep Tailwind classes readable and avoid turning the app into a heavy SPA.

## Scanner Components

- `internal/scanner`: versioned protocol types and allowlist validation
  (issue #7). `ValidateJobForAgent` is the app-side check; `ValidateAgentScope`
  is the agent-side check. `budget.go` holds the shared `ScanBudget` /
  `EstimateTargetHosts` used by both the agent and the app for scan deadlines.
- `internal/scanner/agent`: agent receive/report handler (`GET /healthz`,
  `GET /register`, `POST /jobs`) plus mTLS TLS config builders. Backends:
  `nmap.go` (staged `Discoverer` — host-discovery sweep then service/OS on live
  hosts), `snmp.go` (`arp_table` + `snmp_inventory`, the latter including 802.1Q
  VLAN/interface mapping, over UDP/161), `neighbors.go` (`lldp_cdp` — LLDP/CDP
  neighbor harvesting over UDP/161, methods on the same `SNMPDiscoverer`),
  `names.go` (`name_lookup` — NetBIOS UDP/137 + unicast mDNS UDP/5353), `dns.go`
  (`dns_lookup` — reverse-PTR + forward-confirm over UDP/TCP/53), `dhcp.go`
  (`dhcp_leases` — reads an ISC dhcpd/dnsmasq lease file mounted read-only on the
  agent), `combined.go` (deep nmap that **enriches the hosts it discovers** with
  every passive pass — both SNMP passes, names, DNS, DHCP, LLDP/CDP — merged per
  host, a silent enrichment pass ignored), and `router.go` (`DiscoveryRouter`
  dispatching by scan type). Passive jobs stay no-op.
- `internal/scanner/pki` + `cmd/scanner-certs`: development CA and agent/app
  certificates.
- `cmd/scanner-agent`: the agent process (mTLS HTTPS). Bundles nmap and runs
  with `NET_RAW` only; SNMP, NetBIOS/mDNS, DNS, and DHCP-file reads need no added
  capability. Wires the nmap + SNMP (arp_table/snmp_inventory/lldp_cdp) + names +
  DNS + DHCP + combined backends onto the router.
- `internal/scanner/dispatch`: the app-side mTLS client that POSTs jobs and
  pulls `/register` for enrollment (issues #9/#10).
- `internal/scanner/orchestrator`: app-side coordinator — validate, enqueue,
  dispatch async (deadline from `scanner.ScanBudget`), record lifecycle + audit,
  run the schedule ticker, persist observations as discoveries, auto-import /
  merge-on-rescan onto imported devices, and auto-enroll the bundled agent.
- App routes: `/scans` (+ `/scans/{id}` structured detail), `/agents`
  (+ `/agents/discover`, `/agents/{id}/approve`), `/schedules`, `/discoveries`
  (import/dismiss), `/search`, the manual-IPAM bulk routes (`POST /subnets/bulk`,
  `/addresses/bulk`, `/devices/bulk`) and CSV import/export (`/import`,
  `POST /import/{type}` + `/apply`, `/{subnets,addresses,devices}` `export.csv`),
  and `/static/scan_form.js` (+ `/static/columns.js`, `/static/bulk.js`).
  Migration 5 adds `scan_agents`/`scan_schedules`/`scan_jobs`; migration 6 adds
  `scan_discoveries` (migration 7 adds its reconciliation columns; migration 8
  adds `scan_agents.auto_import`; migration 9 adds discovery-derived inventory
  fields on `devices`; migration 10 carries scanner-reported MAC vendor on
  `scan_discoveries`; migration 11 adds `scan_discoveries.vlan` for VLAN mapping).
- `Dockerfile.scanner` + the `scanner-agent` Compose service (behind the
  `scanner` profile): nmap image, `cap_drop: ALL` + `cap_add: NET_RAW`. The app
  service stays at zero capabilities.

See `docs/SCANNER_AGENT.md`, `docs/SCANNER_PROTOCOL.md`, `docs/SCANNER_DISCOVERY.md`,
and ADRs 0002–0015.

## Current State of the Scanner Track

The initial backlog (issues #1–#10) and **Roadmap Phases 3 and 4 (Network Context)
are complete**. The agent runs real scans routed by type: staged nmap (host discovery
→ service/OS on live hosts only), SNMP `arp_table` harvesting (ADR 0006), SNMP
`snmp_inventory` with 802.1Q VLAN/interface mapping (ADRs 0007/0013), NetBIOS/mDNS
`name_lookup` (ADR 0010), DNS `dns_lookup` reverse/forward enrichment (ADR 0012),
DHCP `dhcp_leases` ingestion (ADR 0014), LLDP/CDP `lldp_cdp` neighbor harvesting
(ADR 0011), and a `combined` scan that runs deep nmap and **enriches the hosts it
discovers** with every passive pass merged per host (ADRs 0008/0015), a silent
enrichment pass ignored not failed. Scan modes are simplified to Light/Standard/Deep,
and scan timeouts are dynamic per-type with a budget shared by the agent and app
(ADR 0009). Successful observations land in the `/discoveries` review queue
(import/dismiss), with per-agent auto-import for trusted agents and merge-on-rescan
onto already-imported devices. Scans run manually or on a schedule (`/schedules`, the
in-process scheduler ticker). Agents enroll by app-pull (auto on boot via
`SCANNER_AGENT_ENDPOINT`, or the `/agents` "Discover" form). The app remains
unprivileged (zero capabilities, no nmap).

## Next

No issue is in progress. **Phases 1-6 are complete** (see `docs/ROADMAP.md`), so the
next phase is open — confirm direction with the user. Remaining candidate work:

- **Terraform provider** against the now-stable `/api/v1` (the `lightipam-cli` is the
  reference client; the user chose a CLI first for ADR 0024).
- **Online agent-pull cert enrollment** — the one explicitly-deferred Phase 5 item:
  the agent renews its own cert over a bootstrap channel instead of operator file
  deployment. (Today the managed CA issues + rotates and the agent hot-reloads.)
- **Optional Phase 4 polish:** tagged/trunk VLAN membership (only access PVID is
  mapped today), per-interface speed/alias, and an SNMP/API-based DHCP source for
  appliances with no lease file.
- **Remaining Settings tabs** (`docs/SETTINGS.md`): General, Scanning (nmap dispatch
  defaults), Discovery, and richer Data & Audit.

Known limitations to be aware of (see README "Limitations"): the SNMP, NetBIOS/mDNS,
DNS, and DHCP backends are unverified against real hardware; IPv4 only; SNMP v2c
only; nmap is TCP-only (no UDP/NSE); DHCP ingestion reads a mounted lease file; and
online agent-pull cert enrollment is not built.

Branch from `main` and confirm the next item with the user before starting.
