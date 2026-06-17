# Light IPAM Agent Guide

This file is for AI coding agents working on Light IPAM. It captures the current state, implementation patterns, and next priorities so future work can continue without rediscovering project context.

## Product

Light IPAM is a lightweight IP address management system for small business through enterprise use. The deployment target is Docker Compose on one Docker host for the initial release. The long-term architecture keeps the web app unprivileged and puts privileged active network discovery into a separate scanner-agent container.

## Current State

Phase 1 manual IPAM foundation is merged to `main`, as are scanner Phases 2, 3, and
4 (all complete) — see "Current State of the Scanner Track" below for discovery.

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
  (`columns.js` selectable table columns, `scan_form.js` dynamic scan form); no
  inline JS, strict CSP.
- `internal/scanner` + `cmd/scanner-agent` + `cmd/scanner-certs`: the scanner
  protocol, agent, app-side dispatch/orchestrator, and dev PKI (see "Scanner
  Components").
- `docs`: product, architecture, roadmap, backlog, ADRs.

## Stack

- Language: Go.
- Web: server-rendered HTML templates.
- Styling: Tailwind CSS.
- Database: PostgreSQL.
- Auth: local admin account for MVP.
- Deployment: Docker Compose.
- GitHub: issues and PRs are tracked in `devSealWare/LightIPAM`.

## Development Commands

```sh
npm run build:css
go test ./...
docker compose build
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
  (import/dismiss), `/search`, and `/static/scan_form.js` (+ `/static/columns.js`).
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

No issue is in progress. Phases 1–4 are complete. Remaining candidate work, roughly
in priority order:

- **Carried forward from earlier phases:** bulk edit + CSV import/export for the
  manual-IPAM UI (Phase 1 / `docs/MVP.md` / backlog #4 scope, never built). The data
  model is stable, so it is unblocked. See `docs/ROADMAP.md` "Carried forward."
- **Phase 5 (Production Hardening):** managed agent cert issuance/rotation (replacing
  the dev CA), OIDC SSO, MFA (TOTP), roles beyond the single admin, encrypted secrets
  at rest, and backup/restore. See `docs/ROADMAP.md` "Phase 5" for the broken-out
  scope and exit criteria.
- **Optional Phase 4 polish:** tagged/trunk VLAN membership (only access PVID is
  mapped today), per-interface speed/alias, and an SNMP/API-based DHCP source for
  appliances with no lease file.

Known limitations to be aware of (see README "Limitations"): the SNMP, NetBIOS/mDNS,
DNS, and DHCP backends are unverified against real hardware; IPv4 only; the dev CA
has no rotation; single admin role, no MFA/OIDC; no backup/restore yet; no CSV/bulk
import-export in the UI yet.

Branch from `main` and confirm the next item with the user before starting.
