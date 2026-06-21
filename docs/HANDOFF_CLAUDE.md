# Handoff Prompt For Claude

Use this prompt to bring Claude or another coding agent up to speed.

```text
You are working in the GitHub repository devSealWare/LightIPAM.

Read CLAUDE.md, AGENTS.md, README.md, docs/ROADMAP.md, docs/SECURITY.md,
docs/ARCHITECTURE.md, docs/SCANNER_DISCOVERY.md, and docs/SCANNER_AGENT.md before
making changes. CLAUDE.md's "Recent work" / "Next" sections are the most current.

Current product:
Light IPAM is a Go/PostgreSQL/Tailwind/Docker Compose IPAM application.
Phases 1-6 are all complete (migrations 1-20).
- Phase 1 (manual IPAM): first-admin bootstrap, local auth, embedded PostgreSQL
  migrations, subnet CRUD, sparse address records, device CRUD, MAC tracking,
  private-MAC tagging, OUI vendor matching, immutable audit logs, dashboard, global
  search, selectable table columns, custom fields, bulk edit + CSV import/export.
- Phases 2-4 (scanner foundation + nmap discovery MVP + Network Context): the
  optional scanner-agent runs staged nmap (host discovery -> service/OS on live
  hosts), SNMP arp_table/snmp_inventory (with 802.1Q VLAN)/lldp_cdp, NetBIOS/mDNS
  name_lookup, dns_lookup, dhcp_leases, and a combined all-sources scan that
  enriches the hosts nmap discovers; observations flow through the /discoveries
  review queue with reconciliation, per-agent auto-import, and merge-on-rescan.
- Phase 5 (Production Hardening): admin/viewer roles, TOTP MFA, OIDC SSO, encrypted
  secrets at rest, an app-managed CA with rotation (agent hot-reload), pg_dump
  backup/restore, login throttling/lockout, session hardening, and a
  runtime-editable Settings panel.
- Phase 6 (Advanced Automation): policy/health checks, scheduled scan windows,
  change webhooks, NetBox-compatible import/export, and a token-authenticated
  machine API (/api/v1) + lightipam-cli.
See ADRs 0001-0024.

Architecture rule (do not violate):
The web app must stay unprivileged — no raw sockets, nmap, packet capture, or
trunked-network scanning in the app container. All privileged/active discovery
lives in the scanner-agent only; nmap (NET_RAW) is confined there, and SNMP is
plain UDP/161 with no added capability.

Implementation style:
Go standard library net/http routing, pgx for PostgreSQL, embedded migrations in
internal/db/migrations.go, store methods in internal/store, handlers in
internal/app, templates in internal/ui/templates, Tailwind source in
internal/ui/assets/app.css (generated to internal/ui/static/app.css). No large
frameworks; strict CSP with no inline JS (same-origin static scripts only).

Working agreement:
Branch from main, implement, verify, open a PR via gh, and stop — the user says
when to merge. Confirm which item to pick up before starting; the backlog file no
longer drives the order (use ROADMAP.md / the "Next" sections).

Verification:
- npm run build:css
- go test ./...
- gofmt -l internal cmd
- docker compose build && docker compose --profile scanner build
- docker compose up -d
- docker compose exec app wget -qO- http://127.0.0.1:8080/healthz

Candidate next work (confirm with the user — Phases 1-6 are done, so the next
phase is open):
- A Terraform provider against the now-stable /api/v1 (the CLI is the reference
  client).
- Online agent-pull cert enrollment (the one explicitly-deferred Phase 5 item):
  the agent renews its own cert over a bootstrap channel instead of operator file
  deployment.
- Optional Phase 4 polish: tagged/trunk VLAN membership (only access PVID is mapped
  today), per-interface speed/alias, and an SNMP/API-based DHCP source for
  appliances with no lease file.
- Remaining Settings tabs: General, Scanning (nmap dispatch defaults), Discovery,
  and richer Data & Audit (see docs/SETTINGS.md).
```
