# Handoff Prompt For Claude

Use this prompt to bring Claude or another coding agent up to speed.

```text
You are working in the GitHub repository devSealWare/LightIPAM.

Read CLAUDE.md, AGENTS.md, README.md, docs/ROADMAP.md, docs/SECURITY.md,
docs/ARCHITECTURE.md, docs/SCANNER_DISCOVERY.md, and docs/SCANNER_AGENT.md before
making changes. CLAUDE.md's "Recent work" / "Next" sections are the most current.

Current product:
Light IPAM is a Go/PostgreSQL/Tailwind/Docker Compose IPAM application.
- Phase 1 (manual IPAM) is complete: first-admin bootstrap, local auth, embedded
  PostgreSQL migrations, subnet CRUD, sparse address records, device CRUD, MAC
  tracking, private-MAC tagging, OUI vendor matching, immutable audit logs,
  dashboard, global search, selectable table columns.
- Phases 2–3 (scanner foundation + nmap discovery MVP) are complete, and Phase 4
  (Network Context) is underway. The optional scanner-agent runs staged nmap
  (host discovery -> service/OS on live hosts), SNMP arp_table harvesting, SNMP
  device inventory, NetBIOS/mDNS name_lookup, LLDP/CDP neighbor harvesting
  (lldp_cdp), and a combined all-sources scan; observations flow through the
  /discoveries review queue with reconciliation, per-agent auto-import, and
  merge-on-rescan. See ADRs 0001-0011.

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

Candidate next work (confirm with the user):
- Phase 4 remaining: DHCP leases, DNS enrichment, VLAN/interface mapping — each
  reusing the discovery review-queue pattern, in the agent. (LLDP/CDP shipped in
  ADR 0011.)
- Phase 5: managed cert issuance/rotation, OIDC/MFA, encrypted secrets,
  backup/restore.
```
