# Handoff Prompt For Claude

Use this prompt to bring Claude or another coding agent up to speed.

```text
You are working in the GitHub repository devSealWare/LightIPAM.

Read AGENTS.md, CLAUDE.md, README.md, docs/MVP.md, docs/ROADMAP.md, docs/SECURITY.md, docs/ARCHITECTURE.md, and docs/BACKLOG.md before making changes.

Current product:
Light IPAM is a Go/PostgreSQL/Tailwind/Docker Compose IPAM application. It has a complete Phase 1 manual IPAM foundation: first-admin bootstrap, local auth, embedded PostgreSQL migrations, subnet CRUD, sparse address create/edit/delete, device CRUD, MAC tracking, private rotating MAC tagging, built-in OUI vendor matching, immutable audit logs, audit UI, dashboard, sidebar navigation, and confirmation flows.

Current architecture rule:
The web app must stay unprivileged. Do not add raw socket scanning, packet capture, Nmap execution, or trunked-network scanning to the app container. Active discovery must be isolated in a future scanner-agent container.

Current task:
Work on issue #7: Define scanner agent protocol.

Implementation expectations:
- Define scanner agent registration model.
- Define mTLS identity model.
- Define scan job schema.
- Define scan result schema.
- Require explicit IPv4 allowlists per scan.
- Define scan lifecycle states and evidence/error records.
- Keep the work as protocol/types/docs only. Do not implement active scanning or Nmap yet.

Suggested files:
- docs/SCANNER_PROTOCOL.md
- docs/adr/0002-scanner-agent-protocol.md
- internal/scanner/protocol.go
- internal/scanner/protocol_test.go

Verification:
- npm run build:css
- go test ./...
- docker compose build
- docker compose up -d
- docker compose exec app wget -qO- http://127.0.0.1:8080/healthz

Next after issue #7:
Start issue #8: scanner-agent container with no-op job receive/report behavior.
```

