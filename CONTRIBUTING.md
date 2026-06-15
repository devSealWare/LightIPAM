# Contributing to Light IPAM

Light IPAM is a Go / PostgreSQL / Tailwind / Docker Compose IPAM application with
an optional, isolated network-discovery scanner agent. This guide captures the
working agreement; for deeper context read [README.md](README.md),
[AGENTS.md](AGENTS.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and the
`docs/SCANNER_*` files.

## Non-negotiable rules

1. **The web app stays unprivileged.** No raw sockets, nmap, packet capture, or
   trunked-network scanning in the app container. All privileged/active discovery
   lives in the **scanner agent** — it alone may hold `NET_RAW`. SNMP and
   NetBIOS/mDNS discovery are unprivileged unicast UDP and also live in the agent,
   never the app. See [docs/SECURITY.md](docs/SECURITY.md).
2. **Strict CSP, no inline JS/CSS.** Progressive enhancement only: every page
   renders server-side, and any script is a same-origin file embedded under
   `internal/ui/static`.
3. **No large frameworks.** Stdlib `net/http` routing, `pgx/v5`, embedded SQL
   migrations in `internal/db/migrations.go`. A new external dependency is an
   explicit, reviewable decision (and usually an ADR).
4. **IPv4 only**, sparse address records, globally-blocked overlapping subnets,
   append-only audit log — keep these invariants intact.

## Workflow

1. Branch from `main`.
2. Implement the change.
3. Verify (see below).
4. Open a PR with `gh` and fill in the template.
5. **Wait for maintainer approval to merge** — the maintainer says when to merge.
   PRs are squash-merged; the branch is deleted and `main` is synced afterward.

For an architectural decision, add a numbered ADR under
[docs/adr](docs/adr) (next number, copy the existing format) and link it from the
PR. Update the docs that describe the area you changed — at minimum the "Next"
sections of [CLAUDE.md](CLAUDE.md) / [AGENTS.md](AGENTS.md), plus
[README.md](README.md), [docs/ROADMAP.md](docs/ROADMAP.md), and the relevant
`docs/SCANNER_*`.

## Verification

Run before opening a PR:

```sh
npm run build:css                       # regenerate the committed Tailwind CSS
go build ./... && go vet ./...
go test ./...
gofmt -l internal cmd                   # must print nothing
docker compose build                    # app image
docker compose --profile scanner build  # agent image, if the agent changed
```

`go build ./cmd/...` can drop stray `/scanner-agent` and `/server` binaries at the
repo root; both are gitignored — do not commit them.

## Code layout

- `cmd/server` — app entrypoint; `cmd/scanner-agent` — the agent; `cmd/scanner-certs` — dev mTLS material.
- `internal/app` — HTTP routes, handlers, form parsing, auth/session checks.
- `internal/store` — database query layer; `internal/db` — connection + embedded migrations.
- `internal/ipam`, `internal/macaddr`, `internal/auth`, `internal/config` — domain helpers.
- `internal/ui` — embedded templates (`templates/`), Tailwind source (`assets/app.css`),
  generated CSS (`static/app.css`), and same-origin JS (`static/*.js`).
- `internal/scanner` — protocol, allowlist validation, scan budget; `internal/scanner/{agent,dispatch,orchestrator,pki}`.

## Commit and PR style

- Keep commits focused; write a clear subject line and a body explaining the *why*.
- Match the surrounding code's naming, comment density, and idioms.
- Run scanner builds with `go build -mod=readonly ./cmd/scanner-agent` to confirm
  you have not silently pulled in a new dependency.
