<!--
Thanks for contributing to Light IPAM. Keep PRs focused and reviewable.
See CONTRIBUTING.md for the full working agreement.
-->

## What

<!-- A short description of the change and why it's needed. Link any issue/ADR. -->

## How

<!-- Notable implementation choices, trade-offs, and anything a reviewer should look at first. -->

## Verification

<!-- Tick what you actually ran. -->

- [ ] `npm run build:css`
- [ ] `go build ./... && go vet ./...`
- [ ] `go test ./...`
- [ ] `gofmt -l internal cmd` is clean
- [ ] `docker compose build` (and `docker compose --profile scanner build` if the agent changed)

## Checklist

- [ ] The **web app stays unprivileged** — no raw sockets, nmap, packet capture,
      or trunked scanning added to the app container. All active/privileged
      discovery lives in the scanner agent. (See [docs/SECURITY.md](../docs/SECURITY.md).)
- [ ] Strict CSP preserved — no inline JS/CSS; any new script is same-origin and
      embedded under `internal/ui/static`.
- [ ] No new heavy framework; new behavior favors the Go stdlib and existing patterns.
- [ ] Docs updated to match (CLAUDE.md / AGENTS.md "Next", README, ROADMAP, an ADR
      for an architectural decision, and the relevant `docs/SCANNER_*`).
- [ ] A new external dependency is called out explicitly in the description.
