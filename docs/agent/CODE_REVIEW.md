# Code Review Checklist

For human reviewers and the `lightipam-review` skill. Work top to bottom; a "no" to
any invariant question below is **blocking**. Group findings by severity: **blocking**,
**should-fix**, **nit**, **follow-up issue**.

## Scope discipline

- [ ] Does every changed line trace to the stated task? No drive-by refactors, renames,
      or reformatting riding along.
- [ ] Is the diff the smallest that solves the problem? No speculative abstraction or
      unused "flexibility".
- [ ] Is generated/vendored noise absent (no stray root binaries, no committed certs,
      no `node_modules`)?

## Architecture & security invariants

- [ ] **Did this PR move scanning capability into the app?** The `app` container must
      stay unprivileged (`cap_drop: ALL`, no nmap, no raw sockets, no packet capture).
- [ ] **Did this PR add a raw socket, nmap call, packet capture, or Linux network
      capability outside `scanner-agent`?** `NET_RAW` belongs to the agent alone.
- [ ] **Did this PR materialize full IP ranges instead of sparse records?** Address
      storage must stay sparse; overlapping subnets stay globally blocked.
- [ ] Are secrets still sealed at rest (`internal/secret`) and never logged or echoed
      back in a form?

## Scanner boundary

- [ ] Are **both** allowlist checks intact — app-side `ValidateJobForAgent` and
      agent-side `ValidateAgentScope`?
- [ ] Do scan failures stay **explainable to operators** (a classified/self-explaining
      notice), rather than a job succeeding with a misleading empty result?
- [ ] Is any new agent config a **secret that stays on the agent** (SNMP community,
      egress pin, DHCP lease path, allowlist) and never surfaced to the app DB or UI?

## Database / migrations

- [ ] Is any schema change an **additive, ordered, embedded** migration (next version
      number) that does not rewrite or destroy data? A destructive migration needs a
      major-version bump and maintainer sign-off.
- [ ] Do new queries use the native `inet`/`cidr`/`macaddr` types and parameterized SQL?

## UI / CSP

- [ ] No inline JS/CSS; any script is a same-origin file under `internal/ui/static`.
- [ ] **Did this PR modify generated CSS (`internal/ui/static/app.css`) without
      updating the Tailwind source (`internal/ui/assets/app.css`)?** The generated file
      must come from `npm run build:css`.
- [ ] Does the page still render server-side with JS off (progressive enhancement)?

## Tests

- [ ] Is there a **regression test for a bug fix**, or coverage for new behavior?
- [ ] Is parsing/validation logic kept **pure and unit-tested** (the codebase
      convention)?
- [ ] Does `go test ./...` pass, and no test silently skipped or weakened?

## Docs

- [ ] Are docs updated to match behavior (README, the relevant `docs/SCANNER_*` /
      `docs/SECURITY.md`, an ADR for a decision)?
- [ ] **Do docs, `AGENTS.md`, `docs/agent/PROJECT_STATE.md`, `docs/ROADMAP.md`, and
      `CHANGELOG.md` contradict each other?** Nothing "planned" in one file while
      "shipped" in another.

## Dependency changes

- [ ] Is any new dependency called out explicitly and justified (ideally an ADR)? Does
      it avoid pulling in a heavy framework?
- [ ] Did `go build -mod=readonly ./cmd/scanner-agent` confirm no silent module creep?

## Release impact

- [ ] Does the change touch a stable surface (`/api/v1`, scanner protocol `v1`, DB
      schema)? If breaking, is a major-version bump and `CHANGELOG.md` entry present?
- [ ] Are version references (README image tags, `package.json`) consistent if this is
      release-adjacent?

## Operational impact

- [ ] Are `compose.yaml` capability drops, `read_only`, and `no-new-privileges`
      preserved for `app`?
- [ ] Do `/healthz` and `/readyz` still behave, and are new env vars documented in
      `.env.example` / `compose.yaml`?
