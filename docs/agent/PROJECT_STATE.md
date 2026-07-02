# Project State (agent-facing)

A compact snapshot of **where LightIPAM is right now**, for agents deciding what is
safe to build on. Keep this short. When shipped/planned status changes, **update this
file** — a stale snapshot here is worse than none.

> This file answers "where are we now?". It is not the source of truth for release
> history or roadmap — see [Source of truth](#source-of-truth) below.

## Current release

- **Latest release: v1.1.0** (see [`CHANGELOG.md`](../../CHANGELOG.md)). Tagged
  releases publish multi-arch app + scanner images to GHCR.
- Database schema is at **migration 23** (additive; migrations 1–23 applied in
  order). Migrations 22–23 (device hardware links, ADR 0029; SNMP hardware
  identity, ADR 0030) are merged but not yet in a tagged release — see the
  CHANGELOG "Unreleased" section.
- Stable surfaces (SemVer-guarded): the JSON API `/api/v1` and the scanner protocol
  `v1`. A breaking change to either, or a destructive migration, is a major bump.

## Completed work

**Phases 1–6 are complete.** In brief (details in the roadmap and ADRs):

- **Phase 1 — Manual IPAM:** auth/bootstrap, subnets, sparse addresses, devices,
  MAC/vendor, audit log, dashboard, search, custom fields, bulk edit + CSV import/export.
- **Phases 2–4 — Scanner track:** mTLS agent, staged nmap discovery, and six
  unprivileged discovery sources (SNMP `arp_table` / `snmp_inventory` with 802.1Q VLAN
  / `lldp_cdp`, NetBIOS/mDNS `name_lookup`, `dns_lookup`, `dhcp_leases`), a `combined`
  scan, a `/discoveries` review queue with reconciliation, auto-import, and
  merge-on-rescan.
- **Phase 5 — Production hardening:** admin/viewer roles, TOTP MFA, OIDC SSO,
  encrypted secrets at rest, app-managed CA with rotation, `pg_dump` backup/restore,
  login lockout, session hardening, runtime-editable Settings.
- **Phase 6 — Advanced automation:** policy/health checks, scheduled scan windows,
  change webhooks, NetBox-compatible import/export, and a token-authenticated machine
  API `/api/v1` + `lightipam-cli`.
- **Post-1.0 (shipped in v1.1.0):** routing-aware scanner egress + agent diagnostics
  (ADR 0027) and schedule scope validation + last-run outcome (ADR 0028).
- **Post-1.1 (merged, unreleased):** same-physical-device links (ADR 0029,
  migration 22) — suggest-and-confirm linking of a multi-homed device's per-subnet
  records; link-not-merge. Phase 2 shipped as ADR 0030 (migration 23): the SNMP
  ENTITY-MIB chassis serial persists as a hardware identity, an exact serial
  match is a gold-confidence link suggestion, and a Settings → Discovery toggle
  (default off) opts in to auto-linking serial matches at import time.

## Known limitations

(See the README "Limitations" section for the authoritative list.)

- **IPv4 only** — no IPv6 anywhere in the stack.
- **SNMP is v2c only**; one read community per agent.
- The SNMP, LLDP/CDP, NetBIOS/mDNS, DNS, and DHCP backends are **unverified against
  real hardware** (hermetic unit tests only).
- nmap is **TCP-only** (no UDP/NSE); VLAN mapping covers the **access VLAN only**.
- DHCP ingestion reads a **mounted lease file** (ISC dhcpd / dnsmasq) — no API/SNMP source.
- **Online agent-pull cert enrollment is not built** (the one deferred Phase 5 item):
  the managed CA issues + rotates and the agent hot-reloads operator-deployed certs.

## What's next

**The next phase is open — confirm direction with the maintainer before starting.**
Do not invent future plans. Candidate follow-ups recorded in the roadmap include a
Terraform provider against `/api/v1`, online agent-pull cert enrollment, optional
Phase 4 VLAN/interface polish, and the remaining Settings tabs. None is committed.

## Source of truth

When these disagree, resolve toward the more specific source and fix the drift:

| Question | Source of truth |
|----------|-----------------|
| What shipped, and when? | [`CHANGELOG.md`](../../CHANGELOG.md) |
| What is the roadmap / phase plan? | [`docs/ROADMAP.md`](../ROADMAP.md) |
| Why was a design decision made? | [`docs/adr/`](../adr) |
| Where are we now (agent-facing)? | **this file** |
| What are the invariants / rules? | [`AGENTS.md`](../../AGENTS.md) |

**Maintenance rule:** any PR that ships or re-plans a feature must update this file,
`CHANGELOG.md`, and `docs/ROADMAP.md` together so they cannot contradict each other.
The `lightipam-doc-sync` skill checks this.
