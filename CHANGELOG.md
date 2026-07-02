# Changelog

All notable changes to Light IPAM are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Starting at v1.0.0, the JSON API (`/api/v1`) and the scanner protocol (`v1`) are
treated as stable surfaces: a breaking change to either, or a destructive database
migration, requires a major-version bump.

## [Unreleased]

### Added

- Same-physical-device links (ADR 0029, migration 22): a reversible link layer that
  groups the multiple device records a multi-homed device (e.g. a router with one
  IP and MAC per subnet) imports as. The device page suggests high-confidence
  matches (identical hostname + same OS family + disjoint subnets — never an exact
  OS-string match) for the operator to confirm or dismiss; nothing links
  automatically. Linked siblings show their IPs, subnets, MACs, OS, and services on
  the device page, records are never merged, and manual link/unlink always works.
  Link actions are audited (`device.link.confirmed` / `.removed` / `.dismissed`).

## [1.1.0] - 2026-06-29

A backward-compatible release: no breaking `/api/v1` or scanner-protocol changes,
and the one new database migration (21) is additive. The headline is routing-aware
scanner egress, which fixes a macvlan agent silently finding zero hosts on routed
subnets.

### Added

- Routing-aware scanner egress: `AGENT_SCAN_PIN_MODE` (default `auto`) pins nmap
  probes to the macvlan source address only for L2-adjacent targets and lets routed
  targets follow the default route, so a single macvlan agent handles both adjacent
  and routed subnets with no per-scan configuration (`always` = the old unconditional
  pin, `off` = never pin) (ADR 0027).
- Agent network diagnostics: a `GET /diagnostics` endpoint and an `/agents/{id}`
  detail panel surface the agent's interfaces, scan source/route, pin mode, nmap
  version, and capabilities — plus any pin/route mismatch — without a `docker exec`
  (ADR 0027).
- A `scanner-agent --healthcheck` subcommand and a Compose healthcheck for the
  scanner-agent service (ADR 0027).
- Save-time scan-scope validation on the scan and schedule forms: an invalid IPv4
  CIDR/target, or a schedule whose allowed CIDRs fall outside the chosen agent's
  allowlist, is now rejected inline instead of failing silently on every scheduler
  tick (ADR 0028).
- A "Last run" column on the schedules page showing each schedule's most recent
  outcome (succeeded / failed / rejected) and failure reason (migration 21,
  ADR 0028).
- A device service-count column on the Devices table and per-subnet utilization on
  the dashboard.
- Light IPAM brand assets: logo lockups, favicons, an Apple touch icon, and a web
  app manifest.

### Changed

- Zero-host and pin/route-mismatch scans now return self-explaining notices, and
  app-to-agent dispatch failures are classified by layer (DNS/TCP/TLS/HTTP) — for
  example, a missing agent container reports "container not running" instead of a
  raw `lookup scanner-agent … no such host` (ADR 0027).

### Fixed

- A macvlan scanner agent no longer silently returns zero hosts when scanning a
  routed subnet (ADR 0027).
- A scan schedule saved with a configuration the agent rejects at dispatch (e.g. a
  mistyped CIDR) no longer fails silently on every tick; it is caught at save time
  and its last-run outcome is surfaced on the schedules page (ADR 0028).

## [1.0.0] - 2026-06-23

First stable release. Light IPAM is a lightweight IP address management system with
a clean web UI and optional, tightly-scoped active network discovery. The web app
runs unprivileged (zero Linux capabilities); all privileged scanning is isolated to a
separate, optional scanner agent.

### Manual IPAM

- First-admin bootstrap, local login/logout, Argon2id password hashing, sessions, and
  CSRF protection with strict security headers.
- Subnet CRUD with global overlap/containment blocking and optional VLAN metadata.
- Sparse IPv4 address records (`/31` and `/32` supported), device CRUD, and MAC
  tracking with private/rotating-MAC detection and best-effort OUI vendor lookup.
- Devices grouped by subnet, global search across subnets/addresses/devices/MACs, and
  per-table selectable columns.
- Tags and operator-defined custom fields (text) on subnets, addresses, and devices.
- Multi-select bulk edit (status/VLAN/tag/clear-device/delete) and CSV import/export
  with a validated dry-run preview and all-or-nothing apply, plus a NetBox-compatible
  CSV format.
- Immutable, append-only audit log with UI filters.

### Identity, access & operations

- Login throttling and account lockout, idle and absolute session timeouts, and a
  per-session origin record with active-session review and "log out everywhere".
- Admin and read-only roles with central authorization.
- TOTP multi-factor authentication with recovery codes.
- OIDC single sign-on (authorization code + PKCE).
- Encrypted secrets at rest (AES-256-GCM).
- `pg_dump`-based backup and restore.
- An app-managed certificate authority that issues and rotates short-lived agent mTLS
  certificates, which the agent hot-reloads.
- A tabbed Settings page (Security, Users & Roles, Authentication, Agent certificates,
  Backup & Restore, Custom fields, Policy, Notifications) with policy editable at
  runtime, plus a per-user account page.

### Network discovery (optional scanner agent)

- Isolated scanner agent communicating with the app over mTLS, with an allowlist of
  permitted scan scopes and an immutable scan audit trail.
- nmap-backed host discovery and service/OS detection, run in staged passes with
  dynamic per-type timeouts. `NET_RAW` is granted to the agent only.
- Unprivileged SNMP discovery: ARP-table harvesting, device inventory with 802.1Q
  VLAN and interface mapping, and LLDP/CDP neighbor harvesting.
- Unprivileged NetBIOS/mDNS name resolution, DNS forward/reverse enrichment, and DHCP
  lease-file ingestion.
- A combined scan that runs every backend and enriches the hosts nmap discovers,
  merging findings per host.
- A discovery review queue with conflict-aware reconciliation, per-agent auto-import,
  and a structured per-host scan-result detail view.
- Subnet auto-create on import and an "Import all" action for the pending,
  non-conflicting discovery queue.
- Manual and scheduled scans, with optional time-of-day/weekday scan windows in the
  schedule's own timezone.

### Automation & integration

- Policy / health checks: a read-only view flagging overlapping subnets, stale managed
  records, and unmanaged/conflicting discovered services.
- Change webhooks: HMAC-signed JSON notifications fanned out from the audit log to
  subscribed endpoints.
- Token-authenticated JSON API under `/api/v1` for subnets, addresses, and devices.
- `lightipam-cli`, a stdlib-only command-line client for the API.

### Deployment

- Docker Compose deployment with separate `app`, `scanner-agent`, and `db` images.
- `/healthz` liveness and `/readyz` readiness probes; the build version is stamped
  into the binaries and reported on `/healthz`, in the startup log, and via
  `--version`.

[Unreleased]: https://github.com/devSealWare/LightIPAM/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/devSealWare/LightIPAM/releases/tag/v1.1.0
[1.0.0]: https://github.com/devSealWare/LightIPAM/releases/tag/v1.0.0
