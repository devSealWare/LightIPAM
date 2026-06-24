# Changelog

All notable changes to Light IPAM are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Starting at v1.0.0, the JSON API (`/api/v1`) and the scanner protocol (`v1`) are
treated as stable surfaces: a breaking change to either, or a destructive database
migration, requires a major-version bump.

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

[1.0.0]: https://github.com/devSealWare/LightIPAM/releases/tag/v1.0.0
