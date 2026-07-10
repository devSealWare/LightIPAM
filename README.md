<p align="left">
  <img src=".github/assets/lightipam-lockup-light.svg#gh-light-mode-only" alt="LightIPAM" width="260">
  <img src=".github/assets/lightipam-lockup-dark.svg#gh-dark-mode-only" alt="LightIPAM" width="260">
</p>

# LightIPAM

[![Release](https://img.shields.io/github/v/release/devSealWare/LightIPAM?sort=semver)](https://github.com/devSealWare/LightIPAM/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**A lightweight, secure, self-hosted IP address management system for homelabs,
small businesses, and smaller IT environments, with optional isolated network
discovery.**

LightIPAM combines a clean web interface for network inventory with a
review-first discovery workflow. It is designed for people moving beyond
spreadsheets or looking for a focused NetBox alternative or phpIPAM alternative
without adopting a full DCIM platform.

## Why LightIPAM?

- **Focused IP address management:** organize IPv4 subnets, addresses, devices,
  VLANs, tags, and custom fields without a large platform around them.
- **Safe, optional discovery:** an isolated scanner agent finds network hosts;
  observations enter a review queue instead of silently changing managed data.
- **Strong privilege separation:** the web app is unprivileged and contains no
  scanning tools. Only the optional scanner container receives `NET_RAW` for nmap.
- **Ready for real operations:** OIDC SSO, TOTP MFA, roles, audit logs, backups,
  policy checks, webhooks, a stable API, and a CLI are included.
- **Portable data and deployment:** Docker Compose, multi-architecture images,
  PostgreSQL-native network types, and NetBox-compatible CSV import/export.

## Quick start

The fastest evaluation path uses the published v1.2.1 container images:

```sh
cp .env.example .env
mkdir -p deploy/scanner-certs
# Set POSTGRES_PASSWORD and APP_SECRET in .env, then:
docker compose --env-file .env -f compose.release.yaml up -d
```

Open <http://localhost:8080> and create the first administrator. This local
quick start uses plain HTTP; use a TLS-terminating reverse proxy and set
`COOKIE_SECURE=true` before exposing LightIPAM beyond localhost.

[Installation](docs/INSTALLATION.md) · [Security](docs/SECURITY.md) ·
[Architecture](docs/ARCHITECTURE.md) · [API and CLI](docs/API.md) ·
[Roadmap](docs/ROADMAP.md) · [Changelog](CHANGELOG.md) ·
[Releases](https://github.com/devSealWare/LightIPAM/releases)

## Is LightIPAM for me?

LightIPAM is a good fit for homelabs, small business networks, small IT teams,
and environments currently tracking addresses in spreadsheets. It favors a
focused self-hosted IPAM, straightforward Docker Compose operations, and
optional network discovery with explicit privilege separation.

Consider a full DCIM platform when you need rack and facility modeling, circuit
management, a broad plugin ecosystem, mature IPv6 support, or large-enterprise
workflow and integration depth. LightIPAM is a lightweight alternative for
users who do not need those broader capabilities; it does not claim to replace
every NetBox or phpIPAM deployment.

## Features

### Inventory and data management

- Sparse IPv4 subnet and address records with global overlap prevention,
  `/31` and `/32` support, status workflows, VLAN metadata, and utilization.
- Device and MAC tracking, best-effort OUI vendor lookup, tags, custom fields,
  global search, bulk editing, and selectable table columns.
- Same-physical-device links for multi-homed hardware, with operator-confirmed
  suggestions and optional exact SNMP chassis-serial matching.
- Validated, all-or-nothing CSV import/export, including a NetBox-compatible
  format.

### Identity, security, and operations

- Local accounts, admin and read-only viewer roles, TOTP MFA with recovery
  codes, and OIDC authorization-code flow with PKCE.
- Encrypted secrets at rest, hardened sessions, login throttling, and an
  append-only audit log.
- Runtime settings, policy and health checks, HMAC-signed change webhooks,
  scheduled scans, and `pg_dump` backup and restore.
- Token-authenticated JSON API at `/api/v1` and the stdlib-only
  `lightipam-cli` reference client.

### Optional discovery

- Staged nmap host, service, and OS discovery with Light, Standard, and Deep
  scan modes.
- SNMP v2c ARP-table, device inventory, access-VLAN, and LLDP/CDP discovery;
  NetBIOS/mDNS and DNS name enrichment; and ISC dhcpd or dnsmasq lease-file
  ingestion.
- A combined scan that merges sources per host, plus manual and scheduled jobs
  with explainable outcomes and two-sided target allowlist enforcement.
- Review, reconcile, import, dismiss, auto-import for trusted agents, and
  merge-on-rescan workflows. Discovery never bypasses the managed inventory
  boundary.

## Installation paths

| Goal | Recommended path |
| --- | --- |
| Evaluate the current release | Published images with `compose.release.yaml` |
| Run a production-style deployment | Pinned published images, external TLS, durable volumes, and operator-managed secrets |
| Develop or build from source | `compose.yaml` with `docker compose up --build` |
| Add network discovery | Add the `scanner` profile to either Compose path after configuring mTLS and an allowlist |

See the [installation and upgrade guide](docs/INSTALLATION.md) for commands,
image-tag policy, secret generation, TLS guidance, source development, scanner
setup, and upgrades.

## Production deployment notes

- Keep `LIGHTIPAM_VERSION` pinned to an exact release and upgrade it
  deliberately after taking a backup.
- Store `APP_SECRET`, the database password, and optional
  `APP_ENCRYPTION_KEY` outside version control. Losing the encryption material
  can make sealed settings in a database backup unusable.
- Terminate TLS at a reverse proxy, set `COOKIE_SECURE=true`, and follow the
  [deployment security guidance](docs/SECURITY.md#deploying-beyond-localhost).
- Copy backups off-host and test restores using the
  [backup and restore runbook](docs/BACKUP_RESTORE.md).
- The default `compose.yaml` remains the source-build workflow; it is not the
  recommended production image deployment.

## Optional scanner agent

The scanner agent is a separately built and deployed network sensor. The app
connects to it over mTLS, and both sides validate every scan target against the
agent allowlist. The app stays at `cap_drop: ALL`; the agent drops all
capabilities and adds back only `NET_RAW` for nmap. SNMP, name resolution, DNS,
and DHCP-file discovery use ordinary sockets or file reads and need no added
capability.

Start with the [scanner-agent setup guide](docs/SCANNER_AGENT.md). It covers
certificate generation and rotation, bridge versus macvlan networking,
routing-aware egress, per-VLAN deployments, scanner configuration, and
troubleshooting.

## How discovery works

```text
App schedules job -> mTLS dispatch -> agent validates scope -> isolated scan
                  <- structured observations and notices <-
Review queue -> operator imports or dismisses -> managed inventory
```

Observations are staged outside managed inventory. LightIPAM labels them as new,
matching, or conflicting, then requires review unless a trusted agent has
explicitly enabled non-conflicting auto-import. See
[Scanner Discovery](docs/SCANNER_DISCOVERY.md) and the versioned
[Scanner Protocol](docs/SCANNER_PROTOCOL.md).

## Security model

The web application runs without Linux capabilities, raw sockets, nmap, or
packet capture. Active discovery belongs exclusively to the scanner agent, and
app-to-agent communication uses mTLS with independent app-side and agent-side
allowlist checks. The UI is server-rendered under a strict CSP with no inline
JavaScript or CSS, and the audit log is append-only at the database layer.

Read the complete [security model and threat boundaries](docs/SECURITY.md).
Security vulnerabilities should be reported through the private process
described there, not through a public issue.

## Architecture and stack

- **App:** Go standard-library `net/http`, `pgx/v5`, embedded migrations,
  server-rendered templates, and hand-written Tailwind CSS.
- **Database:** PostgreSQL 16 using native `inet`, `cidr`, and `macaddr` types.
- **Scanner agent:** a separate Go service with nmap and unprivileged discovery
  backends, connected to the app over mTLS.
- **Deployment:** Docker Compose with separate source-build and published-image
  configurations; release images target amd64 and arm64.

For component boundaries and data flow, see [Architecture](docs/ARCHITECTURE.md)
and the [architecture decisions](docs/adr/).

## Documentation

| Topic | Document |
| --- | --- |
| Installation and upgrades | [Installation](docs/INSTALLATION.md) |
| Scanner deployment | [Scanner Agent](docs/SCANNER_AGENT.md) |
| Discovery behavior | [Scanner Discovery](docs/SCANNER_DISCOVERY.md) |
| Security and vulnerability reporting | [Security](docs/SECURITY.md) |
| System design | [Architecture](docs/ARCHITECTURE.md) |
| API and CLI | [Machine API & CLI](docs/API.md) |
| Backup and restore | [Backup & Restore](docs/BACKUP_RESTORE.md) |
| Disaster recovery | [Disaster Recovery](docs/DISASTER_RECOVERY.md) |
| NetBox-compatible data exchange | [NetBox Import/Export](docs/NETBOX.md) |
| Configuration | [Settings](docs/SETTINGS.md) |
| Planned direction | [Roadmap](docs/ROADMAP.md) |
| Release history | [Changelog](CHANGELOG.md) |
| Brand assets | [Branding](docs/BRANDING.md) |

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), the
[project working agreement](AGENTS.md), and the
[review checklist](docs/agent/CODE_REVIEW.md) before opening a focused PR.

## License

LightIPAM is released under the [Apache License 2.0](LICENSE).
