<p align="left">
  <img src=".github/assets/lightipam-lockup-light.svg#gh-light-mode-only" alt="LightIPAM" width="260">
  <img src=".github/assets/lightipam-lockup-dark.svg#gh-dark-mode-only" alt="LightIPAM" width="260">
</p>

# LightIPAM

[![Release](https://img.shields.io/github/v/release/devSealWare/LightIPAM?sort=semver)](https://github.com/devSealWare/LightIPAM/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

LightIPAM is a lightweight IP address management system with a clean web UI and
optional, tightly-scoped active network discovery. It targets small-business
networks first while keeping its architecture credible for larger environments.

The design is intentionally split so risk stays isolated:

- **`app`** — the unprivileged web UI, auth, IPAM inventory, audit log, and scan
  orchestration. Runs with **zero Linux capabilities** and no scanning tools.
- **`scanner-agent`** — an optional, isolated network sensor that runs nmap
  (staged host-discovery → service/OS detection), SNMP (ARP-table harvesting,
  device inventory + 802.1Q VLAN/interface mapping, and LLDP/CDP neighbor harvesting
  over UDP/161), NetBIOS/mDNS name resolution (UDP/137 and UDP/5353), DNS
  reverse/forward enrichment (UDP/TCP/53), and DHCP lease-file ingestion for
  discovery. nmap is the **only** thing granted a network capability (`NET_RAW`), and
  only when enabled; every other backend is plain unicast UDP/DNS or a file read and
  needs no extra privilege.
- **`db`** — PostgreSQL, using native `inet`/`cidr`/`macaddr` types.

## Features

**Manual IPAM**
- First-admin bootstrap, local login/logout, Argon2id password hashing, sessions
  and CSRF protection, strict security headers.
- Subnet CRUD with global overlap blocking and optional VLAN metadata.
- Sparse IPv4 address records (`/31` and `/32` supported), device CRUD, MAC
  tracking with private/rotating-MAC detection and best-effort OUI vendor lookup.
- Devices grouped by subnet, global search across subnets/addresses/devices/MACs,
  and per-table selectable columns.
- **Same-physical-device links** (ADRs 0029/0030): the separate per-subnet records
  of a multi-homed device (e.g. a router with one IP and MAC per interface) can be
  linked as one physical device — high-confidence suggestions (identical hostname +
  OS family across disjoint subnets), **gold-confidence SNMP chassis-serial
  matches**, and manual link/unlink. Records are never merged; linking is
  confirm-first, with an opt-in Settings → Discovery toggle to auto-link exact
  serial matches at import time.
- Tags and operator-defined **custom fields** (text) on subnets, addresses, and
  devices — custom fields are defined on an admin Settings tab and edited on each
  record's form (ADR 0019).
- Multi-select **bulk edit** (status/VLAN/tag/clear-device/delete) and **CSV
  import/export** for subnets, addresses, and devices, with a validated dry-run
  preview and all-or-nothing apply (ADR 0016), plus a **NetBox-compatible** CSV
  format on the same Import/Export page (ADR 0023).
- Immutable, append-only audit log with UI filters.

**Identity, access & operations**
- **Admin / read-only viewer roles** (a central middleware blocks viewers from all
  mutations), **TOTP MFA** with single-use recovery codes, and **OIDC SSO**
  (auth-code + PKCE) — all configured from a tabbed **Settings** panel; per-user
  password / MFA / session review on the **Account** page.
- Login throttling + account lockout, idle **and** absolute session timeouts, and
  active-session review with "log out everywhere" — all policy editable at runtime
  and persisted in `app_settings` (ADR 0017).
- **Encrypted secrets at rest** (AES-256-GCM) for the OIDC client secret, TOTP
  secrets, the managed-CA key, and webhook signing keys.
- An **app-managed CA** that issues and rotates short-lived agent/app mTLS certs
  (the agent hot-reloads a rotated cert), plus **`pg_dump` backup/restore** with a
  documented runbook (ADR 0018).
- **Policy / Health checks** (`/policy`) for overlapping subnets, stale records,
  and unmanaged/conflicting discovered services, with a dashboard widget (ADR 0020).
- **Change webhooks** — HMAC-signed JSON POSTed to subscribed endpoints, driven by
  the audit log as the change feed (ADR 0022).
- A token-authenticated **machine API** (`/api/v1`) and a stdlib-only
  **`lightipam-cli`**; per-user bearer tokens carry the owner's role (ADR 0024,
  [docs/API.md](docs/API.md)).

**Discovery (optional, agent-driven)**
- mTLS between app and agent; the app is always the client. Two-sided allowlist
  enforcement (app-side + agent-side).
- **Staged nmap** — a fast host-discovery sweep finds live hosts first, then only
  those get service/OS detection (version probing just the open ports). Scan
  **depth** is a Light / Standard / Deep mode (top-1000 → +exhaustive versions+OS
  → all ports), applied to the nmap scan types only.
- **SNMP backends (unprivileged, UDP/161):** `arp_table` harvests IP↔MAC bindings
  from a gateway's ARP cache (recovering MACs across a router), `snmp_inventory`
  reads a device's own identity (name/OS), the MACs of its interfaces, and each
  interface's **802.1Q access VLAN** (a discovered VLAN backfills the containing
  subnet's VLAN when it has none), and `lldp_cdp` reads a switch/router's LLDP/CDP
  neighbor caches to map which devices are wired to which ports.
- **Name resolution (unprivileged):** `name_lookup` asks a host directly for its
  name over NetBIOS (UDP/137) and unicast mDNS (UDP/5353), recovering hostnames for
  devices with no DNS PTR record (NetBIOS works across subnets); `dns_lookup` reads
  the authoritative DNS (reverse PTR, forward-confirmed) for hosts that do have a
  record.
- **DHCP leases (unprivileged):** `dhcp_leases` reads the DHCP server's lease file
  (ISC dhcpd or dnsmasq, mounted read-only on the agent) for the authoritative
  IP↔MAC binding and client-supplied hostname of each active lease.
- **Combined** scan runs deep nmap + ARP + SNMP inventory (VLAN) + NetBIOS/mDNS
  names + DNS names + DHCP leases + LLDP/CDP neighbors in one job, merged into one
  picture per host; it is the form's default. An enrichment target that does not
  answer (or is not configured, or a CIDR these unicast queries cannot expand) is
  *skipped* (ignored), not failed.
- Manual and scheduled scans (in-process scheduler) with a full job lifecycle,
  audit trail, per-host result detail, and generous per-type scan timeouts. A
  schedule can restrict firing to a **run window** — a time-of-day range plus a
  weekday set in its own IANA timezone — on top of the interval cadence (ADR 0021).
- **Review queue** (`/discoveries`): observations never auto-mutate IPAM. Each is
  reconciled against managed records — flagged **new**, **match**, or **conflict**
  (e.g. a changed MAC, or a deprecated address still responding) — and an operator
  imports or dismisses it. Managed addresses get live `last_seen_at` tracking.
  **Import all** clears the whole non-conflicting queue in one click, and importing
  a host with no managed subnet opens a pre-filled **subnet auto-create** modal (the
  exact network the scan targeted — e.g. a `/28` scan suggests `/28` — and the scanned
  VLAN filled in) so a fresh network goes from scan to managed IPAM in a few clicks
  (ADR 0026).
- **Auto-import & merge-on-rescan:** a trusted agent can auto-import
  non-conflicting hosts, and every scan re-syncs its findings onto already-imported
  devices so different scan types accumulate into one complete record.
- **Near-automatic agent enrollment**: the app pulls an agent's identity from its
  `/register` endpoint (auto on boot for the bundled agent, or via the `/agents`
  "Discover" form) and adds it as `pending` for one-click approval.

## Stack

- Backend: Go standard library `net/http`, `pgx` for PostgreSQL, embedded Go
  migrations. No large frameworks.
- Frontend: server-rendered HTML templates with hand-written Tailwind CSS. No
  client-side JavaScript framework — a few small first-party scripts
  (`internal/ui/static/*.js`) progressively enhance specific forms (bulk edit,
  scan form, column preferences); strict CSP (no inline JS/CSS).
- Database: PostgreSQL 16.
- Discovery: nmap plus stdlib SNMP (`gosnmp`), NetBIOS, mDNS, DNS, and DHCP
  lease-file parsing, wrapped by the scanner agent.
- Deployment: Docker Compose.

## Run it

App + database only (no discovery):

```sh
docker compose up --build -d
```

Open `http://localhost:8080` and create the first admin from the bootstrap page.

> **Plaintext HTTP by default.** This quick-start serves over plain HTTP, so
> session, CSRF, and OIDC cookies are sent without the `Secure` attribute and
> traverse cleartext. That's fine for loopback/local use, but before deploying
> anywhere else: terminate TLS with a reverse proxy (nginx/Caddy/Traefik) in
> front of the app and set `COOKIE_SECURE=true`. See
> [docs/SECURITY.md → Deploying beyond localhost](docs/SECURITY.md#deploying-beyond-localhost).

> If host port 8080 is already taken, publish elsewhere without editing
> `compose.yaml`: copy `.env.example` to `.env` and set e.g. `APP_PORT=31415`,
> then `docker compose up -d`. The `.env` is gitignored, so it survives upgrades.

**Prebuilt images.** Tagged releases publish multi-arch (amd64/arm64) images to the
GitHub Container Registry, so you can run a pinned version without building locally:

```sh
docker pull ghcr.io/devsealware/lightipam:1.2.0          # web app
docker pull ghcr.io/devsealware/lightipam-scanner:1.2.0  # scanner agent
```

The default `compose.yaml` builds from source; point its `image:` at these tags (or
drop the `build:` keys) to deploy the published images instead.

With the scanner agent (active discovery):

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs   # one-time dev mTLS material
docker compose --profile scanner up --build -d
```

> **No Go installed?** Generate the one-time certs with a throwaway `golang`
> container instead — see
> [docs/SCANNER_AGENT.md → Without a local Go toolchain](docs/SCANNER_AGENT.md#without-a-local-go-toolchain-docker-one-shot).

The app auto-enrolls the bundled agent as `pending`; approve it under **Agents**,
create a subnet, then run a scan from **Scans**. Discovered hosts appear under
**Discoveries**. Scan targets must fall within the agent's `AGENT_ALLOWED_CIDRS`
(default `192.168.0.0/16,10.0.0.0/8`).

> The `scanner` Compose profile is required to start the agent — a plain
> `docker compose up` runs only `app` + `db`.

## Verify

```sh
npm run build:css
go test ./...
docker compose build
docker compose --profile scanner build
```

## Security model

The web app must stay unprivileged: no raw sockets, no nmap, no packet capture.
All active scanning lives in the scanner agent, which is the sole holder of
`NET_RAW`. See [docs/SECURITY.md](docs/SECURITY.md) and
[docs/SCANNER_DISCOVERY.md](docs/SCANNER_DISCOVERY.md).

## Limitations

What is intentionally **not** built yet (and roughly where it lands on the
[roadmap](docs/ROADMAP.md)):

- **IPv4 only** — no IPv6 addressing or discovery anywhere in the stack.
- **Online agent-pull cert enrollment is not built** — the app-managed CA issues
  and rotates certs and the agent hot-reloads them, but the agent does not yet renew
  its own cert over a bootstrap channel (the one explicitly-deferred Phase 5 item).
- **SNMP is v2c only** (the config is shaped for v3); one read community per agent.
- **The SNMP, LLDP/CDP, NetBIOS/mDNS, DNS, and DHCP backends are unverified against
  real hardware** — they pass hermetic unit tests but await a live shakedown. mDNS
  cross-subnet resolution is best-effort by design (the protocol is link-local).
- **nmap does TCP only** — no UDP scanning or NSE scripting.
- **LLDP/CDP imports need a management IP** — a neighbor that advertises no
  management address (common for endpoints) is not placed in IPAM from `lldp_cdp`
  alone; pair it with `arp_table`/nmap.
- **VLAN mapping covers the access (untagged) VLAN only** — trunk/tagged-VLAN
  membership and per-interface speed/alias are not mapped yet.
- **DHCP ingestion reads a lease file** — the file must be mounted on the agent
  (ISC dhcpd or dnsmasq); appliances that expose leases only over an API/SNMP are
  not covered yet.
- **The machine API + CLI are the only automation surface** — a Terraform provider
  could be added later against the same stable `/api/v1` (the CLI is the reference
  client); it is not built yet.

## Project status

**Phases 1–6 are complete.** Phase 1 (Manual IPAM), Phase 2 (Scanner Agent
Foundation), Phase 3 (Nmap Discovery MVP), and **Phase 4 (Network Context)** —
six agent-side discovery sources (SNMP ARP-table harvesting, SNMP device inventory
with 802.1Q VLAN/interface mapping, NetBIOS/mDNS name resolution, DNS
reverse/forward enrichment, DHCP lease ingestion, and LLDP/CDP neighbor harvesting),
all merged per host through one review/import path, plus a combined all-sources scan,
staged nmap scanning, and dynamic per-type timeouts — landed first, and Phase 4.5
added multi-select bulk edit and CSV import/export (ADR 0016). **Phase 5 (Production
Hardening)** added admin/viewer roles, TOTP MFA, OIDC SSO, encrypted secrets at rest,
an app-managed CA with rotation, backup/restore, and a runtime-editable Settings
panel (ADRs 0017–0018). **Phase 6 (Advanced Automation)** added policy/health checks
(ADR 0020), scheduled scan windows (ADR 0021), change webhooks (ADR 0022),
NetBox-compatible import/export (ADR 0023), and the machine API + CLI (ADR 0024).
**v1.0.0 was the first stable release; v1.1.0 added routing-aware scanner egress and
agent diagnostics (ADR 0027) plus schedule scope validation (ADR 0028); v1.2.0 adds
same-physical-device links (ADR 0029) and SNMP hardware identity + gold-confidence
device links (ADR 0030)** — see the [changelog](CHANGELOG.md). The next phase is
open. See the roadmap for details.

- [Changelog](CHANGELOG.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)
- [Branding](docs/BRANDING.md)
- [Contributing](CONTRIBUTING.md) · [Agent contract (AGENTS.md)](AGENTS.md) — canonical
  guide for AI coding agents and the invariants humans follow too; task workflows live
  in [docs/agent/](docs/agent).
- [Scanner Protocol](docs/SCANNER_PROTOCOL.md) · [Scanner Agent](docs/SCANNER_AGENT.md) · [Scanner Discovery](docs/SCANNER_DISCOVERY.md)
- Architecture decisions: [docs/adr](docs/adr)

The GitHub social preview image is committed at
`.github/assets/github-social-preview.png`; GitHub will not use it automatically.
A maintainer must set it manually in repository Settings -> Social preview.

## License

LightIPAM is released under the [Apache License 2.0](LICENSE).
