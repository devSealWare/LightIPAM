# Scanner Discovery

Issue #10 turns the scanner agent from a no-op into a real discovery engine and
adds a review queue plus near-automatic agent enrollment. This document covers
the discovery flow, the privilege boundary, and the enrollment model.

See also: `docs/SCANNER_AGENT.md`, `docs/SCANNER_PROTOCOL.md`, ADR 0005.

## Privilege boundary

Active discovery uses nmap, which needs raw sockets for ARP/SYN/OS probes. That
risk is isolated to the agent:

- **Agent image** (`Dockerfile.scanner`): bundles nmap, runs as root so nmap can
  use raw sockets.
- **Agent compose service**: `cap_drop: ALL` then `cap_add: NET_RAW`, plus
  `read_only` and `no-new-privileges`. Verified runtime caps: `CapEff=0x2000`
  (NET_RAW only).
- **Web app**: no nmap, `cap_drop: ALL`, zero added capabilities. Verified
  runtime caps: `CapEff=0`.

The app only ever acts as an mTLS client; it never probes the network.

## Scan depth (mode → nmap)

Scan **type** selects what to collect; scan **mode** selects intensity.

| Mode              | nmap behavior                                            |
| ----------------- | -------------------------------------------------------- |
| `passive`         | No nmap is run at all.                                   |
| `light_active`    | Host discovery sweep (`-sn`); top-100 ports for service. |
| `standard_active` | Top-1000 TCP service detection (`-sV`).                  |
| `deep_active`     | Adds OS probing (`-O`) and exhaustive version probes.    |

| Type                | Adds                                              |
| ------------------- | ------------------------------------------------- |
| `host_discovery`    | `-sn` ping/ARP sweep, no port scan.               |
| `service_detection` | `-sV` over the mode's top ports.                  |
| `os_probe`          | `-O` OS fingerprinting.                           |
| `combined`          | `-sV` + `-O` (OS skipped on `light_active`).      |

Job rate limits map to `--max-rate` / `--max-parallelism`; the job timeout maps
to `--host-timeout` and bounds the agent-side context.

`internal/scanner/agent/nmap.go` builds the argument list and parses nmap's XML
(`-oX -`). The command runner is injectable, so argument building and XML parsing
are unit-tested without nmap or raw-socket privileges.

## Review queue (`/discoveries`)

The agent never mutates IPAM data. The orchestrator persists each successful
observation into `scan_discoveries` (`store.UpsertDiscovery`), keyed by IP:

- A new host appears as **pending**.
- Re-observing a host refreshes its details and `last_seen_at`, but does not
  resurrect an already **imported** or **dismissed** host.

In the UI an operator either:

- **Imports** a discovery: it is placed into the managed subnet that contains its
  IP (`ip_addresses`, state `assigned`, with hostname), and when a MAC is known a
  device + MAC record is created (or an existing device that owns the MAC is
  reused). Import is idempotent and refuses if no subnet contains the address.
- **Dismisses** it: it is marked reviewed and will not resurface.

Every import/dismiss is audited.

### Reconciliation (conflict detection)

Each observation is reconciled against the managed IPAM records and tagged with a
`reconcile_status` that is independent of the review status:

- **new** — the address is not managed yet.
- **match** — the address is managed and consistent with the observation.
- **conflict** — the observation disagrees with a managed record. Flagged when:
  the observed MAC differs from the MAC already on the address's device; a
  responding host is recorded as `deprecated`; or the observed MAC is already
  bound to a different managed address (a likely IP change).

Conflicts are surfaced in the queue (a "Conflicts" filter and a per-row badge +
explanation), so an operator reviews them before importing. Reconciliation also
performs the one IPAM write a scan does on its own: refreshing `last_seen_at` on a
matched/conflicting managed address, giving live liveness tracking without an
import. Assignments and records are never created or changed without an import.

## App-pull agent enrollment

Enrollment keeps the mTLS direction (app = client) so the app gains no inbound
surface. The agent self-describes on `GET /register`; the app pulls it and
creates a `pending` agent for one-click approval.

- **Automatic (boot):** set `SCANNER_AGENT_ENDPOINT` (the bundled compose agent
  is `https://scanner-agent:8443`). On startup the app retries a few times while
  the agent container comes up, then enrolls it as pending.
- **On demand:** the `/agents` page has a "Discover" form — paste an endpoint
  URL, the app fetches `/register` over mTLS and enrolls the agent.
- **Approve:** a pending agent has an "Approve" button (`pending → active`).
  Only active agents receive jobs.

Enrollment never overwrites an existing agent (so operator edits to status or
allowlist are preserved); re-discovering a known endpoint is a no-op.

## Try it

```sh
go run ./cmd/scanner-certs -dir deploy/scanner-certs
docker compose --profile scanner build
docker compose --profile scanner up -d
```

1. Bootstrap the admin, sign in.
2. Under `/agents`, approve the auto-enrolled `local-scanner-agent` (or use
   "Discover" with `https://scanner-agent:8443`).
3. Create a subnet covering the network you want to import into.
4. Run a scan from `/scans` (targets must fall inside the agent's
   `AGENT_ALLOWED_CIDRS`, default `192.168.0.0/16,10.0.0.0/8`).
5. Review hits under `/discoveries`; import the ones you want.
