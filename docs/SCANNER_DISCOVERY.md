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

SNMP ARP-table harvesting (below) is the exception that proves the rule: it is
active discovery that needs **no** extra privilege — ordinary UDP/161, no
`NET_RAW` — so it runs in the same agent without widening its capability set.

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

## SNMP ARP-table harvesting (`arp_table`)

nmap only learns a MAC from the ARP/NDP reply on the **local** segment; ARP does
not cross a router. So a scan of a subnet the agent is not attached to returns
services and OS (routed IP) but no MAC or link-layer hostname. The `arp_table`
scan type closes that gap by asking the device that *does* know — the gateway.

- **Targets are the gateway/L3 devices to query** (their IPs), not the host
  range. The agent walks each device's `ipNetToMediaPhysAddress` column
  (`1.3.6.1.2.1.4.22.1.2`) over SNMP, decoding the IP from the row index and the
  MAC from the value, and emits one observation per cached neighbor.
- **Allowlist-scoped.** Only entries whose IP falls inside the job allowlist are
  reported, so a scan never surfaces addresses it was not authorized to learn.
- **Unprivileged.** SNMP is UDP/161 from a normal socket — no `NET_RAW`, no
  change to the agent's capabilities. A `DiscoveryRouter` sends `arp_table` jobs
  to the SNMP backend and everything else to nmap.
- **Credentials live on the agent.** v2c read community via
  `AGENT_SNMP_COMMUNITY` (default `public`); also `AGENT_SNMP_VERSION` (`2c`),
  `AGENT_SNMP_PORT` (161), `AGENT_SNMP_TIMEOUT` (s), `AGENT_SNMP_RETRIES`. The
  secret never reaches the app's job records or audit log. The config is shaped
  for SNMPv3 to drop in later. See ADR 0006.
- **Mode.** `passive` runs no query (no packets); any active mode runs the walk
  (mode does not change SNMP depth). A gateway that cannot be reached yields a
  per-target `snmp_failed` error and the job still succeeds for the rest.

SNMP observations flow through the **same** review queue and reconciliation as
nmap's, keyed by IP — so an `arp_table` MAC merges onto the same discovery row an
nmap service scan produced for that host, rather than replacing it. Vendor is
filled at import time from the built-in OUI table (`macaddr.Analyze`).

`internal/scanner/agent/snmp.go` walks and parses the table behind an injectable
SNMP session, so OID/MAC decoding and allowlist filtering are unit-tested without
a real device.

## SNMP device inventory (`snmp_inventory`)

Where `arp_table` recovers a device's view of its *neighbors*, `snmp_inventory`
asks a device about *itself*: what it is, and the IP↔MAC mapping for its own
interfaces. Most managed gear (routers, switches, printers, servers, hypervisors)
self-reports this over the standard MIB-II groups — facts nmap cannot fingerprint
reliably across a router.

- **Targets are the device(s) to inventory** (their IPs), handled by the same SNMP
  backend (the `DiscoveryRouter` routes both `arp_table` and `snmp_inventory` to
  it). For each target the agent issues one `Get` for the system group
  (`sysDescr`/`sysObjectID`/`sysUpTime`/`sysContact`/`sysName`/`sysLocation`) and
  walks `ipAdEntIfIndex` (IP→ifIndex), `ifPhysAddress` (ifIndex→MAC) and `ifDescr`
  (ifIndex→name).
- **One observation per in-scope IP the device owns,** each enriched with the
  device's name (→ hostname), `sysDescr` (→ OS detail) and a coarse OS-family
  guess, plus the MAC of that IP's interface. sysLocation/contact/uptime and
  `sysObjectID` ride along as evidence.
- **Allowlist-scoped, deduped, best-effort.** Only owned IPs inside the job
  allowlist are reported, deduped by IP across targets. A failed system `Get` is a
  per-target `snmp_failed` (SNMP not answering); the table walks are best-effort,
  so a device that hides `ifTable` still yields its identity. A reachable device
  with no in-scope owned address records itself against the in-scope target IP.
- **Vendor via OUI, not `sysObjectID`.** SNMP interfaces report real MACs, so
  vendor is filled at import from the OUI table (`macaddr.Analyze`) as usual;
  `sysObjectID` is surfaced as evidence rather than mapped through a brittle
  enterprise-number table.

Unprivileged (UDP/161, no `NET_RAW`), no new dependency, no schema change —
observations flow through the **same** review queue and reconciliation as nmap and
`arp_table`, so an inventory record, an ARP-harvested MAC, and an nmap service
scan all merge onto one discovery row per IP. A multi-homed device imports as one
device per distinct interface MAC under the existing MAC-keyed import (deduping by
name is future VLAN/interface-mapping work). See ADR 0007.

## Review queue (`/discoveries`)

The agent never mutates IPAM data. The orchestrator persists each successful
observation into `scan_discoveries` (`store.UpsertDiscovery`), keyed by IP:

- A new host appears as **pending**.
- Re-observing a host refreshes its details and `last_seen_at`, but does not
  resurrect an already **imported** or **dismissed** host.

In the UI an operator either:

- **Imports** a discovery: it is placed into the managed subnet that contains its
  IP (`ip_addresses`, state `assigned`, with hostname) and **always** creates a
  device, stamped with everything the scan exposed — the OS guess (`os_family` /
  `os_detail`), the open services, and the reporting agent (`discovery_source`).
  When a MAC is known it is attached to that device with its OUI vendor and
  private-rotating flag; an existing device that already owns the MAC (or a prior
  import of the same discovery) is reused and refreshed instead of duplicated.
  A MAC-less host (e.g. one scanned over bridged networking) still gets a device,
  named from its hostname or `host-<ip>`. Import is idempotent and refuses only
  if no subnet contains the address. For real MACs (and richer fingerprinting),
  give the agent layer-2 visibility with the macvlan overlay (see
  [`docs/SCANNER_AGENT.md`](SCANNER_AGENT.md#layer-2-discovery-mac-addresses-with-macvlan)).
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

### Auto-import for trusted agents

Each agent carries an `auto_import` flag (`scan_agents.auto_import`, migration 8;
toggled on the agent form, shown as an "Auto-import" badge on `/agents`). When it
is set, the orchestrator imports the agent's observations as soon as they are
recorded (`maybeAutoImport`) instead of leaving them pending — but only when the
observation is **new or match** and still **pending**. Conflicts are never
auto-imported; they always stay in the queue for an operator. An observation
whose address has no containing subnet is left pending rather than failing. Each
auto-import is audited (`scan.discovery.imported`, actor system) alongside a
per-job `scan.discovery.auto_imported` count.

The default stays review-first: a freshly enrolled or manually registered agent
has `auto_import` off until an operator opts in.

### Merge-on-rescan (keeping imported devices current)

A discovery row merges fields from every scan that hits the same IP (an nmap
service scan, an SNMP/ARP MAC harvest, an SNMP inventory record all accumulate on
one row; a richer earlier value is never overwritten by a later empty one). But a
**device** used to be written only at the moment of import, so whichever scan
imported first won and later scans never reached the device — an nmap-then-ARP
pair (common for hosts a router away, where services come over L3 and the MAC only
over ARP) left the device missing either its services or its MAC.

Now, when a scan observes a host whose discovery is **already imported** and
**not conflicting**, the orchestrator re-syncs the merged findings onto the linked
device (`syncImported` → `store.SyncImportedDiscovery`): the OS guess, the open
services, the discovery source, and any newly seen MAC (with its OUI vendor). This
runs on **every** scan regardless of the agent's `auto_import` flag — importing
the host was already the operator's decision to manage it, and a sync creates no
new IPAM records, it only refreshes the existing device. It never renames the
device (an operator may have named it), never wipes a richer value with an empty
one, and skips conflicts (those stay in the queue for an operator). A per-job
`scan.discovery.synced` count is audited. Devices imported before this behavior
existed self-heal on their next scan.

## Scan result detail (`/scans/{id}`)

A finished job stores the agent's full `ScanResult` JSON. The detail page parses
it (`parseScanResult`) and renders, per discovered host, a card with the MAC, OS
family/detail, a services table (port/protocol, state, service name, product,
version), and any evidence the agent attached. Surfaced scan errors get their own
section. The raw JSON remains available in a collapsed block for debugging. A
job with no parseable result (e.g. a failed dispatch) falls back to just the error
and the raw block.

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
5. Open a finished scan under `/scans` to inspect per-host services/OS evidence.
6. Review hits under `/discoveries`; import the ones you want. To skip the queue
   for a trusted agent, enable **Auto-import** on its agent form.

To recover MACs for a subnet the agent cannot reach at Layer 2, run an
`arp_table` scan instead: set `AGENT_SNMP_COMMUNITY` to match your gateway, pick
the **arp_table** scan type and any active mode, and put the **gateway IP(s)** in
Targets. The discovered IP↔MAC pairs land in the same `/discoveries` queue.

To learn what a device is (and the MACs of its own interfaces), run an
**snmp_inventory** scan with the same community: pick the type and any active
mode, and put the **SNMP device IP(s)** in Targets. Each device's name, OS, and
interface IP↔MAC mapping land in the same `/discoveries` queue.
