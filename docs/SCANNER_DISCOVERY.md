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

SNMP harvesting and NetBIOS/mDNS name resolution (below) are the exceptions that
prove the rule: they are active discovery that needs **no** extra privilege —
ordinary unicast UDP (161 for SNMP, 137/5353 for names), no `NET_RAW` — so they run
in the same agent without widening its capability set.

## Scan depth (mode → nmap)

Scan **type** selects what to collect; scan **mode** selects intensity. Mode is a
depth knob for the nmap scan types only — `arp_table`, `snmp_inventory`,
`name_lookup`, `dns_lookup`, `dhcp_leases`, `lldp_cdp`, and `combined` ignore it (combined always runs at full depth), so
the scan form hides the Mode picker for those. The protocol still defines a
`passive` mode (the agent's no-packets short-circuit), but it produces zero results
for every backend, so it is no longer offered as a UI choice; the depths are
Light / Standard / Deep.

| Mode              | nmap behavior                                                  |
| ----------------- | ------------------------------------------------------------- |
| `light_active`    | Top-1000 TCP service detection (`-sV`).                       |
| `standard_active` | Top-1000 + exhaustive versions (`--version-all`) + OS (`-O`). |
| `deep_active`     | Every TCP port (`-p-`) with service detection (`-sV`) + OS, tuned for speed: `-T4`, `--min-rate 1000`, `--max-retries 2`, and no default rate cap. Drops `--version-all` so the all-port sweep stays fast. |

| Type                | Adds                                                           |
| ------------------- | ------------------------------------------------------------- |
| `host_discovery`    | `-sn` ping/ARP sweep, no port scan (mode ignored).            |
| `service_detection` | `-sV` over the mode's ports; `--version-all` on standard. |
| `os_probe`          | `-O`; standard/deep also add `-sV` over the mode's ports.     |
| `combined`          | Deep nmap (all ports, `-sV` + `-O`) **plus** SNMP ARP harvest, SNMP inventory, NetBIOS/mDNS name lookup, DNS name lookup, DHCP lease lookup, and LLDP/CDP neighbor harvest of the targets, merged per host (see below). |
| `arp_table`         | SNMP walk of a gateway's ARP cache, no nmap (mode ignored).   |
| `snmp_inventory`    | SNMP read of a device's identity + interfaces + VLAN, no nmap (mode ignored). |
| `name_lookup`       | NetBIOS (UDP/137) + mDNS (UDP/5353) name query, no nmap (mode ignored). |
| `dns_lookup`        | DNS reverse (PTR) + forward-confirm name query, no nmap (mode ignored). |
| `dhcp_leases`       | Read active leases from the DHCP server's lease file on the agent, no nmap (mode ignored). |
| `lldp_cdp`          | SNMP read of a switch/router's LLDP + CDP neighbor caches, no nmap (mode ignored). |

Job rate limits map to `--max-rate` / `--max-parallelism`; the job timeout maps
to `--host-timeout` and feeds the agent/app budgets (see "Timeouts" below).

### Staged scan methodology

nmap scans run in stages, mirroring how a human narrows down a host, so probing
is never wasted on dead address space:

1. **Host discovery** — a fast `-sn` sweep (`-T4`) over the raw targets finds which
   hosts are alive (and, on the local segment, their MAC/vendor). A target range
   with nothing alive short-circuits here, before any port scan.
2. **Port + service/OS detection** — only the live hosts are handed to a second
   pass that skips re-discovery (`-Pn`), scans the mode's ports, and lets nmap
   version-probe (`-sV`) **only the ports it finds open**, plus OS detection where
   the type calls for it.

Stage-1 (alive + MAC) and stage-2 (services + OS) findings are merged per IP
(`mergeObservations`), so a host ends up as one record. `host_discovery` is just
stage 1; the SNMP scan types are unaffected (they are not nmap).

`internal/scanner/agent/nmap.go` builds each stage's argument list and parses
nmap's XML (`-oX -`). The command runner is injectable, so argument building, the
staged pipeline, and XML parsing are unit-tested without nmap or raw-socket
privileges.

### Timeouts

`ScanJob.TimeoutSeconds` is the **per-host** budget (nmap's `--host-timeout`). The
form leaves it blank by default and the app fills a generous per-type default
(`app.defaultTimeoutForType`: host_discovery 120s, service_detection 600s, os_probe
900s, combined 1200s, arp_table 180s, snmp_inventory 300s, name_lookup 120s,
lldp_cdp 300s). From that per-host
budget, `scanner.ScanBudget(perHost, targets)` derives the **whole-job** budget
(`perHost × host-count + discovery allowance + grace`, capped at 4h). Both the
agent (supervising the discoverer) and the app (bounding the blocking dispatch
HTTP call) compute their deadline from `ScanBudget`, so the app always outlasts the
agent — fixing the multi-host "context deadline exceeded" where the app gave up
after `perHost + 10s` while the agent needed `perHost × hosts`.

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
- **VLAN and interface mapping.** Each owned IP carries the **802.1Q access VLAN**
  of its interface, read from the Q-BRIDGE-MIB `dot1qPvid` table and joined to the
  interface through `dot1dBasePortIfIndex` (bridge port → ifIndex); `dot1qVlanStaticName`
  names the VLAN. The interface's operational status (`ifOperStatus`, up/down) and
  the VLAN (with name) ride as evidence. On import (and on every re-sync), a
  discovered VLAN **fills the containing subnet's VLAN when it has none** — never
  overwriting an operator-set value — so VLAN findings surface on the Subnets page;
  the device's linked-addresses list shows each address's subnet VLAN. All the VLAN
  walks are best-effort: a device that is not an 802.1Q bridge simply yields no VLAN
  and keeps the rest of its inventory.
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

## Name resolution (`name_lookup`)

Where nmap recovers a hostname only when DNS has a PTR record, `name_lookup` asks
a host *directly* for its name over two unprivileged UDP protocols — recovering
names for the many small-business hosts that have no DNS record at all:

- **NetBIOS node status** (UDP/137). The agent sends an NBSTAT query for the
  wildcard name `*`; a Windows or Samba host replies with the NetBIOS names it has
  registered. The unique suffix-`0x00` name is the **machine name** (→ hostname);
  the group suffix-`0x00` name is the **workgroup/domain** (→ evidence). The query
  is unicast, so unlike multicast mDNS it **works across subnets**.
- **mDNS reverse lookup** (UDP/5353). The agent sends a unicast PTR query for the
  host's `<reversed>.in-addr.arpa` name with the QU (unicast-response) bit set; an
  Apple/Linux/IoT responder (Bonjour/avahi) answers with its `.local` name. mDNS
  is primarily link-local, so cross-subnet replies are best-effort.

Per target the agent attempts both and folds them into **one observation**:
NetBIOS leads the hostname, mDNS fills it only if NetBIOS was silent, and both ride
as evidence (`netbios` / `mdns` sources). Targets must be single IPv4 hosts (each
probe is a unicast query to one device); a CIDR or a host that answers neither
protocol is reported as a per-target `name_unresolved` notice, never a job
failure.

`internal/scanner/agent/names.go` (`NameDiscoverer`) builds and parses the NetBIOS
and DNS wire formats with the standard library — **no new dependency** — behind an
injectable `udpExchanger` so the packet encoders/parsers are unit-tested without a
socket. Both protocols are ordinary unicast UDP: **no `NET_RAW`, no new privilege**
(tunable via `AGENT_NETBIOS_PORT` / `AGENT_MDNS_PORT` / `AGENT_NAME_TIMEOUT`).
Observations reuse the **same** review queue and reconciliation as every other
source, so a name merges onto the same discovery row as an nmap service scan, an
ARP MAC, and an SNMP inventory record. See ADR 0010.

## DNS name enrichment (`dns_lookup`)

Where `name_lookup` recovers names for hosts with **no** DNS record (NetBIOS/mDNS),
`dns_lookup` reads the authoritative DNS the network already runs — the common case
for managed hosts — and forward-confirms it:

- **Reverse then forward.** Per target the agent does a reverse (PTR) lookup to
  learn the IP's name, then a forward (A) lookup of that name. The PTR name becomes
  the observation's hostname (FQDN, trailing dot trimmed); whether the forward
  lookup maps back to the same IP rides as `dns` evidence ("forward-confirmed" or
  "forward lookup did not confirm"). A stale or hijacked PTR is surfaced, not
  trusted blindly — but the name is still kept.
- **Targets are single hosts.** A reverse lookup is per-address, so a CIDR target is
  a per-target `dns_unresolved` notice rather than expanded. An address with no PTR
  record is likewise a per-target `dns_unresolved` notice, never a job failure.
- **Resolver on the agent.** With `AGENT_DNS_SERVER` set the agent queries that
  resolver directly (host or host:port, defaulting to `:53`); otherwise it uses the
  agent's system resolver. `AGENT_DNS_TIMEOUT` (seconds) bounds each lookup.
- **Unprivileged, no new dependency.** Resolution uses the standard library's
  `*net.Resolver` over ordinary UDP/TCP/53 — no `NET_RAW`. The resolver sits behind
  an injectable interface so the reverse/forward decoding is unit-tested with no
  real DNS.

`dns_lookup` is the fourth best-effort enrichment pass folded into `combined`, and
its names flow through the **same** review queue and reconciliation as every other
source, so a DNS name merges onto the same discovery row (and device) as an nmap
service scan, an ARP MAC, an SNMP inventory record, and a NetBIOS/mDNS name. See
`internal/scanner/agent/dns.go`, ADR 0012.

## DHCP lease ingestion (`dhcp_leases`)

A DHCP server holds the authoritative IP↔MAC binding and the **client-supplied
hostname** (option 12) for every lease — often the most accurate name a host has on
a small LAN. `dhcp_leases` ingests that record from the server's lease file:

- **Reads a lease file, not the wire.** The agent reads the configured lease file
  (`AGENT_DHCP_LEASE_FILE`, mounted read-only into the agent) and emits one
  observation per **active** lease — IP, MAC, client hostname — with the lease
  state/expiry as `dhcp` evidence. Active DHCP probing would need raw sockets; reading
  a file needs no privilege.
- **Two formats, auto-sniffed.** `AGENT_DHCP_LEASE_FORMAT` selects `isc` (ISC
  dhcpd's `dhcpd.leases` blocks) or `dnsmasq` (one line per lease); the default
  (`auto`) sniffs the file. ISC keeps only `binding state active` leases, last block
  per IP winning.
- **Targets scope which ranges to ingest.** The data source is a local file, so the
  job's targets (host or CIDR) select which leases to emit; the allowlist still bounds
  the targets. In a `combined` scan the per-host targets limit DHCP to the hosts being
  scanned.
- **Opt-in, never fatal.** With no lease file configured, a standalone scan reports a
  clear `dhcp_unconfigured` notice (set `AGENT_DHCP_LEASE_FILE`); inside `combined` it
  is a muted "Skipped" line. A read/parse error is likewise a per-job notice.

`dhcp_leases` is the fifth best-effort enrichment pass folded into `combined`, and
its findings flow through the **same** review queue and reconciliation as every other
source, so a lease's MAC and hostname merge onto the same discovery row (and device)
as nmap services, an ARP MAC, an SNMP inventory record, and a DNS/NetBIOS name. See
`internal/scanner/agent/dhcp.go`, ADR 0014.

## LLDP/CDP neighbor harvesting (`lldp_cdp`)

Where the other sources answer "what is at this IP?", `lldp_cdp` answers "how is
the network wired?". A managed switch or router passively records the neighbors it
hears on each port — over the vendor-neutral **LLDP** and Cisco's **CDP** — and
exposes both caches over SNMP. Asking one core switch typically reveals its whole
directly-connected neighborhood at once.

- **Targets are the switch/router IPs to query**, not a host range. The agent
  walks the **CISCO-CDP-MIB** `cdpCacheTable` and the **LLDP-MIB** `lldpRemTable`
  (+ `lldpRemManAddrTable`) and emits one observation per neighbor.
- **Both protocols, merged per neighbor.** CDP carries the neighbor IP, device id,
  platform, and remote port directly. LLDP carries the IP in its management-address
  table (joined to the neighbor row by the shared `timeMark.localPort.remIndex`
  index), the system name/description, the remote port, and — when the chassis id
  is MAC-typed — the neighbor's **MAC**. A neighbor seen via both protocols, or via
  two switches, is merged by IP (`mergeObservations`). The reporting device,
  protocol, and remote port ride as evidence (`cdp` / `lldp` sources).
- **Only neighbors with a management IP are emitted.** IPAM keys on an address, so
  a neighbor that advertises none (common for endpoints) is dropped — pair an
  `lldp_cdp` scan with `arp_table` / nmap to place those by IP. IPv4 only: a
  non-IPv4 LLDP management address is skipped.
- **Unprivileged, no new dependency.** SNMP is UDP/161 from a normal socket — no
  `NET_RAW`. The one `SNMPDiscoverer` handles `arp_table`, `snmp_inventory`, and
  `lldp_cdp`; the `DiscoveryRouter` registers it for all three. Same agent-only
  `AGENT_SNMP_*` read community as the other SNMP scans.
- **Non-response is not a failure.** A device that cannot be reached over SNMP is a
  per-target `snmp_failed` error and the job still succeeds for the rest; a
  reachable switch with no neighbors is a clean empty result.

`internal/scanner/agent/neighbors.go` decodes the CDP/LLDP OIDs (and the address
encoded in the LLDP management-address row index) behind the same injectable
`snmpSession` as the other SNMP scans, so the parsing is unit-tested against
hand-built PDUs with no device. Observations reuse the **same** review queue and
reconciliation as every other source, so a neighbor record merges onto the same
discovery row as an nmap service scan, an ARP MAC, an SNMP inventory record, and a
name. See ADR 0011.

## Combined scan (`combined`)

`combined` runs every backend in one job and merges their findings into the most
complete picture per host. The crucial move is that the per-host enrichment passes
are aimed at **the hosts nmap discovers**, not the raw job targets — so a combined
scan of a CIDR (the common case) recovers MACs and SNMP inventory, because nmap
expands the range into live hosts and the enrichment passes then query each of
them. A combined scan does:

- a **deep nmap** scan (every TCP port, `-sV` + `-O`) of the targets — the core of
  the job, which also yields the live-host list,
- against each discovered host (unioned with any bare-IP targets the operator
  listed, so a silent gateway/switch is still queried): an **SNMP inventory**
  (`snmp_inventory`), and — only when the host answered SNMP — an **SNMP ARP
  harvest** (`arp_table`) and an **LLDP/CDP neighbor harvest** (`lldp_cdp`); plus a
  **NetBIOS/mDNS name lookup** (`name_lookup`) and a **DNS name lookup**
  (`dns_lookup`), and
- a **DHCP lease lookup** (`dhcp_leases`) over the whole target range (if a lease
  file is configured on the agent) — leases can name hosts that are currently
  offline, which nmap never sees.

The per-host passes run through a bounded worker pool (`enrichWorkers`), so a /24's
worth of SNMP/name/DNS timeouts overlap instead of serializing. The **SNMP
short-circuit** — running inventory first and the two other SNMP passes only if the
host answered — keeps a plain (non-SNMP) host to a single timeout rather than three.

nmap is authoritative: if it fails, the combined job fails. The enrichment passes
are **best-effort** — a host that does not answer SNMP, a name protocol, or DNS (or
a source that is not configured) is reported as *ignored*, never failed. To keep the
detail view readable, per-host non-responses are **collapsed** into one notice per
pass (`"SNMP inventory skipped: N hosts did not respond"`) rather than one per host.
Ignored notices carry the `scan_ignored` code; the orchestrator never promotes them
to the job's headline error, and `/scans/{id}` renders them in a muted **Skipped**
section rather than as red errors.

`internal/scanner/agent/combined.go` (`CombinedDiscoverer`) composes the nmap core
with the SNMP, name, DNS, and DHCP discoverers (the `arp_table` and `lldp_cdp`
passes reuse the SNMP discoverer). It forces the nmap sub-job to deep mode, expands
enrichment to `unionHosts(observedIPs(nmap), hostTargets(targets))`, fans the
per-host passes out concurrently, and merges the per-IP observations
(`mergeObservations`: the leading nmap source wins scalar fields, the SNMP-inventory
hostname/VLAN fill before the name/DNS passes, services union by port, evidence
concatenates). Because the discovery store already merges by IP (`ON CONFLICT (ip)`),
the consolidated observations land on one discovery row and, once imported, on one
device (see Merge-on-rescan). See ADRs 0008, 0010, 0011, and 0015.

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
services, the discovery source, and any newly seen MAC (with its OUI vendor). It
also backfills the imported **address's hostname** when that address has none yet,
so a name learned by a later scan — a `name_lookup` NetBIOS/mDNS name or an
`lldp_cdp` neighbor's system name — reaches a host nmap had imported without one;
an existing hostname is left intact. This runs on **every** scan regardless of the
agent's `auto_import` flag — importing the host was already the operator's decision
to manage it, and a sync creates no new IPAM records, it only refreshes the
existing device. It never renames the device (an operator may have named it), never
wipes a richer value with an empty one, and skips conflicts (those stay in the
queue for an operator). A per-job `scan.discovery.synced` count is audited. Devices
imported before this behavior existed self-heal on their next scan.

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

To map physical topology — which devices are wired to which switch ports — run an
**lldp_cdp** scan with the same community: pick the type and any active mode, and
put the **switch/router IP(s)** in Targets. Each device's LLDP and CDP neighbors
(with the remote port as evidence) land in the same `/discoveries` queue.
