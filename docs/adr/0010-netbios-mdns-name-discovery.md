# ADR 0010: NetBIOS / mDNS Name Discovery

## Status

Accepted.

## Context

nmap (ADR 0005) recovers a hostname only when DNS has a PTR record for the host —
it does a reverse lookup, nothing more. SNMP inventory (ADR 0007) recovers a name
only for SNMP-capable managed gear. Neither helps the most common small-business
case: ordinary Windows PCs, Macs, phones, printers, and IoT devices that have **no
DNS record at all**. Those hosts will, however, plainly state their own name when
asked directly:

- A **NetBIOS node-status** query (NBSTAT, UDP/137) makes a Windows or Samba host
  enumerate its registered NetBIOS names — including its machine name and
  workgroup. The query is **unicast**, so it works across subnets (the agent's
  exact cross-router scenario).
- A **unicast mDNS** reverse query (UDP/5353) makes an Apple/Linux/IoT responder
  (Bonjour/avahi) return its `.local` name. mDNS is primarily link-local, so
  cross-subnet replies are best-effort, but on the agent's own segment it is
  reliable.

Both are ordinary unicast UDP — the same unprivileged path SNMP already
established (ADR 0006). This is the natural next Phase 4 source, and the user
asked for it to be folded into the existing `combined` scan alongside nmap + ARP +
SNMP inventory.

## Decision

- **A new `name_lookup` scan type with its own backend.** `NameDiscoverer`
  (`internal/scanner/agent/names.go`) implements the `Discoverer` interface; the
  `DiscoveryRouter` routes `name_lookup` to it. Per target it sends both an NBSTAT
  query and a unicast mDNS reverse query and folds the results into **one
  observation**: NetBIOS leads the hostname (a machine name is more meaningful than
  a `.local` name), mDNS fills it only if NetBIOS was silent, and both ride as
  evidence (`netbios` / `mdns` sources); the NetBIOS workgroup is evidence too.
- **Targets are single hosts; non-response is not a failure.** A name probe is a
  unicast query to one device, so a CIDR target is reported as a per-target
  `name_unresolved` notice rather than expanded. A host that answers neither
  protocol — most hosts do not run these services — is likewise a per-target
  `name_unresolved` notice, never a job failure.
- **Folded into `combined` as a third best-effort pass.** `CombinedDiscoverer`
  now composes nmap + SNMP + names; after the deep nmap core and the two SNMP
  passes it runs `name_lookup` over the single-host targets. As with SNMP, a silent
  host or CIDR target is downgraded to a `scan_ignored` notice, so a combined scan
  of a plain host still succeeds with whatever was learned. The findings merge per
  IP (`mergeObservations`) onto one observation.
- **Standard library, no new dependency.** The NetBIOS and DNS wire formats are
  built and parsed directly (first-level NetBIOS name encoding, DNS label encoding,
  DNS compression-pointer following). The socket I/O sits behind an injectable
  `udpExchanger`, so the encoders/parsers are unit-tested against hand-built packet
  bytes with no network. This matches how `gosnmp` sits behind `snmpSession`.
- **No new privilege.** Both protocols are ordinary unicast UDP from an ephemeral
  port (137/5353 destination); no raw sockets, no `NET_RAW`. The agent's capability
  set is unchanged. Ports and the per-probe timeout are tunable via
  `AGENT_NETBIOS_PORT` / `AGENT_MDNS_PORT` / `AGENT_NAME_TIMEOUT`.
- **Reuses the existing pipeline.** Observations flow through `UpsertDiscovery` →
  review queue → reconciliation → import like every other source, so a name merges
  onto the same discovery row (and, once imported, the same device) as an nmap
  service scan, an ARP-harvested MAC, and an SNMP inventory record. No schema
  change.

## Consequences

- LightIPAM recovers hostnames for the large class of hosts with no DNS PTR record
  — and, via unicast NetBIOS, across subnets — from unprivileged UDP queries,
  reusing the whole review/import path.
- mDNS cross-subnet resolution is unreliable by design (the protocol is link-local
  and a responder may answer a unicast query with a multicast reply our connected
  socket never sees). NetBIOS is the dependable cross-subnet name source; mDNS is
  bonus enrichment, strongest on the agent's own segment.
- A connected UDP socket only accepts datagrams from the queried host, so a stray
  reply from another host is ignored; an ICMP port-unreachable surfaces as a normal
  "no name" result.
- IPv4 only, matching the rest of the scanner (the mDNS reverse query uses
  `in-addr.arpa`).
- Names are *not* used to dedupe multi-homed devices; import still keys on MAC.
  Name-based device consolidation remains future VLAN/interface-mapping work, as in
  ADR 0007.
- A future SMB/NetBIOS-MAC or richer service enumeration could layer onto the same
  backend (the NBSTAT statistics block carries the adapter MAC), but is out of
  scope here — this ADR is about names.
