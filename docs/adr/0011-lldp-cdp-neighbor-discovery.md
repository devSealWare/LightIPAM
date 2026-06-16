# ADR 0011: LLDP / CDP Neighbor Discovery

## Status

Accepted.

## Context

The discovery sources so far answer "what is at this IP?" — nmap probes a host,
SNMP inventory asks a device about itself (ADR 0007), ARP harvesting recovers a
MAC (ADR 0006), name lookup recovers a hostname (ADR 0010). None of them answer
"how is the network physically wired?" — which device is plugged into which switch
port, and what the switch's neighbors are. That topology is exactly what the
link-layer discovery protocols carry:

- **LLDP** (IEEE 802.1AB) is the vendor-neutral standard. Every LLDP-speaking
  device records the neighbors it hears on each port in the **LLDP-MIB**
  (`lldpRemTable`), and exposes each neighbor's management address in
  `lldpRemManAddrTable`.
- **CDP** (Cisco Discovery Protocol) is the Cisco equivalent, exposed through the
  **CISCO-CDP-MIB** (`cdpCacheTable`). Its cache carries the neighbor's IP
  directly, plus its device id, platform, and the port it is reachable on.

A switch already collects all of this passively from the advertisements its
neighbors broadcast. The question is only how the agent reads it. Two options:

1. **Sniff LLDP/CDP frames** off the wire. This needs raw packet capture
   (`NET_RAW`/`CAP_NET_ADMIN`), only sees the agent's own segment, and only hears
   a frame every ~30–60s. It widens the agent's privilege and sees very little.
2. **Read the switch's neighbor tables over SNMP.** This is plain UDP/161 — the
   same unprivileged path ARP/inventory already use — sees the switch's *whole*
   neighbor view at once, and works for any reachable managed switch, not just the
   agent's segment.

Option 2 reuses the existing SNMP backend, dependency (`gosnmp`, ADR 0006), and
credential handling, and adds zero privilege. The user asked for LLDP/CDP to be a
standalone scan and to be folded into the `combined` scan, and for it (and the
name lookup from ADR 0010) to feed the per-IP device-inventory merge.

## Decision

- **A new `lldp_cdp` scan type, handled by the SNMP backend.** `SNMPDiscoverer`
  (`internal/scanner/agent/neighbors.go`, methods on the type defined in
  `snmp.go`) gains a third behavior alongside `arp_table` and `snmp_inventory`;
  its `Discover` switch dispatches `lldp_cdp` to `discoverNeighbors`, and the
  `DiscoveryRouter` registers the one SNMP discoverer for all three types. Targets
  are the **switch/router IPs** to query; the agent emits one observation per
  discovered neighbor.
- **Both protocols, merged per neighbor.** Per target the agent walks the CDP
  cache and the LLDP remote table. CDP gives the neighbor IP as a cache column;
  LLDP gives it via the management-address table, joined back to the remote-table
  row by the shared `<timeMark>.<localPort>.<remIndex>` index. A neighbor seen via
  both protocols (and the same neighbor learned from two switches) is merged by IP
  with the existing `mergeObservations`. An LLDP MAC-typed chassis id becomes the
  neighbor's MAC; the device id / system name becomes the hostname; the platform /
  system description becomes the OS detail; the remote port and protocol ride as
  evidence.
- **Only neighbors with a management IP are emitted.** IPAM keys on an address, so
  a neighbor that advertises no management address (common for endpoints) is
  dropped — there is nothing to record it against. This is a deliberate scope
  limit, not a topology store; mapping port-level adjacency without an IP is future
  VLAN/interface-mapping work.
- **Non-response is not a failure.** A device that cannot be reached over SNMP is a
  per-target `snmp_failed` notice; a reachable switch that simply has no neighbors
  is a clean empty result. In a `combined` scan the whole pass is best-effort: a
  target that is not a switch (or speaks neither protocol) is downgraded to a
  `scan_ignored` notice, exactly like the SNMP and name passes.
- **Folded into `combined` as a fourth enrichment pass.** `CombinedDiscoverer`
  runs `lldp_cdp` through the SNMP backend it already holds (no new constructor
  argument), after nmap + ARP + inventory + names, and merges the result per IP.
- **No new privilege, dependency, or schema.** UDP/161 only; `gosnmp` is already a
  dependency; observations reuse the same review-queue + reconciliation +
  merge-on-rescan path, so a neighbor record merges onto the same discovery row
  (and, once imported, the same device) as every other source. The OID parsing
  sits behind the existing injectable `snmpSession`, so it is unit-tested against
  hand-built PDUs with no device.
- **Names and neighbors reach already-imported hosts.** `SyncImportedDiscovery`
  now also backfills the imported address's hostname when it has none, so a name
  learned later by `name_lookup` or an LLDP/CDP neighbor's system name lands on a
  host that nmap had imported without one. An existing hostname is never
  overwritten.

## Consequences

- LightIPAM can map physical topology — which devices are wired to which switch
  ports — from unprivileged SNMP, reusing the whole discovery pipeline.
- Coverage depends on the gear: LLDP is broad (most managed switches, many APs,
  phones, printers, servers); CDP is Cisco-centric. Querying one core switch
  typically reveals its whole directly-connected neighborhood at once.
- Endpoints without a management address are not imported from LLDP/CDP alone —
  pair an `lldp_cdp` scan with `arp_table` / nmap to place them by IP.
- IPv4 only, matching the rest of the scanner: an LLDP management address with a
  non-IPv4 family, or a CDP address that is not a 4-byte octet string, is skipped.
- The read community is the same agent-only `AGENT_SNMP_*` credential as the other
  SNMP scans; nothing new lands in the app DB or audit log.
- Richer topology (port-to-port adjacency graphs, VLAN membership, link
  aggregation) is out of scope here — this ADR is about turning neighbor tables
  into IP-keyed observations.
