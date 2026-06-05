# ADR 0007: SNMP Device Inventory

## Status

Accepted.

## Context

ADR 0005 (nmap) and ADR 0006 (SNMP ARP-table harvesting) recover *that a host
exists* and *its IP↔MAC binding*. Neither reliably answers *what the device is*.
nmap's OS fingerprinting needs Layer-2 reach or open ports and is a guess; across
a router it usually comes back empty or low-confidence. Yet most managed devices —
routers, switches, printers, servers, hypervisors, UPSes — will plainly state
their own identity over SNMP: a textual description (`sysDescr`), an
administrative name (`sysName`), a location/contact, an uptime, and the IP↔MAC
mapping for every interface they own (`ifTable` joined with `ipAddrTable`).

Reading that costs one SNMP `Get` plus a few table walks and needs no privilege —
the same UDP/161 path ADR 0006 already established. It is the natural next Phase 4
source: it enriches the discovery records with real device identity and recovers
the MACs of a device's *own* interfaces (distinct from the ARP cache, which is the
device's view of its *neighbors*).

## Decision

- **A new `snmp_inventory` scan type, handled by the existing SNMP backend.** The
  `DiscoveryRouter` now routes both `arp_table` and `snmp_inventory` to the one
  `SNMPDiscoverer`; `Discover` shares the job preamble (passive/version/targets/
  allowlist) then dispatches by type to `discoverARP` or `discoverInventory`. The
  agent core is unchanged — it still calls one `Discoverer`.
- **Targets are the device(s) to inventory, not a host range.** For each target
  the agent issues one `Get` for the system-group scalars
  (`sysDescr`/`sysObjectID`/`sysUpTime`/`sysContact`/`sysName`/`sysLocation`) and
  walks `ipAdEntIfIndex` (IP→ifIndex), `ifPhysAddress` (ifIndex→MAC) and `ifDescr`
  (ifIndex→name). It joins these and emits **one observation per in-scope IP the
  device owns**, each carrying the shared identity (name → hostname, sysDescr →
  OSDetail, a coarse `OSFamily` guess) and the MAC of that IP's interface.
- **Allowlist-scoped, deduped, best-effort.** Only owned IPs inside the job
  allowlist are reported; observations are deduped by IP across targets. The
  system `Get` failing is fatal *for that target* (`snmp_failed`) — it means SNMP
  is not really answering — while the table walks are best-effort enrichment, so a
  device that hides `ifTable` still yields its identity and any addresses it did
  expose. If a reachable device owns no in-scope address, the in-scope target IP
  itself records the device so the inventory is not lost.
- **No new privilege, no new dependency, no schema change.** SNMP is ordinary
  UDP/161 (no `NET_RAW`); gosnmp is already vendored (ADR 0006); observations
  reuse the existing `scan_discoveries` columns. The read community still lives
  only on the agent (`AGENT_SNMP_COMMUNITY`); v2c only, `SNMPConfig` shaped for
  v3 as before.
- **Vendor stays an OUI lookup; `sysObjectID` is evidence.** A device's SNMP
  interfaces report real MACs, so import-time OUI matching (`macaddr.Analyze`)
  already fills vendor. Rather than maintain a brittle SMI enterprise-number
  table, `sysObjectID` is surfaced as evidence for a human (and for future
  mapping). The full `sysDescr` is preserved as `OSDetail`; `OSFamily` is only a
  coarse grouping hint (Linux/Windows/Cisco IOS/JunOS/RouterOS/BSD/macOS, else
  empty).
- **Observations reuse the existing pipeline.** They flow through
  `UpsertDiscovery` → review-queue → reconciliation → import like every other
  source. The #41 service-list-preservation merge means a service-less inventory
  observation enriches (rather than wipes) an nmap row for the same IP, and an
  ARP-harvested MAC and an inventory record merge on one discovery.

## Consequences

- LightIPAM learns what a device is and the MACs of its own interfaces — data
  nmap cannot fingerprint reliably across subnets — from a single unprivileged
  SNMP exchange, reusing the whole review/import path.
- A **multi-homed device** (a distinct MAC per interface) imports as one device
  *per distinct interface MAC* under the current MAC-keyed import logic; the
  observations all share `sysName` but the importer keys on MAC. Deduping
  multi-interface devices by name belongs with the future VLAN/interface-mapping
  work and is deliberately out of scope here — the import path is untouched.
- IPv4 only, matching the rest of the scanner; `ipAddrTable` is the IPv4 table.
- Accuracy depends on the device exposing the standard MIB-II groups under the
  configured community. Devices that restrict the `system` group will surface a
  per-target `snmp_failed` and the job still succeeds for the rest.
- One read community per agent, as in ADR 0006; mixed-community estates and
  SNMPv3 remain deferred behind the existing config shape.
