# ADR 0013: VLAN and Interface Mapping

## Status

Accepted.

## Context

The `snmp_inventory` scan (ADR 0007) already reads a device's interfaces — joining
`ipAddrTable` (IP → ifIndex), `ifPhysAddress` (ifIndex → MAC), and `ifDescr`
(ifIndex → name) — and emits one observation per owned IP carrying that interface's
MAC and name. The remaining Phase 4 item is **VLAN and interface mapping**: which
VLAN each interface/IP sits on, and richer per-interface detail.

VLAN membership is the missing piece IPAM cares about most, because a VLAN maps
directly to a subnet. Managed switches expose it over the standard 802.1Q
**Q-BRIDGE-MIB** (RFC 4363): `dot1qPvid` gives each bridge port's untagged (access)
VLAN, and `dot1qVlanStaticName` names the VLANs. The catch is that `dot1qPvid` is
keyed by *bridge port*, not ifIndex, so it must be joined to the interface through
the base BRIDGE-MIB's `dot1dBasePortIfIndex` (bridge port → ifIndex) to reach the
IP. This is all standard, widely implemented, and — like the rest of SNMP discovery
— unprivileged UDP/161.

## Decision

- **Extend `snmp_inventory`; no new scan type.** VLAN/interface mapping is an
  enrichment of the inventory the agent already gathers, and folding it in keeps the
  scan-type list small (the "simple but powerful" goal) — a `combined` scan and any
  `snmp_inventory` scan get it for free. `walkInventory` adds three best-effort
  Q-BRIDGE walks (`dot1dBasePortIfIndex`, `dot1qPvid`, `dot1qVlanStaticName`) plus
  `ifOperStatus`, joins bridge port → ifIndex → VLAN, and stamps each owned IP's
  observation with its interface's access VLAN. The interface (name, ifIndex,
  up/down) and VLAN (with name) ride as evidence.
- **A structured `VLAN` field on the observation.** `scanner.Observation` gains
  `VLAN int` (0 = unknown), carried through `scan_discoveries.vlan` (migration 11)
  and the discovery merge (a non-zero VLAN is preserved when a later MAC-only source
  merges onto the same IP, mirroring the service-list merge).
- **VLAN findings reach the Subnets page by backfill.** On import — and on every
  re-sync of an already-imported host — a discovered VLAN fills the **containing
  subnet's** VLAN when it has none (`backfillSubnetVLAN`, `cidr >>= ip`). It never
  overwrites an operator-set VLAN and is a no-op when the VLAN is unknown or no
  managed subnet contains the IP. This is the one piece of subnet metadata a scan
  writes; it is conservative (empty-only) and reversible by an operator, matching
  the "best-effort, verify before relying" stance of the rest of discovery.
- **Surfaced where an operator looks.** The scan detail card shows the VLAN, the
  discovery review queue shows a VLAN badge, the device's linked-addresses list
  shows each address's subnet VLAN, and the subnet page already renders VLAN (now
  auto-populated).
- **No new privilege, dependency, or scan type.** UDP/161, `gosnmp` already in tree,
  OID parsing behind the same injectable `snmpSession` so the bridge-port join and
  VLAN decoding are unit-tested against hand-built PDUs with no device.

## Consequences

- An `snmp_inventory` (or `combined`) scan of a managed switch now records which
  VLAN each host's interface is on, and that VLAN flows all the way to the subnet —
  closing the loop between L2 discovery and the IPAM subnet model.
- A switch that does not implement the Q-BRIDGE tables (or a plain host) simply
  yields no VLAN; everything else about the inventory is unaffected.
- Access (untagged/PVID) VLANs only. Trunk/tagged-VLAN membership
  (`dot1qVlanCurrentEgressPorts` bitmaps) and per-interface speed/alias are natural
  follow-ups but out of scope here — this ADR delivers the IP→VLAN→subnet mapping.
- IPv4 only, matching the rest of the scanner.
