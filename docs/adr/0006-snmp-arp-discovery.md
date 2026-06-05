# ADR 0006: SNMP ARP-Table Discovery

## Status

Accepted.

## Context

nmap (ADR 0005) recovers a host's MAC address from the ARP/NDP reply on the
local segment. ARP is link-layer and does not cross a router, so when the agent
scans a subnet it is not directly attached to, service and OS detection work
(they ride on routed IP) but MAC and link-layer hostname come back empty — the
agent only ever sees the gateway's MAC.

A gateway / L3 switch, by contrast, holds the IP↔MAC binding for every subnet it
is directly connected to, in its ARP cache (`ipNetToMediaTable`). Reading that
table over SNMP recovers MACs for hosts the agent cannot reach at Layer 2,
without deploying an agent on every segment.

## Decision

- **A second discovery backend in the agent, selected by scan type.** A new
  `arp_table` scan type routes to an `SNMPDiscoverer` (`internal/scanner/agent`)
  via a small `DiscoveryRouter`; every other type still routes to nmap. The
  agent core is unchanged — it calls one `Discoverer`.
- **Targets are the gateway device(s) to query, not the host range.** For an
  `arp_table` job, `Targets` lists the router/L3-switch IPs. The agent walks each
  device's `ipNetToMediaPhysAddress` column (`1.3.6.1.2.1.4.22.1.2`), decoding the
  IP from the row index and the MAC from the value, and emits one observation per
  cached neighbor. Entries outside the job allowlist are dropped, so a scan never
  reports addresses it was not authorized to learn about.
- **No new privilege.** SNMP is ordinary UDP/161 from a normal socket. Unlike
  nmap it needs no `NET_RAW`; the agent's capability set is unchanged. This is a
  notable property: the highest-value cross-subnet MAC source is also the
  least-privileged backend.
- **gosnmp, isolated behind an interface.** `github.com/gosnmp/gosnmp` does the
  wire protocol; a minimal `snmpSession` interface and injectable dialer keep
  OID/MAC parsing and allowlist filtering unit-tested without a real device.
- **v2c now, structured for v3.** `SNMPConfig` carries the version and reserved
  SNMPv3 fields; only v2c (read community) is wired today. The read credential
  lives on the **agent** (`AGENT_SNMP_COMMUNITY`, default `public`), never in the
  app's job records or audit logs — the secret stays on the scanning component,
  consistent with the security boundary.
- **Observations reuse the existing pipeline.** SNMP observations flow through
  the same `UpsertDiscovery` → review-queue → reconciliation → import path as
  nmap's. The upsert now preserves an earlier non-empty service list when a new
  observation has none, so a MAC-only SNMP harvest merges onto the same IP row as
  an nmap scan instead of clobbering its services. Vendor enrichment happens at
  import time via the existing OUI lookup (`macaddr.Analyze`).

## Consequences

- The system recovers MACs (and the device records that follow) for hosts on
  subnets the agent cannot reach at Layer 2, by asking the gateway that can.
- Accuracy depends on the gateway's ARP cache: only recently-active neighbors
  appear, and entries age out. Re-scanning refreshes them; this is advisory data
  an operator imports, same as nmap.
- One read community per agent for the MVP. Mixed-community estates and SNMPv3
  (user/auth/priv) are deferred but the config shape already accommodates them.
- IPv4 only, matching the rest of the scanner. The newer `ipNetToPhysicalTable`
  (IPv6-capable) can layer in later behind the same discoverer.
- The agent gains an outbound UDP/161 dependency to the gateways; if SNMP is
  disabled or the community is wrong, the target reports a per-target
  `snmp_failed` scan error and the job still succeeds for any reachable gateways.
