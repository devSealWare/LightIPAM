# ADR 0015: Combined Scan Enriches nmap-Discovered Hosts

## Status

Accepted.

## Context

Phase 4 added six unprivileged discovery sources and a `combined` scan that runs
them all and merges per host (ADRs 0006–0014). In practice an operator points
`combined` at a **CIDR** (e.g. `192.168.10.0/24`) — that is the whole appeal of a
"scan my network" button.

But the combined discoverer restricted its enrichment passes to
`hostTargets(job.Targets)`, which keeps only **bare IPv4 targets and drops every
CIDR**. So a combined scan of a CIDR ran nmap only; the ARP, SNMP-inventory, name,
DNS, DHCP, and LLDP/CDP passes were all skipped with a "needs single-host targets"
notice. The result: `combined` did not recover MAC addresses or SNMP inventory,
while a dedicated `arp_table`/`snmp_inventory` scan aimed at a bare device IP did —
a confusing, broken-feeling split for the scan that is meant to "just work".

The unicast enrichment queries genuinely cannot expand a CIDR themselves (SNMP/
NetBIOS/mDNS/DNS must be aimed at one device). But nmap already expands the range
into a concrete live-host list. That list is the missing input.

## Decision

- **Enrich the hosts nmap discovers, not the raw targets.** After the deep nmap
  stage, the combined discoverer takes the live-host IPs nmap returned
  (`observedIPs`), unions them with any bare-IP targets the operator listed
  (`unionHosts(observedIPs(nmap), hostTargets(targets))` — a silent gateway/switch
  that ignores nmap host discovery but answers SNMP is still queried), and runs the
  per-host passes against that set. A CIDR combined scan now recovers MACs and SNMP
  inventory for every live host.
- **DHCP runs over the whole range,** not the per-host list: it reads a file and can
  report leases for hosts that are currently offline (which nmap never sees), so it
  keeps the job's raw targets as its scope.
- **Bounded-concurrency fan-out.** The per-host passes run through a worker pool
  (`enrichWorkers = 16`) so a /24's worth of network timeouts overlap instead of
  serializing. This is what keeps the broader scan fast.
- **SNMP short-circuit.** Per host the inventory pass runs first; the ARP and
  LLDP/CDP passes — which use the same SNMP transport — run only when the host
  actually answered SNMP. A plain (non-SNMP) host costs one timeout, not three.
- **Best-effort, with collapsed notices.** No enrichment pass can fail the job
  (only nmap can). Per-host non-responses are aggregated into one `scan_ignored`
  notice per pass (`"SNMP inventory skipped: N hosts did not respond"`) instead of
  one per host, so the `/scans/{id}` "Skipped" section stays readable on a large
  range. Whole-pass conditions (an unconfigured DHCP file) are kept verbatim.
- **Deterministic merge order preserved.** Results are collected in a fixed order
  (per-host findings in host order, then DHCP) before `mergeObservations`, so the
  documented precedence holds regardless of goroutine scheduling: nmap leads scalar
  fields, the SNMP-inventory hostname/VLAN fill before the name/DNS passes, ARP
  fills the MAC. `mergeInto` now also carries `VLAN` (previously dropped when an
  inventory observation merged into an nmap base).

## Consequences

- A `combined` scan of a CIDR now does what its name promises: deep nmap plus every
  enrichment source, merged per host — MACs, OS, services, identity, VLAN, names,
  and topology in one picture — reaching the review queue and imported devices like
  any single-source scan.
- It is faster than a naive per-host loop: concurrent fan-out plus the SNMP
  short-circuit keep the enrichment time bounded by a few overlapping timeouts, not
  the sum of every probe.
- No new scan type, privilege, dependency, schema, or protocol change; the fix is
  contained to `internal/scanner/agent/combined.go` and its tests. The single-source
  scan types are unchanged and remain available for targeted use.
- The mode/depth picker stays nmap-only: `combined`, `arp_table`, and
  `snmp_inventory` present no depth choice (combined always runs deep; the SNMP
  passes have no depth), so the form effectively offers them a single default.
- IPv4 only, matching the rest of the scanner.
