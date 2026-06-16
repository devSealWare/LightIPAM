# ADR 0012: DNS Forward/Reverse Name Enrichment

## Status

Accepted.

## Context

LightIPAM can now recover a hostname three ways: nmap does a reverse (PTR) lookup
for the hosts it scans (ADR 0005), SNMP inventory reads `sysName` from managed gear
(ADR 0007), and `name_lookup` asks a host directly over NetBIOS/mDNS for hosts with
**no** DNS record (ADR 0010). The remaining Phase 4 naming item on the roadmap is
explicit **DNS forward/reverse enrichment** — reading the authoritative DNS the
network already runs.

This is the common case for managed hosts: they *do* have a DNS record, and that
record is the name the operator actually administers. A dedicated `dns_lookup`
source adds value the others do not:

- It names IPs that an enrichment-only pass reached but nmap did not port-scan
  (e.g. an `arp_table`/SNMP-harvested IP a router away), where nmap's own PTR
  resolution never ran.
- It **forward-confirms** the PTR: a reverse record that does not map back to the
  same address (a stale or hijacked PTR) is surfaced as unconfirmed rather than
  trusted blindly.
- It works as a fast, dependency-free standalone scan when an operator only wants
  names.

## Decision

- **A new `dns_lookup` scan type with its own backend.** `DNSDiscoverer`
  (`internal/scanner/agent/dns.go`) implements the `Discoverer` interface; the
  `DiscoveryRouter` routes `dns_lookup` to it. Per target it does a reverse (PTR)
  lookup, then a forward (A) lookup of the resulting name, and emits **one
  observation** carrying the hostname (FQDN, trailing dot trimmed) with the
  forward-confirmation result as `dns` evidence.
- **Targets are single hosts; non-response is not a failure.** A reverse lookup is
  per-address, so a CIDR target is a per-target `dns_unresolved` notice rather than
  expanded. An address with no PTR record is likewise a per-target `dns_unresolved`
  notice, never a job failure.
- **Folded into `combined`.** `CombinedDiscoverer` is refactored to a list of
  best-effort enrichment passes; `dns_lookup` joins ARP, SNMP inventory,
  NetBIOS/mDNS names, and LLDP/CDP after the deep nmap core. A silent host or CIDR
  target is downgraded to a `scan_ignored` notice, so a combined scan still
  succeeds with whatever was learned. Findings merge per IP (`mergeObservations`).
  Because nmap and SNMP inventory run first, an existing hostname wins; DNS fills an
  IP that nothing else named.
- **Standard library, no new dependency.** Resolution uses `*net.Resolver` behind
  an injectable `NameResolver` interface, so reverse/forward decoding and allowlist
  filtering are unit-tested with a fake and no real DNS. With `AGENT_DNS_SERVER` set
  the agent builds a Go resolver that dials that server directly (defaulting to
  `:53`); otherwise it uses the agent's system resolver. `AGENT_DNS_TIMEOUT` bounds
  each lookup.
- **No new privilege.** DNS is ordinary UDP/TCP/53 from a normal socket — no raw
  sockets, no `NET_RAW`. The agent's capability set is unchanged.
- **Reuses the existing pipeline.** Observations flow through `UpsertDiscovery` →
  review queue → reconciliation → import like every other source, so a DNS name
  merges onto the same discovery row (and, once imported, the same device) as an
  nmap service scan, an ARP-harvested MAC, an SNMP inventory record, and a
  NetBIOS/mDNS name. No schema change — `SyncImportedDiscovery` already backfills an
  imported address's empty hostname from a later scan.

## Consequences

- LightIPAM names hosts from the authoritative DNS it already runs, forward-confirms
  the record, and folds the result into the one-host-per-IP discovery picture, all
  from an unprivileged socket reusing the whole review/import path.
- Within `combined` the DNS pass overlaps nmap's built-in PTR resolution for hosts
  nmap scanned; the overlap is harmless (merge keeps the first non-empty hostname
  and de-dupes evidence) and the pass still adds forward-confirmation and names for
  IPs nmap did not scan.
- A forward-lookup failure or mismatch never drops the name — the PTR name is kept
  and the discrepancy is recorded as evidence for an operator to judge.
- IPv4 only, matching the rest of the scanner.
- The combined discoverer's enrichment-pass list makes adding further per-host
  enrichment sources (e.g. DHCP leases) a one-line change rather than another
  constructor field.
