# ADR 0014: DHCP Lease Ingestion

## Status

Accepted.

## Context

The final naming/binding source on the Phase 4 roadmap is **DHCP lease ingestion**.
A DHCP server holds the authoritative record of which MAC was handed which IP, plus
the **client-supplied hostname** (DHCP option 12) — which on a small LAN is often
the most accurate name a host has, more reliable than reverse DNS or a guessed
NetBIOS name. The DHCP server is usually the site router or a Linux box the operator
already controls.

The constraint is the project's: the agent stays unprivileged and adds no new
attack surface. Active DHCP probing (DHCPINFORM) needs raw sockets and a privileged
source port — exactly the `NET_RAW` profile we keep off everything but nmap. There
is also no broadly-implemented standard SNMP MIB for DHCP leases across vendors.

The clean, unprivileged, broadly-applicable source is the DHCP server's **lease
file**, whose two dominant formats are well defined: ISC dhcpd's `dhcpd.leases`
(lease blocks) and dnsmasq's leases file (one line per lease). Reading a file the
operator mounts into the agent needs no privilege and is hermetically testable.

## Decision

- **A new `dhcp_leases` scan type with its own backend.** `DHCPDiscoverer`
  (`internal/scanner/agent/dhcp.go`) implements the `Discoverer` interface; the
  `DiscoveryRouter` routes `dhcp_leases` to it. It reads the configured lease file,
  parses it, and emits one observation per **active** lease — IP, MAC, and
  client-hostname — whose IP falls within a target range, with the lease
  state/expiry as `dhcp` evidence.
- **Two formats, auto-sniffed.** `AGENT_DHCP_LEASE_FORMAT` selects `isc` or
  `dnsmasq`; the default (`auto`) sniffs the file (an ISC file has `lease … {`
  blocks). The ISC parser keeps only `binding state active` leases and, since the
  server appends, the **last** active block per IP wins. Parsing sits behind an
  injectable `leaseReader`, so both parsers are unit-tested against fixture bytes
  with no filesystem.
- **Targets scope which ranges to ingest.** Unlike the network sources, the data
  source is a local file, so the job's targets (host or CIDR) select which leases to
  emit (`scopeFromTargets` → containment test). The allowlist still bounds the
  targets. In a `combined` scan the per-host targets naturally limit DHCP to the
  hosts being scanned.
- **Folded into `combined`** as a best-effort enrichment pass. A lease file that is
  not configured returns a clear `dhcp_unconfigured` notice (not a hard error): a
  standalone `dhcp_leases` scan surfaces it as the headline so the operator knows to
  set `AGENT_DHCP_LEASE_FILE`, and `combined` downgrades it to a muted `scan_ignored`
  "Skipped" line. A read/parse failure is likewise a per-job notice, never a job
  failure.
- **No new privilege, dependency, or schema.** Reading a file needs nothing extra;
  the IP/MAC/hostname a lease carries flow through the existing `Observation` fields,
  the review queue, reconciliation, and import — merging per IP onto the same
  discovery row and device as every other source. `AGENT_DHCP_LEASE_FILE` (and
  optional `AGENT_DHCP_LEASE_FORMAT`) live on the agent; the operator mounts the
  lease file read-only into the agent container.

## Consequences

- When the agent can read the DHCP server's lease file, LightIPAM gains the
  authoritative IP↔MAC binding and the device's own DHCP hostname, merged into the
  one-host-per-IP picture and reaching the imported device like any other source.
- The feature is opt-in and degrades gracefully: with no lease file configured it is
  silent in standalone use beyond one explanatory notice, and a single muted Skipped
  line in `combined` — no failures, no surprises.
- Only **active** leases are surfaced; expired/free/abandoned entries are ignored, so
  the queue reflects current bindings.
- It reads a file rather than querying the DHCP protocol, so it requires filesystem
  access to the lease file (a read-only mount), not network reachability to the
  server. A future SNMP- or API-based lease source for appliances that expose leases
  that way could layer onto the same scan type behind the injectable reader.
- IPv4 only, matching the rest of the scanner.
