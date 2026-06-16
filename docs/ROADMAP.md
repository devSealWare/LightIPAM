# Roadmap

## Phase 1: Manual IPAM MVP

- Authentication, sessions, and admin bootstrap.
- Default site, optional VLAN metadata, subnets, and sparse address records.
- Address status workflow: available, reserved, assigned, deprecated, conflict.
- Devices, MAC addresses, private MAC tagging, basic OUI vendor matching, tags, and custom fields.
- Subnet utilization and address grid.
- Address editing, navigation shell, dashboard widgets, empty states, and confirmation flows.
- Dashboard with global search, subnet widgets, review widget, recent changes, and scan status.
- Bulk edit and import/export foundation.
- Audit log.

## Phase 2: Scanner Agent Foundation

- Scanner agent registration.
- App-to-agent mTLS.
- Allowed scan scopes.
- Manual and scheduled scan jobs.
- Immutable scan audit trail.
- Optional review mode for detected changes.

## Phase 3: Nmap Discovery MVP — complete

- ICMP and TCP host discovery. ✅
- Nmap-backed OS and service detection. ✅
- Findings review queue (`/discoveries`). ✅
- Last-seen tracking on managed addresses. ✅
- Conflict detection: discoveries are reconciled against managed records and
  flagged new/match/conflict (changed MAC, deprecated-but-responding, MAC seen
  on another address). ✅

Follow-ups merged on top of Phase 3 (#18):

- Per-agent auto-import for trusted agents (`scan_agents.auto_import`); conflicts
  always stay in the review queue. ✅
- Structured scan-result detail UI (per-host services/OS/evidence). ✅

## Phase 4: Network Context

- SNMP ARP-table harvesting (**done**, ADR 0006). The `arp_table` scan type
  queries a gateway/L3 device's `ipNetToMediaTable` over SNMP to recover IP↔MAC
  bindings for subnets the agent cannot reach at Layer 2. Unprivileged (UDP/161,
  no `NET_RAW`); reuses the discovery review-queue + reconciliation pattern.
- SNMP device inventory (**done**, ADR 0007). The `snmp_inventory` scan type reads
  a device's system group (name, OS, location) and its interface/IP tables to
  recover the device's own identity and the MACs of its interfaces.
- Combined all-sources scan + scan-experience polish (**done**, ADRs 0008/0009):
  one `combined` job runs deep nmap + ARP + SNMP inventory, merged per host, with
  unreachable SNMP ignored not failed; simplified Light/Standard/Deep modes;
  staged nmap (host discovery → service/OS on live hosts only); and dynamic,
  generous per-type scan timeouts.
- NetBIOS and mDNS/Bonjour hostname resolution (**done**, ADR 0010). The
  `name_lookup` scan type asks a host directly for its name over NetBIOS (UDP/137)
  and unicast mDNS (UDP/5353), recovering names for SMB, Apple, and IoT devices
  with no DNS PTR record; NetBIOS works across subnets. Folded into the `combined`
  scan as a best-effort enrichment pass. Unprivileged unicast UDP, no new
  dependency; reuses the discovery review-queue + reconciliation, in the agent.
- LLDP/CDP neighbor ingestion (**done**, ADR 0011). The `lldp_cdp` scan type reads
  a switch/router's LLDP (`lldpRemTable` + `lldpRemManAddrTable`) and CDP
  (`cdpCacheTable`) neighbor caches over SNMP to map physical topology — which
  devices are wired to which ports. Targets are the switch/router IPs; each neighbor
  with a management address becomes an IP-keyed observation (name, platform/OS, and
  an LLDP MAC-typed chassis id). Unprivileged (UDP/161, no `NET_RAW`); folded into
  the `combined` scan; reuses the discovery review-queue + reconciliation, in the
  agent.
- DNS forward/reverse enrichment (**done**, ADR 0012). The `dns_lookup` scan type
  resolves each host's name from the network's authoritative DNS (reverse PTR) and
  forward-confirms it, naming managed hosts that already have a DNS record and
  flagging a stale/mismatched PTR. Unprivileged UDP/TCP/53; folded into `combined`;
  reuses the discovery review-queue + reconciliation, in the agent.
- VLAN and interface mapping (**done**, ADR 0013). The `snmp_inventory` scan now
  reads each interface's 802.1Q access VLAN (Q-BRIDGE-MIB `dot1qPvid`, joined to the
  interface through the bridge-port table) and operational status, mapping a host's
  IP → interface → VLAN. A discovered VLAN backfills the containing subnet's VLAN
  when it has none (never overwriting an operator value), so the mapping reaches the
  Subnets and Devices pages. Unprivileged (UDP/161), no new scan type.
- DHCP lease ingestion (**done**, ADR 0014). The `dhcp_leases` scan type reads the
  DHCP server's lease file (ISC dhcpd or dnsmasq, mounted read-only on the agent) for
  the authoritative IP↔MAC binding and client-supplied hostname of each active lease.
  Opt-in and never fatal (an unconfigured file is a clear notice / muted Skipped
  line); folded into `combined`; reuses the discovery review-queue + reconciliation,
  in the agent.

**Phase 4 is complete.** The four Network-Context sources (SNMP ARP, SNMP inventory
+ VLAN/interface, NetBIOS/mDNS names, DNS names, DHCP leases, LLDP/CDP neighbors) all
merge per host through one review/import path; a single `combined` scan runs them all.

## Phase 5: Production Hardening

- OIDC.
- MFA.
- Encrypted secrets.
- Agent mTLS rotation.
- Backup and restore.
- Multi-tenant or organization separation if needed.

## Phase 6: Advanced Automation

- Scheduled scan windows.
- Change webhooks.
- NetBox-compatible import/export.
- Terraform provider or CLI.
- Policy checks for overlapping subnets, stale records, and unmanaged services.
