# Architecture

## Goals

Light IPAM should be small enough to run in a single Docker Compose stack, but structured enough to safely discover networks without giving the web application raw network privileges.

## Components

### Web/API App

The app owns:

- User authentication and authorization.
- Sites, VRFs, VLANs, subnets, addresses, reservations, and device records.
- Scan policies, schedules, and result review.
- Audit logs and configuration history.
- Reporting and export.

The app should run as an unprivileged container with no Linux capabilities.

### Scanner Agent

The scanner agent owns:

- Staged nmap host discovery (ICMP/ARP) then TCP service and OS fingerprinting on
  live hosts. (Privileged probing via `NET_RAW`, confined here.)
- SNMP ARP-table harvesting (`arp_table`), SNMP device inventory
  (`snmp_inventory`), and LLDP/CDP neighbor harvesting (`lldp_cdp`) over
  unprivileged UDP/161 — implemented.
- NetBIOS + unicast mDNS host-name resolution (`name_lookup`) over unprivileged
  UDP/137 and UDP/5353 — implemented.
- A combined scan that fuses nmap + both SNMP passes + the name lookup + the
  LLDP/CDP harvest per host.
- Future enrichment: DHCP, DNS, VLAN/interface mapping.

Agents are deployed near the networks they scan. The app sends scan jobs over
mTLS (each carrying an explicit IPv4 allowlist), and agents return normalized
observations that flow through the discovery review queue.

### Database

Use PostgreSQL as the source of truth. Prefer native `inet` and `cidr` columns for addresses and subnets, with exclusion constraints where useful to prevent overlapping allocations within the same VRF.

## Discovery Pipeline

1. Define allowed scan scopes by site, VRF, subnet, and agent.
2. Agent performs low-impact host discovery.
3. Agent performs policy-limited port/service scans.
4. Agent normalizes observations into host, address, service, OS, and evidence records.
5. App presents changes as reviewable findings before mutating critical IPAM records.

## UI Direction

The UI should combine a beautiful dashboard with dense operational views:

- Dashboard with global search, discovery review, subnet health, utilization, recent changes, and scan status widgets.
- Subnet tree with utilization and conflict indicators.
- Address grid with filters for status, device, owner, services, and last seen.
- Device detail page with addresses, services, scan history, and evidence.
- Scan policy editor with explicit scope, rate limits, and probe types.
- Review queue for newly detected hosts, conflicts, and stale records.

Visual direction: Apple-inspired restraint, strong spacing, polished dark mode, and database-style information density where operators need to compare many records.
