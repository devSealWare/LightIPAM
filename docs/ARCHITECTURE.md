# Architecture

## Goals

Netventory should be small enough to run in a single Docker Compose stack, but structured enough to safely discover networks without giving the web application raw network privileges.

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

- ICMP and ARP/ND host discovery.
- TCP and UDP service discovery.
- OS and service fingerprinting.
- Optional SNMP, LLDP/CDP, DHCP, and DNS enrichment.

Agents should be deployed near the networks they scan. The app should send signed scan jobs over mTLS, and agents should return normalized observations.

### Database

Use PostgreSQL as the source of truth. Prefer native `inet` and `cidr` columns for addresses and subnets, with exclusion constraints where useful to prevent overlapping allocations within the same VRF.

## Discovery Pipeline

1. Define allowed scan scopes by site, VRF, subnet, and agent.
2. Agent performs low-impact host discovery.
3. Agent performs policy-limited port/service scans.
4. Agent normalizes observations into host, address, service, OS, and evidence records.
5. App presents changes as reviewable findings before mutating critical IPAM records.

## UI Direction

The UI should be operational, dense, and fast:

- Subnet tree with utilization and conflict indicators.
- Address grid with filters for status, device, owner, services, and last seen.
- Device detail page with addresses, services, scan history, and evidence.
- Scan policy editor with explicit scope, rate limits, and probe types.
- Review queue for newly detected hosts, conflicts, and stale records.

