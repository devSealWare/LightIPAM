# Roadmap

## Phase 1: Manual IPAM MVP

- Authentication, sessions, and admin bootstrap.
- Default site, optional VLAN metadata, subnets, and sparse address records.
- Address status workflow: available, reserved, assigned, deprecated, conflict.
- Devices, MAC addresses, tags, and custom fields.
- Subnet utilization and address grid.
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

## Phase 3: Nmap Discovery MVP

- ICMP and TCP host discovery.
- Nmap-backed OS and service detection.
- Findings review queue.
- Last-seen tracking and conflict detection.

## Phase 4: Network Context

- SNMP device inventory.
- LLDP/CDP neighbor ingestion.
- DHCP lease ingestion.
- DNS forward/reverse enrichment.
- VLAN and interface mapping.

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
