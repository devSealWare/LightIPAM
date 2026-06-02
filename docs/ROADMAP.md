# Roadmap

## Phase 1: Usable IPAM

- Authentication, sessions, and admin bootstrap.
- Sites, VRFs, VLANs, subnets, and address records.
- Address status workflow: available, reserved, assigned, deprecated, conflict.
- Subnet utilization and address grid.
- CSV import/export.
- Audit log.

## Phase 2: Discovery MVP

- Scanner agent registration.
- Allowed scan scopes.
- ICMP and TCP host discovery.
- Nmap-backed OS and service detection.
- Findings review queue.
- Last-seen tracking and conflict detection.

## Phase 3: Network Context

- SNMP device inventory.
- LLDP/CDP neighbor ingestion.
- DHCP lease ingestion.
- DNS forward/reverse enrichment.
- VLAN and interface mapping.

## Phase 4: Production Hardening

- OIDC.
- MFA.
- Encrypted secrets.
- Agent mTLS rotation.
- Backup and restore.
- Multi-tenant or organization separation if needed.

## Phase 5: Advanced Automation

- Scheduled scan windows.
- Change webhooks.
- NetBox-compatible import/export.
- Terraform provider or CLI.
- Policy checks for overlapping subnets, stale records, and unmanaged services.

