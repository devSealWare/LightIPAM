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
- LLDP/CDP neighbor ingestion.
- DHCP lease ingestion.
- DNS forward/reverse enrichment.
- NetBIOS and mDNS/Bonjour hostname resolution (agent-side), so SMB, Apple, and
  IoT devices without a DNS PTR record still resolve to a name. Reuses the
  discovery review-queue + reconciliation pattern and stays in the scanner
  agent (e.g. nmap `nbstat` NSE / mDNS probe), never the web app.
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
