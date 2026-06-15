# MVP Requirements

## Target

Light IPAM should support small business deployments first while keeping the architecture credible for larger enterprise use.

## Deployment

- Docker Compose only for the first release.
- One Docker host for the app, database, and scanner agent.
- IPv4 only.
- PostgreSQL database.
- Local username/password authentication.
- First admin created through a web bootstrap page.
- Single admin role for the first version.

## Manual IPAM

Initial IPAM objects:

- A default site created automatically.
- VLAN as optional subnet metadata for MVP.
- Subnets.
- IPv4 addresses.
- Devices.
- MAC addresses.
- Tags and custom fields.

Initial address states:

- Available.
- Reserved.
- Assigned.
- Deprecated.
- Conflict.

Bulk edit and import/export should be available in the UI early. CSV support can be deferred until the data model is stable.

Subnet rules:

- IPv4-only, including `/31` and `/32`.
- Overlapping subnets are globally blocked for MVP.
- Address records are sparse: Light IPAM stores only touched, reserved, assigned, deprecated, conflicted, or discovered addresses.
- Devices can be linked to IP address records and MAC addresses.
- Locally administered unicast MAC addresses are tagged as private rotating MACs.
- MAC vendor matching is best-effort from built-in OUI data for MVP, with a future importer planned for the full IEEE OUI registry.

## Discovery

Discovery comes after the manual IPAM foundation.

Supported modes:

- Manual scans.
- Scheduled scans.
- **Review queue by default** (`/discoveries`): observations are reconciled against
  managed records and imported on approval, never auto-mutating IPAM. (The earlier
  "auto-create by default" intent was inverted in favor of safety.)
- Optional **per-agent auto-import** for trusted agents, with conflicts always kept
  in the queue.

Nmap is the active scanner for OS probing and service detection; SNMP
(`arp_table`, `snmp_inventory`) and NetBIOS/mDNS (`name_lookup`) provide
unprivileged passive imports, and a `combined` scan fuses them.

Further passive integrations such as DHCP, DNS, LLDP/CDP, firewall, and controller imports are planned as optional integrations. Light IPAM should not require connection to a DHCP server for the first scanner workflow.

## Security

- Keep the app container unprivileged.
- Put elevated scan capabilities only in the scanner agent.
- Use mTLS for app-to-agent communication.
- Write immutable audit logs for scan activity and IPAM changes.
- Audit rows are append-only and protected against direct update/delete attempts.
- MFA is not required for MVP, but the auth design should leave room for it.

## UI

The first screen is a dashboard with:

- Global search.
- Review widget.
- Subnet utilization widget.
- Subnet list widget.
- Recent changes.
- Scan status.

The UI should support dark mode from the start.

Tailwind CSS is the styling system for the first release.

## Future Integrations

Leave clear extension points for:

- NetBox import/export.
- phpIPAM import/export.
- DNS read-only discovery.
- UniFi.
- pfSense and OPNsense.
- Windows DHCP.
- Infoblox.
- Pi-hole.
- PowerDNS.
