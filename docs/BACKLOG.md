# Initial Backlog

These are the first GitHub issues to create once repository issue automation is available.

## 1. Implement Admin Bootstrap and Local Login

Build the first local authentication flow with a single admin role.

Acceptance criteria:

- First-run admin bootstrap.
- Web bootstrap page for first admin creation.
- Secure password hashing.
- Login and logout.
- Secure session cookies.
- CSRF protection for browser forms.

## 2. Add Database Migrations and Core IPAM Schema

Create the PostgreSQL schema for manual IPAM.

Acceptance criteria:

- Embedded Go migration runner.
- Tables for sites, VLANs, subnets, IPv4 addresses, devices, MAC addresses, tags, and custom fields.
- Address states: available, reserved, assigned, deprecated, conflict.
- Audit log table.

## 3. Build the Dashboard Shell

Create the first real Light IPAM web UI.

Acceptance criteria:

- Dashboard as the first screen.
- Global search at the top.
- Widgets for subnet utilization, review items, recent changes, and scan status.
- Dark mode support.
- Apple-inspired visual polish with dense operational data where needed.

## 4. Build Subnet and Address Management

Implement the main manual IPAM workflow.

Acceptance criteria:

- Create, edit, and delete subnets.
- View subnet utilization.
- Address grid with filtering.
- Create, reserve, assign, deprecate, and mark conflict states.
- Bulk edit foundation.

## 5. Build Device and MAC Address Tracking

Add device records tied to IPv4 and MAC observations.

Acceptance criteria:

- Device list and detail views.
- MAC address records.
- Address-to-device relationships.
- Notes, tags, and custom fields.

## 6. Implement Immutable Audit Logs

Track security and IPAM changes.

Acceptance criteria:

- Audit entries for login, logout, IPAM mutations, and scan configuration changes.
- Audit entries cannot be edited through normal app APIs.
- Audit UI with filters.

## 7. Define Scanner Agent Protocol

Create the API contract between the app and scanner agent.

Acceptance criteria:

- Agent registration model.
- mTLS identity plan.
- Scan job schema.
- Scan result schema.
- Explicit IPv4 allowlist per scan.

## 8. Add Scanner Agent Container

Create the first scanner-agent service.

Acceptance criteria:

- Separate Docker Compose service.
- App container remains unprivileged.
- Scanner capabilities are scoped to the agent.
- Agent can receive and report a no-op scan job.

## 9. Add Manual and Scheduled Scan Jobs

Implement scan orchestration without active Nmap probing yet.

Acceptance criteria:

- Manual scan trigger.
- Scheduled scan configuration.
- Scan status lifecycle.
- Scan audit trail.

## 10. Add Nmap Discovery MVP

Implement active discovery with Nmap.

Acceptance criteria:

- IPv4 host discovery.
- TCP service detection.
- OS probing where reliable and allowed.
- Rate limits.
- Auto-create records by default.
- Optional review mode.
