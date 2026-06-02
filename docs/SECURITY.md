# Security Model

## Core Rule

Do not trunk every network into the web application container. Deploy scanner agents into network zones instead. Keep the app on a management network and make agents initiate outbound connections when possible.

## Container Boundaries

The app container should:

- Run as a non-root user.
- Be read-only where practical.
- Drop all Linux capabilities.
- Avoid direct layer-2 access to scanned networks.
- Store secrets only through environment or a secret manager.

Scanner containers may need capabilities such as `NET_RAW`, but only on hosts and networks where scanning is approved.

## Agent Trust

Agents should use:

- mTLS for app-to-agent or agent-to-app communication.
- Per-agent identities and revocation.
- Signed scan jobs with explicit allowed CIDRs.
- Rate limits and concurrency limits.
- Local allowlists and denylists that cannot be bypassed by the app UI alone.

## Product Security Features

Minimum viable security features:

- Local admin bootstrap followed by forced password rotation.
- Argon2id password hashing.
- TOTP or WebAuthn MFA.
- Role-based access control.
- Immutable audit log for login, config, scan, and IPAM mutations.
- CSRF protection for browser forms.
- Secure session cookies.
- Optional OIDC integration for production.

## Scan Safety

Discovery should support graduated policies:

- Passive only: DHCP, DNS, ARP tables, SNMP inventory imports.
- Light active: ICMP echo, ARP/ND discovery, TCP SYN to selected ports.
- Standard active: top TCP ports, service banners, OS fingerprinting.
- Deep active: UDP, NSE-style scripts, authenticated checks.

Deep active scans should be disabled by default.

