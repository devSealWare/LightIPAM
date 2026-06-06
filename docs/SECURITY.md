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

Discovery supports graduated, allowlist-bounded policies. The nmap scan types take
a depth mode; SNMP-based types read what a device exposes and ignore depth.

- **SNMP imports (unprivileged):** `arp_table` reads a gateway's ARP cache and
  `snmp_inventory` reads a device's own identity/interfaces, both over UDP/161 with
  no `NET_RAW`. The read community lives only on the agent.
- **Light:** top-1000 TCP service detection.
- **Standard:** top-1000 + exhaustive version probes + OS fingerprinting.
- **Deep:** every TCP port + OS, tuned for speed; the broadest (and loudest) scan.
- **Combined:** deep nmap plus both SNMP passes, merged per host.

All nmap scans run staged — a host-discovery sweep first, then port/service work
only on live hosts — so probing is never aimed at dead address space. Privileged
(`NET_RAW`) probing is confined to the nmap backend in the agent; UDP/NSE-style
scripting and authenticated checks remain future work.

