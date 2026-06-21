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
a depth mode; the SNMP and name-resolution types read what a device exposes and
ignore depth.

- **SNMP imports (unprivileged):** `arp_table` reads a gateway's ARP cache,
  `snmp_inventory` reads a device's own identity/interfaces + 802.1Q VLAN, and
  `lldp_cdp` reads a switch/router's LLDP/CDP neighbor caches — all over UDP/161 with
  no `NET_RAW`. The read community lives only on the agent.
- **Name resolution (unprivileged):** `name_lookup` asks a host for its name over
  NetBIOS (UDP/137) and unicast mDNS (UDP/5353), and `dns_lookup` reads the
  authoritative DNS (reverse PTR, forward-confirmed) over UDP/TCP/53 — again with no
  `NET_RAW`.
- **DHCP leases (unprivileged):** `dhcp_leases` reads a mounted ISC dhcpd/dnsmasq
  lease file for the authoritative IP↔MAC binding of each active lease; a file read
  needs no `NET_RAW`.
- **Light:** top-1000 TCP service detection.
- **Standard:** top-1000 + exhaustive version probes + OS fingerprinting.
- **Deep:** every TCP port + OS, tuned for speed; the broadest (and loudest) scan.
- **Combined:** deep nmap plus every passive pass (both SNMP passes, the
  NetBIOS/mDNS name lookup, DNS, DHCP leases, and the LLDP/CDP neighbor harvest),
  merged per host.

All nmap scans run staged — a host-discovery sweep first, then port/service work
only on live hosts — so probing is never aimed at dead address space. Privileged
(`NET_RAW`) probing is confined to the nmap backend in the agent; the SNMP, name,
DNS, and DHCP backends are ordinary unicast UDP or a file read. UDP/NSE-style
scripting and authenticated checks remain future work.

