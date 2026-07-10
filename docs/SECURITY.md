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

### Deploying beyond localhost

The quick-start in `README.md` serves plain HTTP, which is fine for loopback/dev
use but sends session, CSRF, and OIDC-state cookies without the `Secure`
attribute — they traverse cleartext. Before deploying past localhost:

- Terminate TLS in front of the app with a reverse proxy (nginx, Caddy, Traefik).
- Set `COOKIE_SECURE=true` so those cookies get `Secure`, and so the app emits
  `Strict-Transport-Security` (see Product Security Features below).

`COOKIE_SECURE` defaults to `false` (opt-in) rather than `true` with an
opt-out, so a bare local/dev instance isn't broken out of the box. Whether that
default should flip is an open product decision for the maintainer, not
something to change silently.

## Agent Trust

Agents should use:

- mTLS for app-to-agent or agent-to-app communication.
- Per-agent identities and revocation.
- Signed scan jobs with explicit allowed CIDRs.
- Rate limits and concurrency limits.
- Local allowlists and denylists that cannot be bypassed by the app UI alone.

### Outbound-URL SSRF guards

Two admin-only surfaces make server-initiated outbound requests to an
admin-supplied URL, and both share the same literal-IP SSRF guard:
`scanner.ValidateAgentEndpoint` (`internal/scanner/endpoint.go`) for the
scanner-agent endpoint, and `webhook.ValidateURL`
(`internal/webhook/endpoint.go`) for the webhook Payload URL. Both require
`https://` and reject a literal loopback, link-local, or unspecified IP (e.g.
`127.0.0.1`, `169.254.169.254`, `::1`, `0.0.0.0`), but deliberately do **not**
resolve hostnames or reject private RFC-1918 ranges — agents and some webhook
receivers legitimately live on the private LAN. This is a first line of
defense against a compromised or careless admin pointing either surface at
cloud instance metadata or another internal-only service, not a substitute for
admins trusting what they configure.

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
- Baseline security headers on every response: CSP (`default-src 'self'`,
  `base-uri 'self'`, `object-src 'none'`, no inline JS/CSS), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, and — when
  `COOKIE_SECURE=true` (i.e. the deployment is fronted by TLS) —
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

### RBAC scope

The `authorize` middleware (`internal/app/authz.go`) exempts every `/account/*`
path from the admin-only write check — this is intentional: it's a per-user
self-service surface (password change, MFA enrollment, session sign-out) that
should not require an admin role, since a user is only ever acting on their own
account there. That blanket exemption does **not** cover API token creation:
`POST /account/tokens` has its own explicit `canWrite` (admin-role) check in
`accountTokenCreate`, gating token creation to admins even though the account
path itself is otherwise self-service. This keeps a hard bound on how many
long-lived credentials can touch `/api/v1`, at the cost of viewers needing an
admin to mint a token on their behalf. Token **deletion** stays self-service for
every role — revoking your own token is not a privilege concern.

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

