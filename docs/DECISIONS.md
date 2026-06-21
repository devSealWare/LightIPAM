# Technical Decisions

## Language

Use Go for the first version.

Reasons:

- Produces small static binaries for Docker.
- Good fit for concurrent scan orchestration.
- Strong networking libraries.
- Easier to keep the app and scanner agent in the same language.
- Lower operational weight than a large full-stack framework.

## Web Platform

Use server-rendered HTML with Tailwind CSS.

Reasons:

- Keeps the UI fast and lightweight.
- Gives the product a polished interface without committing to a heavy single-page app.
- Keeps app interactions server-owned while leaving room for HTMX or TypeScript when address grids, filters, modals, and scan review queues need richer behavior.

Use TypeScript only where browser-side complexity is justified.

## Database

Use PostgreSQL.

Reasons:

- Native `inet`, `cidr`, and MAC address types.
- Network containment operators for subnet/address queries.
- Mature constraints, transactions, indexing, and backup tooling.

## Discovery

Use a separate scanner agent, even when it runs on the same Docker host as the app. Nmap handles OS and service fingerprinting; SNMP (unprivileged UDP/161), NetBIOS/mDNS (unprivileged UDP/137 and UDP/5353), DNS (UDP/TCP/53), and DHCP lease-file reads handle passive imports the agent can read directly. Each new source reuses the discovery review-queue + reconciliation pipeline and stays in the agent.

As-built scan types and modes:

- **Scan types:** `host_discovery`, `service_detection`, `os_probe`, `combined`
  (deep nmap + SNMP ARP + SNMP inventory/VLAN + NetBIOS/mDNS names + DNS names +
  DHCP leases + LLDP/CDP neighbors, merged per host), `arp_table` (SNMP ARP-cache
  harvesting), `snmp_inventory` (SNMP device identity + interface MACs + 802.1Q
  VLAN), `name_lookup` (NetBIOS + mDNS host-name resolution), `dns_lookup`
  (reverse-PTR + forward-confirm), `dhcp_leases` (ISC dhcpd/dnsmasq lease-file
  ingestion), and `lldp_cdp` (SNMP LLDP/CDP neighbor harvesting — physical
  topology).
- **Modes** (nmap depth knob only; SNMP/name/combined ignore it): Light (top-1000
  service detection), Standard (top-1000 + exhaustive versions + OS), Deep (all
  ports + OS, tuned for speed). The protocol still defines `passive` (no packets)
  but it is no longer offered in the UI.
- **Staged nmap:** a fast host-discovery sweep finds live hosts first, then only
  those get service/OS detection. NSE scripts / UDP scanning remain future work.

## Authentication

Start with local auth and a web-based first-admin bootstrap page. Support OIDC later for production environments that need centralized identity.

Minimum production controls:

- Argon2id password hashing.
- MFA.
- Secure sessions.
- CSRF protection.
- Role-based access control.
- Audit logging.

## Deployment

Use Docker Compose for the first release. The app service should be unprivileged. Scanner agents can run in separate containers on the same host with tightly scoped network access.
