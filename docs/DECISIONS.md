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

Use a separate scanner agent, even when it runs on the same Docker host as the app. Start with Nmap for OS and service fingerprinting, then add lighter custom probes where needed.

Initial discovery modes:

- Passive imports: DHCP, DNS, ARP tables, SNMP inventory.
- Light active scan: ICMP, ARP/ND, selected TCP ports.
- Standard active scan: Nmap service/version detection and OS detection.
- Deep active scan: NSE scripts and UDP scanning, disabled by default.

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
