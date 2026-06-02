# ADR 0001: Keep Scanning in a Separate Agent

## Status

Accepted.

## Context

Light IPAM needs active network discovery, OS probing, and service detection. Those functions may require raw socket access, elevated Linux capabilities, or broad network reachability.

The first deployment target is a single Docker host, but the security model should still be credible for larger networks.

## Decision

Light IPAM will use a separate scanner agent process/container for active discovery.

The web/API app remains unprivileged. The scanner agent may receive tightly scoped network capabilities, such as `NET_RAW`, only when required by the selected probes.

The app and agent communicate through authenticated APIs using mTLS. Scan jobs must include explicit allowed IPv4 ranges, scan type, rate limits, and scheduling metadata.

## Consequences

- The web app does not need raw packet privileges.
- Scanner risk is isolated to a smaller component.
- Future multi-site scanning remains possible.
- Docker Compose deployments need one extra service.
- The agent protocol must be designed early enough to avoid coupling scanner output directly to UI/database internals.

