# ADR 0002: Versioned Scanner Agent Protocol

## Status

Accepted.

## Context

Light IPAM needs active discovery features such as subnet detection, OS probing, and service detection. Those features must not run inside the web app container because they may require raw packet access, broad network reachability, and future Nmap execution.

Before adding a scanner-agent container, the app needs a clear protocol contract.

## Decision

Light IPAM will define scanner-agent messages as versioned Go structs and JSON-compatible schemas.

The first protocol version covers:

- Agent registration.
- mTLS identity.
- Scan jobs.
- Scan results.
- Explicit IPv4 allowlists.
- Scan lifecycle states.
- Host, MAC, OS, service, evidence, and error observations.

The first protocol definition does not implement active scanning.

## Consequences

- The scanner-agent container can be implemented without inventing message contracts later.
- The web app can keep scanner orchestration separate from IPAM data mutation.
- Agent-side allowlist validation becomes a hard protocol requirement.
- Future queue-based or API-based transports can reuse the same messages.

