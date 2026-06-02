# ADR 0003: Scanner Agent Container (No-op Foundation)

## Status

Accepted.

## Context

ADR 0002 defined the scanner agent protocol as versioned Go types. The next step
(issue #8) is to stand up the scanner-agent as a real, separately deployable
container that can receive and report a scan job, without yet performing any
active scanning.

Two constraints shape the design:

- The web app must stay unprivileged. Active discovery and any future raw-socket
  capability must live only in the agent.
- The protocol's transport is app-to-agent over mTLS. The agent authenticates
  the app and enforces its own allowlist, so a compromised or buggy app cannot
  direct the agent to scan outside its registered scope.

## Decision

Add a scanner-agent component built and deployed independently of the app:

- `cmd/scanner-agent` runs an HTTPS server exposing `GET /healthz` and
  `POST /jobs`. It performs no scanning; a valid job returns an empty,
  successful `ScanResult` and an out-of-allowlist job is rejected.
- `internal/scanner/agent` holds the receive/report handler, the mTLS server and
  client TLS config builders, and the client-identity check. Job acceptance runs
  `scanner.ValidateJobForAgent`, enforcing the dual job/agent allowlist contract.
- `internal/scanner/pki` and `cmd/scanner-certs` generate a development CA plus
  agent (server) and app (client) certificates for local and Compose use.
- A `Dockerfile.scanner` image and a `scanner-agent` Compose service behind a
  `scanner` profile keep the default app stack unchanged. The service drops all
  capabilities and runs read-only.

mTLS is wired now rather than deferred: the agent requires and verifies the
app's client certificate and checks its CommonName against `APP_CLIENT_CN`.

## Consequences

- The app and agent can be hardened and granted capabilities independently.
  `NET_RAW` will be added to the agent image only, when Nmap discovery lands.
- The receive/report contract is exercised end to end (including mTLS) before any
  scanning code exists, so later issues add discovery behind a stable boundary.
- The dev PKI generator is explicitly not production-grade. Managed issuance and
  rotation are tracked in the roadmap (Phase 5: agent mTLS rotation).
- App-side job dispatch and scan orchestration are intentionally out of scope and
  arrive in issue #9.
