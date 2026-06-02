# ADR 0004: App-Side Scan Orchestration

## Status

Accepted.

## Context

ADR 0003 added a no-op scanner agent that receives jobs over mTLS. Issue #9
gives the app the ability to manage agents, dispatch manual and scheduled scan
jobs to them, track each job's lifecycle, and record an audit trail — still
without any active Nmap scanning.

The app must remain unprivileged: dispatching a job is an ordinary outbound mTLS
HTTP request, not a network probe.

## Decision

- **Agents** are managed in the app (`/agents`): a registration carries an
  endpoint URL, an expected certificate subject, an IPv4 allowlist, and a status
  (`pending`/`active`/`disabled`/`revoked`). Full agent CRUD lives in the UI;
  agent IDs are app-assigned.
- **Dispatch** is real mTLS. `internal/scanner/dispatch` is the app's client; it
  presents the app's client certificate and verifies the agent's server
  certificate per request against the endpoint host. Missing client-certificate
  files disable dispatch and make jobs fail cleanly rather than blocking startup.
- **Orchestration** lives in `internal/scanner/orchestrator`. It validates a job
  against the agent (`ValidateJobForAgent`), records it, dispatches asynchronously,
  and writes lifecycle transitions (`queued` → `running` → `succeeded`/`failed`/
  `rejected`) plus immutable audit entries.
- **Scheduling** uses an in-process ticker (`StartScheduler`) suited to the
  single-Docker-host target. Schedules store an interval and a `next_run_at`; due
  schedules enqueue jobs and advance their timestamps. A "Run now" action reuses
  the manual dispatch path.
- **Allowlist enforcement is two-sided.** The app checks `ValidateJobForAgent`
  before dispatch; the agent independently checks `ValidateAgentScope` (allowlist
  containment only, since the app is already authenticated by mTLS and the agent
  cannot verify app-assigned identity or status). This split was driven by the
  agent's self-configured identity differing from the app-assigned agent ID.

## Consequences

- Operators can register agents, run and schedule scans, and review results and
  audit history before any active scanning exists.
- The app gains no privileged capability; it is only an mTLS client.
- Results are stored verbatim (`scan_jobs.result`). Turning observations into
  IPAM records (auto-create or a review queue) is deferred to the Nmap MVP
  (issue #10).
- Certificate issuance/rotation remains the dev-grade generator from ADR 0003;
  managed issuance is tracked in roadmap Phase 5.
