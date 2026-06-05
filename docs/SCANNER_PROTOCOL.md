# Scanner Agent Protocol

Issue #7 defines the contract between the Light IPAM web app and future scanner agents. This document describes the protocol before the scanner-agent container or Nmap execution exists.

## Principles

- The web app stays unprivileged.
- Scanner agents are separate processes/containers.
- Every scan job must include an explicit IPv4 allowlist.
- Agents must reject work outside their local allowlist even if the app submits it.
- Deep probing is disabled unless explicitly selected in the scan policy.
- Results are observations, not automatic truth. The app decides how observations become IPAM records.

## Transport

Initial transport target:

- HTTPS JSON API.
- mTLS between app and agent.
- App validates agent certificate identity.
- Agent validates app/client certificate identity.

Future transports such as queue-based delivery can reuse the same message schemas.

## Agent Registration

Agents are registered by the app before receiving work.

Fields:

- `id`: stable app-generated agent ID.
- `name`: human-readable name.
- `site_id`: optional site association.
- `version`: agent software version.
- `certificate_subject`: mTLS subject or SPIFFE-style identity.
- `allowed_cidrs`: explicit IPv4 CIDRs the agent may scan.
- `created_at`: registration time.
- `last_seen_at`: heartbeat time.
- `status`: `pending`, `active`, `disabled`, or `revoked`.

## mTLS Identity Model

Each agent has a unique client certificate. The app stores the expected identity at registration time.

Minimum checks:

- Certificate chains to the configured Light IPAM scanner CA.
- Certificate identity maps to exactly one active agent.
- Agent is not disabled or revoked.
- Scan job requested CIDRs are contained by both the job allowlist and the agent allowlist.

Certificate rotation should be added before production multi-agent deployments.

## Scan Job

A scan job is the app-to-agent work request.

Required fields:

- `id`: stable job ID.
- `agent_id`: intended agent.
- `requested_by`: user ID or system.
- `scan_type`: `host_discovery`, `service_detection`, `os_probe`, `combined`, or
  `arp_table`.
- `mode`: `passive`, `light_active`, `standard_active`, or `deep_active`.
- `allowed_cidrs`: explicit IPv4 CIDRs for this job.
- `targets`: IPv4 CIDRs or individual IPv4 addresses. For an `arp_table` scan
  these are the gateway/L3 device IPs to query over SNMP (see ADR 0006); the
  agent reports the cached IP↔MAC neighbors that fall within `allowed_cidrs`.
- `ports`: optional TCP/UDP port selections.
- `rate_limit`: packet/probe rate policy.
- `timeout_seconds`: job timeout.
- `created_at`: creation time.

### Allowlist validation

Allowlists are enforced at two layers, both implemented in `internal/scanner/protocol.go`:

- `ValidateJob` rejects a job whose required fields are missing, whose `scan_type`/`mode` are unknown, whose `timeout_seconds` is not positive, or whose any `target` falls outside the job's own `allowed_cidrs`.
- `ValidateJobForAgent` is the **app-side** check before dispatch. It additionally requires that the agent is `active`, that the job is addressed to that agent (by app-assigned ID), and that every entry in the job's `allowed_cidrs` is fully contained by the agent's registered `allowed_cidrs`.
- `ValidateAgentScope` is the **agent-side** check before accepting work. The connecting app is already authenticated by mTLS, so the agent's own security boundary is its allowlist: it runs `ValidateJob` and requires the job's `allowed_cidrs` to be contained by the agent's allowlist, without re-checking the app-assigned agent identity or registration status (those are app concerns the agent cannot independently verify).

A job is only dispatched if it passes the app-side check, and only acted on if it passes the agent-side check, so neither a buggy app nor a spoofed job can push an agent past its registered allowlist.

## Scan Result

A scan result is the agent-to-app observation report.

Required fields:

- `protocol_version`: protocol version the agent reported under (current: `v1`).
- `job_id`: source job.
- `agent_id`: reporting agent.
- `status`: `queued`, `running`, `succeeded`, `failed`, `cancelled`, or `rejected`.
- `started_at`: optional.
- `finished_at`: optional.
- `observations`: list of observed hosts/services.
- `errors`: list of scanner errors.

Observation fields:

- `ip`: observed IPv4 address.
- `mac`: optional MAC address.
- `hostname`: optional hostname.
- `os_family`: optional OS family.
- `os_detail`: optional OS details.
- `services`: optional service observations.
- `evidence`: raw or normalized evidence references.
- `observed_at`: time the observation was made.

Service fields:

- `protocol`: `tcp` or `udp`.
- `port`: port number.
- `state`: `open`, `closed`, or `filtered`.
- `service_name`: optional.
- `product`: optional.
- `version`: optional.

## Lifecycle

1. App creates scan job.
2. App sends job to registered agent.
3. Agent validates mTLS identity and allowlists.
4. Agent accepts or rejects job.
5. Agent reports status updates.
6. Agent reports final result.
7. App writes audit entries and converts observations into auto-created or review-queued IPAM records based on policy.

