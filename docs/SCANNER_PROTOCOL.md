# Scanner Agent Protocol

Issue #7 defined the contract between the Light IPAM web app and scanner agents.
The contract is now implemented by the app-side dispatcher and the optional
scanner-agent container; later discovery work has extended the scan types while
keeping the same versioned message boundary.

## Principles

- The web app stays unprivileged.
- Scanner agents are separate processes/containers.
- Every scan job must include an explicit IPv4 allowlist.
- Agents must reject work outside their local allowlist even if the app submits it.
- Deep probing is disabled unless explicitly selected in the scan policy.
- Results are observations, not automatic truth. The app decides how observations become IPAM records.

## Transport

Implemented transport:

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

The app is the mTLS client and presents the app client certificate. Each agent
presents a server certificate; the app verifies it against the scanner CA and the
agent endpoint host. The agent requires the app client certificate and checks the
configured app client CommonName.

Minimum checks:

- Certificate chains to the configured Light IPAM scanner CA.
- The endpoint and registered agent identity map to exactly one active agent.
- Agent is not disabled or revoked.
- Scan job requested CIDRs are contained by both the job allowlist and the agent allowlist.

Certificate rotation should be added before production multi-agent deployments.

## Scan Job

A scan job is the app-to-agent work request.

Required fields:

- `id`: stable job ID.
- `agent_id`: intended agent.
- `requested_by`: user ID or system.
- `scan_type`: `host_discovery`, `service_detection`, `os_probe`, `combined`,
  `arp_table`, `snmp_inventory`, `name_lookup`, `dns_lookup`, `dhcp_leases`, or
  `lldp_cdp`. `combined` runs deep nmap plus every passive pass (both SNMP passes,
  the NetBIOS/mDNS name lookup, DNS, DHCP leases, and the LLDP/CDP neighbor harvest)
  against the targets and merges the result per host, enriching the hosts nmap
  discovers (ADRs 0008/0010/0011/0012/0014/0015).
- `mode`: `passive`, `light_active`, `standard_active`, or `deep_active`. Mode is
  an nmap depth knob; every non-nmap type
  (`arp_table`/`snmp_inventory`/`name_lookup`/`dns_lookup`/`dhcp_leases`/`lldp_cdp`)
  and `combined` ignore it (the app hides the picker and normalizes it). `passive` is
  still a valid value (the agent's no-packets short-circuit) but is no longer offered
  in the UI.
- `allowed_cidrs`: explicit IPv4 CIDRs for this job.
- `targets`: IPv4 CIDRs or individual IPv4 addresses. For an `arp_table` scan
  these are the gateway/L3 device IPs to query over SNMP (see ADR 0006); the
  agent reports the cached IP↔MAC neighbors that fall within `allowed_cidrs`. For
  an `snmp_inventory` scan they are the SNMP device IPs to inventory (see ADR
  0007); the agent reports each device's identity and its interface MACs. For a
  `name_lookup` scan they are the individual host IPs to name over NetBIOS/mDNS
  (see ADR 0010); each must be a single host (a CIDR is reported as a skipped
  notice, since the probes are unicast). For a `dns_lookup` scan they are the
  individual host IPs to resolve via reverse PTR + forward confirmation (see ADR
  0012). For a `dhcp_leases` scan they scope which IP ranges to ingest from the
  agent's mounted lease file (see ADR 0014). For an `lldp_cdp` scan they are the
  switch/router IPs to query over SNMP (see ADR 0011); the agent reports the LLDP
  and CDP neighbors each device sees, keyed by the neighbor's management address.
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
- `vendor`: optional MAC vendor (from nmap's OUI data or the SNMP source).
- `hostname`: optional hostname (nmap reverse DNS, SNMP `sysName`, or a
  NetBIOS/mDNS name).
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

### Error codes

`errors` carries failures, but also informational notices. A combined scan whose
best-effort enrichment (SNMP or NetBIOS/mDNS) got no response — or was pointed at
a CIDR, which these unicast queries cannot expand — reports a notice with code
`scan_ignored` (`scanner.CodeScanIgnored`) rather than failing. The app does not
promote `scan_ignored` to a job's headline error, and the result detail view
renders these as a muted "Skipped" section. A result whose only errors are
`scan_ignored` notices is still `succeeded`.

## Lifecycle

1. App creates scan job.
2. App sends job to registered agent.
3. Agent validates mTLS identity and allowlists.
4. Agent accepts or rejects job.
5. Agent reports status updates.
6. Agent reports final result.
7. App writes audit entries, persists observations into the discovery queue, and
   imports them only by operator action or by the agent's explicit auto-import
   trust setting.
