---
name: lightipam-scanner-change
description: Use for any LightIPAM change touching the scanner-agent or discovery — nmap, SNMP, NetBIOS/mDNS, DNS, DHCP leases, LLDP/CDP, scan scheduling, diagnostics, agent/app mTLS, egress pin/route/macvlan/bridge, or scan allowlists.
---

# LightIPAM Scanner Change

The highest-risk surface in the repo: it is where the unprivileged/privileged
boundary lives. Read [`AGENTS.md`](../../../AGENTS.md), `docs/SCANNER_PROTOCOL.md`,
`docs/SCANNER_AGENT.md`, and `docs/SCANNER_DISCOVERY.md` before editing.

## Applies to

nmap · SNMP (`arp_table` / `snmp_inventory` / `lldp_cdp`) · NetBIOS/mDNS
(`name_lookup`) · DNS (`dns_lookup`) · DHCP leases (`dhcp_leases`) · the `combined`
scan · scan scheduling and windows · scan diagnostics · app↔agent mTLS · egress
pin/route (`AGENT_SCAN_PIN_MODE`, macvlan/bridge) · scan allowlists.

## Hard rules (do not violate)

1. **The app stays unprivileged.** No nmap, raw sockets, packet capture, or Linux
   network capability in the `app` container. `NET_RAW` is granted to `scanner-agent`
   only, and only for nmap.
2. **Active discovery stays in the agent.** New discovery logic goes under
   `internal/scanner/agent` and is wired onto the `DiscoveryRouter`; the app only
   orchestrates, dispatches over mTLS, and reconciles results.
3. **Both allowlist checks must stay valid.** App-side `ValidateJobForAgent` (active +
   agent_id + allowlist containment) and agent-side `ValidateAgentScope` (containment).
   Save-time scope validation (`validateScanScope`, `ValidateScope`) must match the
   agent's dispatch rules — a scope accepted by a form must not be rejected at dispatch.
4. **Failures must be explainable to operators.** Do not let a job report `succeeded`
   with a misleading empty result. Emit a self-explaining notice (the `scan_ignored` /
   zero-host / pin-route-mismatch pattern) and keep it out of the headline error only
   when it is genuinely a skipped enrichment pass.
5. **Agent-only secrets stay on the agent.** SNMP community, egress pin, DHCP lease
   path, and the allowlist are agent env/config — never the app DB or the Settings UI.

## Workflow

1. **Restate** the discovery behavior and which backend(s) it touches. Confirm it does
   not require a new capability; if it seems to, stop and raise it.
2. **Plan the smallest change.** Reuse the review-queue + reconciliation path
   (`UpsertDiscovery`, merge-per-host) rather than a parallel pipeline. New scan types
   register on the router and appear in `scanTypeOptions()` and the scan form.
3. **Keep parsing hermetic and testable.** Wire formats and sessions sit behind
   injectable seams (`snmpSession`, `udpExchanger`, `NameResolver`, `leaseReader`,
   command runner) so encoders/parsers/filters are unit-tested **without a socket**.
   Add table-driven tests; never require live hardware to pass CI.
4. **Preserve two-sided validation and budgets.** If you change targets/scope/timeouts,
   keep `ValidateJobForAgent`/`ValidateAgentScope` and the shared `ScanBudget` consistent
   on both sides so multi-host scans don't trip a dispatch deadline.
5. **Validate.** [`VALIDATION.md`](../../../docs/agent/VALIDATION.md) Tier 0 + Tier 1
   (`docker compose --profile scanner build`) + Tier 2 scanner smoke. Run
   `go build -mod=readonly ./cmd/scanner-agent` to confirm no new dependency slipped in.
6. **Document.** Update `docs/SCANNER_*`, the README limitations if a caveat changes,
   `compose.yaml`/`.env.example` for any new agent env var, and add a numbered ADR for a
   behavior or boundary decision.

## Done when

- Tests pass hermetically (no live network), both images build, and both allowlist
  checks + the app-unprivileged boundary are demonstrably intact.
- Any new operator-facing behavior or caveat is in the scanner docs (and an ADR if it
  is a decision).
