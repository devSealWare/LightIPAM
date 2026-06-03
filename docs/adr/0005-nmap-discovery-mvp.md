# ADR 0005: Nmap Discovery MVP

## Status

Accepted.

## Context

ADR 0004 gave the app the ability to dispatch and schedule scan jobs to a no-op
agent over mTLS, storing raw results but never probing the network. Issue #10
adds the first real active discovery: the agent runs nmap, and observations
become managed IPAM records.

This is the first time the system gains a privileged capability and the first
time scan output can mutate IPAM data, so both the privilege boundary and the
write path need explicit decisions.

## Decision

- **Discovery runs in the agent via nmap.** A new `Discoverer` interface
  (`internal/scanner/agent`) abstracts active scanning; the nmap implementation
  shells out with an injectable command runner so argument building and XML
  parsing are unit-tested without raw-socket privileges. The app never gains a
  discoverer.
- **Scan depth is bounded by mode.** `passive` runs no nmap at all;
  `light_active` is a host-discovery ping/ARP sweep (`-sn`); `standard_active`
  adds top-1000 TCP service detection (`-sV`); `deep_active` adds OS probing
  (`-O`). Scan type (`host_discovery`/`service_detection`/`os_probe`/`combined`)
  selects what is collected; mode selects intensity. Job rate limits map to
  nmap's `--max-rate`/`--max-parallelism`.
- **The privilege boundary stays in compose.** The agent image bundles nmap and
  runs as root so nmap can use raw sockets; the agent **service** drops every
  capability except `NET_RAW`. The web app image carries no nmap and runs with
  zero capabilities. Verified at runtime: app `CapEff=0`, agent
  `CapEff=0x2000` (NET_RAW only).
- **Observations land in a review queue, not auto-created.** Each observed host
  is upserted into `scan_discoveries` (keyed by IP; existing imported/dismissed
  rows are not resurrected). An operator imports a discovery — which creates or
  updates the address in its containing subnet and, when a MAC is known, a device
  + MAC record — or dismisses it. Nothing mutates IPAM data without consent. This
  departs from the backlog's "auto-create by default" in favor of a safer,
  auditable default for the small-business target; auto-import can be layered on
  later as a per-agent trust setting.
- **Enrollment is app-pull.** The agent exposes `GET /register` (self-reported
  identity + allowlist) behind the same mTLS/client-CN check as `/jobs`. The app
  pulls it — automatically at boot for the bundled agent
  (`SCANNER_AGENT_ENDPOINT`), or on demand from the `/agents` "Discover" form —
  and enrolls the agent as `pending` for one-click approval. This keeps the mTLS
  direction (app = client) and adds no inbound surface to the app.

## Consequences

- The system performs real IPv4 host discovery, TCP service detection, and OS
  probing, all isolated to the agent. The app remains unprivileged.
- Discoveries are reviewable and auditable; imports reuse existing IPAM
  structures (subnet containment, device/MAC creation) and are idempotent.
- Importing a discovery requires a managed subnet that contains the address;
  otherwise the import is refused with guidance to create the subnet first.
- nmap accuracy (especially OS detection) varies; observations are advisory and
  an operator confirms them at import time.
- Certificate issuance/rotation remains the dev-grade generator from ADR 0003.

## Update — Phase 3 completion (conflict reconciliation)

A follow-up to this issue (migration 7) adds reconciliation so the review queue
is not blind. Each observation is compared to the managed records and tagged
`new` / `match` / `conflict` (`store.reconcileDiscovery`): a conflict is a changed
MAC on the address's device, a responding host marked `deprecated`, or a MAC
already bound to a different address. Conflicts are surfaced in the UI before
import. Reconciliation also refreshes `last_seen_at` on a matched/conflicting
managed address — the only IPAM write a scan performs without an explicit import —
which completes the roadmap's Phase 3 "last-seen tracking and conflict detection."
