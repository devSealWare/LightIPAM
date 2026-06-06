# ADR 0009: Staged nmap Scanning and Dynamic Scan Timeouts

## Status

Accepted.

## Context

Two related problems with the nmap scan path surfaced in use:

1. **Methodology.** A scan ran nmap once with the full flag set for its type. nmap
   already does the right thing internally (it won't port-scan a host that failed
   host discovery, and it version-probes only open ports), but that pipeline was
   implicit: there was no fast "is anything even alive here?" gate, so a scan of a
   mostly-dead range could spend its whole budget before finding the few live
   hosts, and the methodology was not legible or independently tunable.

2. **Timeouts caused "context deadline exceeded".** `ScanJob.TimeoutSeconds` is the
   per-host budget (nmap `--host-timeout`). The agent correctly sized its
   supervising context as `perHost × hosts + grace`, but the **app's dispatch HTTP
   context** was only `perHost + 10s`. The dispatch is a single blocking call the
   agent answers when the whole scan finishes, and the HTTP client has no timeout
   of its own — so for any multi-host (CIDR) scan the app's context fired long
   before the agent was done, and the job failed with "context deadline exceeded".
   The flat 60s default per-host timeout also under-served slow/thorough scans.

## Decision

- **Stage nmap explicitly.** `NmapDiscoverer.Discover` now runs two passes:
  1. **Host discovery** — a fast `-sn -T4` sweep over the raw targets finds the
     live hosts (and their MAC/vendor on the local segment). If nothing is alive,
     it short-circuits with no port scanning. `host_discovery` is exactly this
     stage.
  2. **Service/OS detection** — only the live hosts are passed to a second pass
     that skips re-discovery (`-Pn`), scans the mode's ports, and lets nmap
     version-probe only the ports it finds open (`-sV`), plus `-O` where the type
     asks for it.
  Stage-1 and stage-2 findings merge per IP (`mergeObservations`, reused from the
  combined discoverer). The injectable command runner keeps the staged pipeline
  hermetically testable. `combined`'s nmap portion inherits staging for free.

- **Per-host timeout defaults are dynamic by scan type and generous.**
  `app.defaultTimeoutForType` fills a blank timeout with a per-type value
  (host_discovery 120s, service_detection 600s, os_probe 900s, combined 1200s,
  arp_table 180s, snmp_inventory 300s). `--host-timeout` is a *ceiling*, so a high
  value is harmless for fast hosts and only protects slow ones; the form shows the
  active default as the field's placeholder.

- **One shared budget formula bounds the whole job, everywhere.**
  `scanner.ScanBudget(perHostSeconds, targets)` returns `perHost × host-count +
  host-discovery allowance + grace`, capped at 4h (raised from 2h). The agent uses
  it to supervise the discoverer; the app uses it (plus 60s network grace) for the
  dispatch context, so the app always outlasts the agent. `EstimateTargetHosts`
  and the budget moved to `internal/scanner/budget.go` so both sides share one
  implementation instead of the app guessing.

## Consequences

- A scan of a sparse range no longer burns its budget probing dead space — the
  discovery sweep narrows to live hosts first, then the expensive port/version
  work runs only against them. The methodology is now explicit and each stage is
  independently tunable.
- Multi-host scans no longer fail with "context deadline exceeded": the app's
  dispatch deadline is derived from the same budget the agent uses, not a flat
  `perHost + 10s`.
- nmap is invoked up to twice per job instead of once. The extra process start is
  negligible next to scan time, and nmap's own behavior is unchanged (it already
  version-probed only open ports); the win is the alive-gate and per-stage
  control, not a change to what nmap does on a live host.
- A firewalled host that drops all discovery probes can be missed by stage 1 (the
  classic host-discovery trade-off). On a LAN, ARP discovery is reliable; across a
  router, nmap's default ping set is used. If this becomes a problem, a future
  option can force `-Pn` (skip discovery, scan every target) at the cost of speed.
- The 4h budget cap means the app can hold a dispatch connection open for a long
  deep scan of a large range. That is by design (the scan runs in its own
  goroutine) and is what prevents premature cutoff; `--host-timeout` still bounds
  each individual host.
