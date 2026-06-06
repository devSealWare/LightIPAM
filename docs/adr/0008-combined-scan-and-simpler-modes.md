# ADR 0008: Combined Scan (nmap + ARP + SNMP) and Simpler Scan Modes

## Status

Accepted.

## Context

Phase 4 added three discovery backends — nmap (ADR 0005), SNMP ARP-table
harvesting (ADR 0006) and SNMP device inventory (ADR 0007) — each as its own scan
type. Getting the "most complete picture" of a host a router away meant running
several scans by hand (an nmap service scan plus an `arp_table` harvest at the
gateway plus an `snmp_inventory` of the device) and letting the per-IP discovery
merge stitch them together. That works but is tedious and easy to get wrong.

Two friction points in the scan form compounded it:

- **The Mode picker applied to every scan type, but only nmap uses it.** SNMP and
  ARP read whatever the device exposes; "intensity" is meaningless for them. The
  one mode that *was* offered to them, `passive`, is a no-op for every backend
  (it always returns zero results), so it was a footgun for nmap scans too.
- **Four modes (`passive`/`light`/`standard`/`deep`)** were more than the depth
  gradient needs.

## Decision

- **`combined` runs all three backends in one job and merges the result.** A new
  `CombinedDiscoverer` (`internal/scanner/agent/combined.go`) composes the nmap
  and SNMP discoverers: it runs a **deep** nmap scan (every port, `-sV` + `-O`),
  then an `arp_table` harvest and an `snmp_inventory` of the targets. nmap is the
  core — if it fails, the job fails — but the SNMP passes are **best-effort
  enrichment**.
- **No SNMP response is *ignored*, not failed.** A device that does not answer
  SNMP, an unsupported SNMP version, or a CIDR target (SNMP must be aimed at one
  device) yields a notice with the new `scanner.CodeScanIgnored` (`scan_ignored`)
  code instead of a failure. The orchestrator's `headlineError` skips ignored
  notices, so a combined scan whose SNMP portion was silent still reports
  **succeeded**; `/scans/{id}` renders ignored notices in a muted **Skipped**
  section, not as red errors.
- **Observations merge per IP at the agent.** `mergeObservations` consolidates the
  three backends' observations for a host into one record (the leading nmap source
  wins scalar fields; services union by port; evidence concatenates). The
  discovery store already merges by IP (`ON CONFLICT (ip)`), so this is belt-and-
  suspenders that also makes the scan-detail page show one card per host.
- **Mode is an nmap-only depth knob; the picker hides for the rest.** `arp_table`,
  `snmp_inventory` and `combined` ignore mode entirely. The scan/schedule form
  normalizes the mode server-side by type (`app.modeForType`: SNMP/ARP → a
  canonical active mode, combined → deep), so the form posts a valid job even with
  the picker hidden and even with JavaScript disabled. A small same-origin script
  (`static/scan_form.js`, like `columns.js`) hides the picker and shows a per-type
  hint as progressive enhancement; the strict CSP is unchanged (no inline JS).
- **Three depths, no `passive` in the UI.** Modes reduce to **Light** (top-1000
  service detection), **Standard** (top-1000 + `--version-all` + `-O`) and **Deep**
  (every port `-p-` with `-sV` + `-O`). `passive` remains a valid protocol value
  (the agent's no-packets short-circuit) but is no longer offered as a choice.
- **Deep is tuned for speed, not slowed by service detection.** The cost of a deep
  scan is the 65535-port SYN sweep, not `-sV` (which only probes the open ports it
  finds). So deep keeps `-sV` for real service detection but **drops
  `--version-all`** (the exhaustive per-port version probing, kept on standard's
  small port set) and runs the sweep aggressively: `-T4`, `--max-retries 2`, and —
  unless the operator pinned an explicit rate — `--min-rate 1000`. The previous
  hidden `--max-rate 100` default (which throttled every scan, making an all-port
  sweep take ~11 min/host) is no longer applied to deep; shallow modes keep that
  conservative cap. The job timeout (`--host-timeout`) still bounds each host.

## Consequences

- One `combined` scan of a device now gathers services, OS, the device's own
  identity, and MACs (its interfaces' and its neighbors') in a single action, and
  they land on one discovery row / one device — no manual multi-scan choreography.
- A combined scan of a plain host (no SNMP) or a whole CIDR succeeds with whatever
  nmap found; the unused SNMP passes show as Skipped, which is informative rather
  than alarming.
- No new privilege, dependency, or schema change: combined reuses the existing
  nmap (NET_RAW) and SNMP (UDP/161) backends, the discovery pipeline, and the
  `scan_discoveries` columns. `scan_ignored` is a string code, not a migration.
- Existing schedules stored with `mode = passive` are no longer selectable as
  passive; re-saving such a schedule picks a real depth. Passive scans produced no
  results, so nothing of value is lost.
- The combined nmap scan is always deep (all ports). It is the broadest scan, but
  the timing tuning keeps it far quicker than a throttled `--version-all` sweep
  would be; operators who want the quickest look still pick `service_detection` at
  Light. The faster, uncapped deep sweep is also louder on the wire — acceptable
  for an admin scanning their own LAN, and still bounded by `--host-timeout`.
