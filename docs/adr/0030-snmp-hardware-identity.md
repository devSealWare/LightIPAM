# ADR 0030: SNMP hardware identity and gold-confidence device links

## Status

Accepted. Implements "Phase 2" as planned in ADR 0029.

## Context

ADR 0029 linked a multi-homed device's per-subnet records with a heuristic rule
(identical hostname + same OS family + disjoint subnets) that always needs a human
confirmation, because hostnames and OS fingerprints are circumstantial. Devices
that speak SNMP can do better: the ENTITY-MIB chassis serial number names the
physical *unit* — every interface of one box reports the same serial — and the
`snmp_inventory` scan already talks to exactly these devices.

Constraints: SNMP support is v2c-only (the SNMPv3 engine ID is therefore not
obtainable today), vendors sometimes ship placeholder serials ("N/A",
"To be filled by O.E.M."), and cloned VMs or cheap hardware can carry duplicate
serials — so even a serial match must keep sanity guards, and automatic linking
must be opt-in.

## Decision

**Collect.** The agent's `snmp_inventory` (and `combined`) scan walks the
ENTITY-MIB `entPhysicalClass`/`entPhysicalSerialNum` columns and picks the
chassis-class serial (falling back to the lowest-indexed usable serial), rejecting
well-known placeholder values (`usableSerial`, pure + unit-tested). Observations
gain two additive fields — `hw_serial` and the already-read `sysObjectID` as
`hw_object_id` — so the scanner protocol stays `v1`. The SNMPv3 engine ID is
**out** until SNMPv3 lands (the stack is v2c-only).

**Persist.** Migration 23 adds `hw_serial`/`hw_object_id` to `scan_discoveries`
and `devices` (non-empty wins on merge, mirroring the OS fields, so an nmap
re-scan never wipes what SNMP learned). `hw_object_id` identifies the
vendor/model only — never the unit — so it is stored for display/evidence and
**never matched on**.

**Match (gold confidence).** `goldHardwareCandidate` (pure, unit-tested) declares
two device records the same physical unit when both report the same non-empty
trimmed serial (case-sensitive — a serial names one unit) **and** their subnet
sets are disjoint and non-empty. The subnet guard survives even at gold
confidence as the cloned-serial defense. Serial matches surface as distinct
"Serial match" suggestions on the device page regardless of hostname/OS
agreement; dismissed pairs stay dismissed.

**Opt-in auto-link.** A new **Settings → Discovery** toggle
(`device_link_auto_serial` in `app_settings`, default **off**) lets the operator
allow linking without confirmation: after any discovery import or re-scan sync,
`AutoLinkDeviceBySerial` links the device to every gold-confidence serial match,
audited as `device.link.auto`. It respects dismissals and never fails the
import/sync it follows. With the toggle off, serial matches remain
suggest-and-confirm like everything else.

## Consequences

- The OPNsense-style router that motivated ADR 0029 now links on hard evidence
  once an SNMP inventory scan has seen it — and can link itself, if the operator
  opts in.
- The app remains unprivileged; SNMP stays in the agent over plain UDP/161; the
  agent's security posture and allowlist checks are untouched.
- Devices without SNMP (or without the ENTITY-MIB) simply keep the ADR 0029
  heuristic path; nothing regresses.
- The serial is inventory data an operator can read on the device page; it is
  not treated as a secret (it identifies hardware, not credentials).
