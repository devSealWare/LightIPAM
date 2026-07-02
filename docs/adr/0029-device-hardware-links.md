# ADR 0029: Same-physical-device links (suggest-and-confirm, link-not-merge)

## Status

Accepted.

## Context

A multi-homed device — classically a router/firewall — presents one IP per subnet,
each on a different physical port with a **different MAC**. A real field sample: one
OPNsense box (`Archer_A7.internal`) imported as three separate device records —
192.168.0.1 (`58:9c:fc:10:ff:96`), 192.168.1.1 (`c4:62:37:09:1a:f4`), and 192.168.2.1
(`90:e2:ba:8f:a3:21`). The import path (`resolveImportDevice`) reuses a device only by
prior import or by MAC; that conservatism is correct (a shared MAC is near-proof of
identity, anything looser risks silently fusing different hosts), so distinct port
MACs legitimately produce distinct devices. Operators still need to see that those
three gateways are one box.

Notable input constraint: nmap fingerprinted the **same box** as
"FreeBSD 11.2-RELEASE" on two interfaces and "FreeBSD 14.3-RELEASE-p15" on the third,
so any rule requiring an exact OS string would fail on the motivating example.

## Decision

**Link, don't merge.** Migration 22 adds a nullable, indexed
`devices.hardware_group_id`: every device sharing a non-null group id is one physical
device. Each record keeps its own name, MACs, and its own address in its own subnet —
nothing is collapsed, and unlinking (nulling the id) fully reverses the operation. A
group left with fewer than two members dissolves. The group id is an opaque generated
token, not a table of its own.

**Suggest-and-confirm; never auto-link.** The system computes high-confidence
suggestions and shows them on the device detail page with the matching evidence; the
operator confirms ("Link") or dismisses. Nothing links without a human. Manual
link/unlink is always available and bypasses the rule entirely.

**The suggestion rule.** Two devices are suggested as the same hardware iff **all**
hold:

1. **Identical, non-empty hostname** (trimmed, case-insensitive) — the strong signal.
   A device's identity hostname is the single hostname its IP records agree on; a
   device whose addresses carry conflicting hostnames has no identity hostname and is
   never suggested.
2. **Same non-empty OS family** (`devices.os_family`). `os_detail` is deliberately
   **excluded** — it is display-only, per the mixed-release fingerprints above.
3. **Disjoint subnet sets, both non-empty.** A true multi-homed device has at most
   one IP per subnet, so two devices holding addresses in the same subnet are
   different hosts — never suggested.
4. Not already in the same hardware group, and the unordered pair has not been
   dismissed. Dismissals persist in `device_link_rejections` keyed by the unordered
   pair (`device_lo < device_hi`), `ON DELETE CASCADE` with the devices.

The pairwise predicate is a pure function (`sameHardwareCandidate` over
hostname/OS-family/subnet-IDs) with unit tests, per the codebase convention; SQL only
prefilters cheaply (matching hostname + OS family, not dismissed, not same group).

Confirm, unlink, and dismiss are CSRF-protected POSTs audited as
`device.link.confirmed`, `device.link.removed`, and `device.link.dismissed`.

## Consequences

- Gateways still list per-subnet (sparse storage untouched; nothing per-IP is
  materialized), while the device page shows the linked siblings with their IPs,
  subnets, MACs, OS, and services; the Devices list marks grouped records "Linked".
- The import path is unchanged: merge-on-MAC stays conservative, and links survive
  re-imports because records are reused, not recreated.
- The hostname signal depends on discovery having recorded hostnames; environments
  without reverse DNS/NetBIOS names get no suggestions and rely on manual linking.

## Phase 2 (PLANNED, not shipped)

A future, separate branch may persist an SNMP hardware identity — `sysObjectID`,
ENTITY-MIB `entPhysicalSerialNum`, and/or the SNMPv3 engine ID — through
`docs/SCANNER_PROTOCOL.md`, the `scan_discoveries`/`devices` schema, and the agent's
SNMP source, then use an exact serial/engine-ID match as a gold-confidence signal
that could support **opt-in** auto-linking. That work needs its own ADR; nothing in
this decision ships or depends on it.
