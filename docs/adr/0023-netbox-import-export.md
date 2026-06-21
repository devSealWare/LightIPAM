# ADR 0023: NetBox-compatible Import / Export

## Status

Accepted.

## Context

Light IPAM already has a CSV import/export on-ramp (Phase 4.5, ADR 0016): export columns
mirror the forms, every imported row is validated against the same rules, a dry-run
preview shows per-row outcomes, and the apply is all-or-nothing in one transaction.
NetBox is the most common open-source IPAM/DCIM, and operators evaluating or migrating
to/from it want to move their prefixes, IP addresses, and devices without hand-editing
columns. This is the fourth slice of **Phase 6 (Advanced Automation)** — the roadmap's
"NetBox-compatible import/export" item.

The constraints are unchanged: app-side only, no new privilege, no scanner surface, no
client JS, and the import must keep the same dry-run + all-or-nothing discipline so a
NetBox file can never be partially applied.

## Decision

Add a **NetBox** CSV format alongside the native one. The Import / Export page gains a
per-type **Format** selector (Light IPAM / NetBox) and **Export NetBox** links; the
import dry-run and apply are otherwise identical.

### Import is a pure translation, not a second pipeline

A NetBox upload is **translated into the canonical Light IPAM columns** before
validation, so it reuses the exact same validators (`validateSubnets` /
`validateAddresses` / `validateDevices`), dry-run preview, transactional apply, and
audit path. The translator `translateNetBoxImport(entity, header, records)` (in
`internal/app/netbox.go`) is **pure and unit-tested**: it maps NetBox column names and
value semantics to the canonical header/rows, preserving row count and order so the
preview's line numbers still point at the uploaded file. A missing required NetBox
column (`prefix` / `address` / `name`) is a file error surfaced in the preview. The
`format` rides through the dry-run on `ImportResult.Format` (a hidden field on the apply
form), so the confirmed apply re-translates and re-validates the same file.

Value mappings (also pure, tested) — `mapNetBoxIPStatus` (NetBox IP status →
address state: `active`/`dhcp`/`slaac` → `assigned`, `reserved`, `deprecated`),
`stripMask` (NetBox `address/mask` → host), and the prefix/device column maps. The full
table lives in `docs/NETBOX.md`.

### Export emits NetBox columns

Three new handlers emit NetBox-named CSV: prefixes (`prefix, status, vlan_vid, site,
description`), IP addresses (`address, status, dns_name, description`), and devices
(`name, status, description`). `reverseNetBoxIPStatus` and `netboxAddressString`
(host + the containing subnet's mask, `/32` fallback) map values back. They reuse the
same `ListSubnets` / `ListAddressesForExport` / `ListDevices` queries and the shared
`beginCSV` writer.

### Documented lossiness

The models don't align perfectly, so the mapping is lossy at two documented edges:
NetBox prefixes have no name (Light IPAM's subnet **name** is carried in the NetBox
`description` so it round-trips), and NetBox devices require a role/type/site Light IPAM
does not model (a Light IPAM device export is not directly importable into NetBox
without adding those columns). The IPAM core — prefixes ↔ subnets and IP addresses —
round-trips cleanly. `docs/NETBOX.md` spells out every column.

## Consequences

- An operator can move prefixes, IP addresses, and devices between NetBox and Light
  IPAM with NetBox's own CSV columns, through the same safe dry-run + all-or-nothing
  import — no hand-editing of headers.
- Almost no new validation/apply surface: the NetBox path is a thin, pure translation in
  front of the existing pipeline, so both dialects share one set of rules and one
  transactional apply. No schema change, no new dependency, no client JS, no new
  privilege.
- The documented lossy edges (prefix name, device role/type/site) are inherent to the
  model differences; the round-trippable core is the IPAM data operators actually
  migrate. A future increment could add a NetBox **JSON/API** format behind the same
  translator seam if needed.
- This is the fourth Phase 6 slice; the last is a Terraform provider or CLI (ADR 0024),
  which depends on a stable authenticated read/write API + roles — to be confirmed with
  the user (CLI vs provider) before starting.
