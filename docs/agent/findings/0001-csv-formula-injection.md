# 0001 — CSV formula injection in exports

- **Priority:** High
- **Area:** Security
- **Status:** Open — not yet fixed

## Summary

CSV exports (subnets, addresses, devices, and the NetBox-compatible export) use
`encoding/csv`, which quotes correctly for CSV *parsing* but does not neutralize
spreadsheet **formulas**. A field whose value begins with `=`, `+`, `-`, or `@` is
interpreted as a formula by Excel and Google Sheets when the exported file is opened.

## Evidence

A subnet was created with the name `=SUM(1+1)`. The exported `subnets.csv` contains
that value verbatim in the `Name` column. Opening the file in Excel/Sheets executes
it as a formula rather than displaying the literal string.

Realistic vector: subnet/device names and descriptions are operator-entered, and
discovered **hostnames** (from DNS, NetBIOS/mDNS, DHCP lease files) flow into
exports unmodified — an attacker who controls DNS/DHCP/NetBIOS records on a scanned
network can plant a hostname that becomes a formula in an operator's spreadsheet.

## Affected code

- `internal/app/portability.go:558` — `beginCSV()`, the shared CSV writer entry
  point used by all export handlers.
- `internal/app/portability.go:499-554` — `exportSubnetsCSV`, `exportAddressesCSV`,
  `exportDevicesCSV` (and the NetBox export path in `internal/app/netbox.go`), all
  of which write operator- or discovery-sourced strings as CSV cells via
  `cw.Write([]string{...})`.

## Fix instructions

1. Add a small pure helper, e.g. `sanitizeCSVCell(s string) string`, that prefixes
   the value with a leading `'` (single quote) when it starts with `=`, `+`, `-`,
   `@`, tab, or carriage return (the standard OWASP CSV-injection mitigation set).
   Keep it pure and unit-tested per repo convention (`docs/agent/CODE_REVIEW.md`).
2. Apply it to every cell written from operator/discovery-sourced fields before
   `cw.Write(...)` — not to fixed/internal values (e.g. numeric VLAN IDs).
   The cleanest chokepoint is likely wrapping `csv.Writer.Write` itself in a small
   wrapper type used by `beginCSV`, so no call site can forget it.
3. Add a regression test: create a subnet/device/address named `=SUM(1+1)` (or
   `@cmd|...`), export, and assert the exported cell begins with `'`.
4. Do the same for the NetBox export path (`internal/app/netbox.go`) if it shares
   `beginCSV` — verify at implementation time.
5. No migration, no new dependency, no UI change needed — this is a pure
   output-encoding fix at the CSV-writing layer.
