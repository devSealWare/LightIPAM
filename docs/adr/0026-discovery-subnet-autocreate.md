# ADR 0026: Subnet auto-create on import + "Import all" discoveries

## Status

Accepted.

## Context

The `/discoveries` review queue (ADR 0005, and every Network-Context source after it)
lets an operator turn a scanned host into managed IPAM records one row at a time. Import
places the address into the **subnet that contains it** (`cidr >>= ip`) and refuses with
`ErrNoContainingSubnet` when no such subnet exists yet. In practice a fresh scan of a new
network surfaces a queue full of hosts that all fail to import until the operator leaves
the page, hand-creates each subnet on `/subnets/new`, and comes back — a tedious loop,
especially right after onboarding when *nothing* is defined yet.

Two gaps, then:

1. Importing a host with no containing subnet dead-ends on an error instead of helping
   the operator define the subnet.
2. There is no way to clear a reviewed queue in bulk; each host is an individual import.

The standing constraints still apply: the web app stays unprivileged, no scanner
surface, **no client JS** under the unchanged strict CSP, and IPAM mutations remain
audited (so they also fan out to change webhooks, ADR 0022).

## Decision

Add a **subnet-creation modal** to the Discoveries page, opened whenever an import needs
a subnet that does not exist yet, and an **"Import all"** control that imports the whole
importable queue in one click — using that same modal to resolve any missing subnets
first.

### One modal, pre-filled from the scan

When an import has nowhere to land, the page opens a modal that *is* the subnet form,
pre-filled with a suggested **`/24`** containing the host (`suggestSubnetCIDR`, masks the
host address to a `/24` — the common small-business size) and the scanned **VLAN** when
one was learned. The CIDR is editable; the operator typically just names it and saves.
On save the subnet is created and the import that opened the modal resumes automatically.

The modal is a **server-rendered, pure-CSS overlay** (the `glass-panel` styling, the
Discoveries sky accent, `role="dialog"`/`aria-modal`, click-outside and Cancel return to
the queue) — no client JS, consistent with the codebase's JS-off discipline. It renders
"open" because the server decided to show it; `autofocus` puts the cursor on the name
field. All mutations are POST with redirect-after-POST, so a refresh never re-submits.

### "Import all" with a resolve-then-import loop

`POST /discoveries/import-all` imports every **pending, non-conflicting** discovery
(`ListPendingImportTargets`, which also reports per-target `HasSubnet` via the same
`cidr >>=` containment the import uses). The flow:

1. If any targets lack a containing subnet, **do not import** — redirect to the modal for
   the **first missing subnet**.
2. Hosts are grouped by suggested `/24` (`missingSubnetGroups`), so a network with several
   discovered hosts prompts **once**, not per host. Groups are walked in ascending
   network order.
3. After each subnet is created, the flow **re-checks** for remaining missing subnets and
   prompts for the next, **looping until none remain**, then imports everything and lands
   on a "Imported N hosts" banner.

`conflict` discoveries are deliberately excluded from the bulk action and the missing-
subnet resolution — resolving a conflict is an operator decision, never a bulk one (it
matches how auto-import already treats conflicts, ADR 0007). The operator-edited CIDR is
validated to actually **contain the host** before the subnet is created, so a mistyped
range surfaces an in-modal error instead of a silent re-failed import.

### Why server-driven, not a client wizard

The resolve-then-import loop is inherently a series of "create a thing, re-check the
world" steps. Driving it from the server — each step a POST that redirects to a GET that
re-renders the next modal — keeps it refresh-safe, CSP-clean (no JS), and reuses the
existing `CreateSubnet` + `ImportDiscovery` store methods and their auditing verbatim.
The single-import path and the bulk path share one modal and one `discoverySubnetCreate`
handler, differing only by a `flow` field (`import-one` vs `import-all`).

## Consequences

- A brand-new network goes from scan → managed IPAM in a few clicks: run a scan, hit
  **Import all**, name each subnet as it's offered, done.
- No schema change, no new privilege, no new audit events — imports still emit
  `scan.discovery.imported` and subnet creation still emits `subnet.created`, so change
  webhooks and the audit log see exactly what they saw before.
- The modal creates only the core subnet (name / CIDR / VLAN / site / description).
  Operator-defined **custom fields** (ADR 0019) are not edited in the quick-create modal;
  they remain available on the full subnet edit page afterward.
- The suggested `/24` is a default, not a constraint: an operator who needs a `/25` (or a
  subnet that doesn't overlap an existing one) edits the prefix, and the existing overlap
  guard / containment check report the problem in-modal.

## Alternatives considered

- **A client-side wizard / `<dialog>` driven by JS.** Rejected: it would be the first
  app-side feature to require client JS for its core flow, against the strict-CSP, JS-off
  norm. The server-driven loop is just as smooth and stays refresh-safe.
- **Auto-creating the subnet without asking** (e.g. silently materialize a `/24`).
  Rejected: subnet boundaries, names, and VLANs are operator decisions; guessing them
  would create mislabeled or wrongly-sized subnets that overlap real ones.
- **Importing conflicts in the bulk action.** Rejected: conflicts need individual review;
  importing them en masse would paper over exactly the discrepancies the queue exists to
  surface.

## Implementation

- `internal/store/discoveries.go`: `DiscoveryImportTarget` + `ListPendingImportTargets`
  (pending, non-conflict, with `HasSubnet`).
- `internal/app/discoveries.go`: `discoveriesImportAll`, `discoverySubnetCreate`, the
  resolve-loop render helpers, and the pure, unit-tested `suggestSubnetCIDR` /
  `missingSubnetGroups`.
- `internal/app/app.go`: `POST /discoveries/import-all`, `POST /discoveries/subnet`.
- `internal/ui/ui.go`: the `DiscoverySubnetPrompt` view model + PageData fields.
- `internal/ui/templates/discoveries.html`: the "Import all" control, the success
  banner, and the modal.
- Tests: `internal/app/discoveries_test.go` (pure helpers) and a modal render test in
  `internal/ui/ui_test.go`.

See [`docs/SCANNER_DISCOVERY.md`](../SCANNER_DISCOVERY.md) "Review queue".
