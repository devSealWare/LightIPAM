# ADR 0016: CSV Import/Export and Bulk Edit

## Status

Accepted.

## Context

A full audit (2026-06-17, merged in #54) found one earlier-phase feature that was
scoped but never built: **bulk edit + import/export** for the manual-IPAM UI. It is
listed under Phase 1 in `docs/ROADMAP.md`, called out in `docs/MVP.md` ("Bulk edit
and import/export should be available in the UI early. CSV support can be deferred
until the data model is stable"), and is backlog item #4. The data model has been
stable since Phase 1, so the work was unblocked; it is tracked as **Phase 4.5** to
keep it from slipping between the scanner phases.

Two needs sit behind one feature:

- **Bulk edit** — an operator who has touched dozens of addresses (often via
  discovery import) needs to retag, restate, or delete them without visiting each
  row.
- **CSV import/export** — the on-ramp for getting existing inventory *into*
  LightIPAM and back *out* for a spreadsheet edit or a backup. This is the basic CSV
  format, deliberately distinct from the richer NetBox-compatible format planned for
  Phase 6.

The constraints are the project's existing ones: the web app stays unprivileged
(this is all manual IPAM, no scanner involvement); progressive enhancement with a
strict CSP (server-rendered markup must work with JavaScript off, any script is a
same-origin embedded file, no inline JS — exactly like the selectable-columns
feature); and every mutation writes an immutable audit entry. Import must reuse the
**same** validation the forms enforce — IPv4-only including `/31` and `/32`, global
subnet-overlap blocking, the sparse address model, and the address-state enum — so a
CSV cannot create records a form would reject.

## Decision

### Bulk edit

- **Multi-select on the Subnets, Addresses (subnet detail), and Devices tables.**
  Each table is wrapped in one `POST` form; each row carries a checkbox
  (`name="ids"`), and an always-visible action bar selects the operation. Actions:
  addresses — set status, add/remove tag, clear device link, delete; subnets — set
  VLAN, add/remove tag, delete; devices — add/remove tag, delete.
- **Progressive enhancement.** The tables work fully JS-off (check rows, pick an
  action, fill the matching field, submit). `internal/ui/static/bulk.js`
  (same-origin, embedded via `ui.BulkJS` + `GET /static/bulk.js`, referenced from
  `base.html`) only adds select-all, a live count, disabling Apply until a row and
  action are chosen, and showing only the chosen action's field. No inline JS; the
  strict CSP is unchanged.
- **Destructive actions route through the shared `confirm.html`,** which now carries
  the selected ids forward as hidden inputs so the confirmed POST re-runs the same
  delete. A `split` template func renders the comma-joined ids (IDs are base64url, so
  comma-joining is safe).
- **Store methods are single `id = ANY($1)` statements** in `internal/store/bulk.go`;
  tagging reuses the shared `taggings` table for the `subnet`/`ip_address`/`device`
  entity types (mirroring `TagDevice`). `ListSubnets`/`ListAddresses` now aggregate
  tags so the new tag chips render (Devices already showed tags).
- **`parseBulkRequest` is a pure, unit-tested validator** reusing the existing
  IPv4/VLAN/state rules; each handler audits with selected/affected counts.

### CSV import/export

- **One CSV shape per object, columns matching the create/edit forms,** so an export
  re-imports cleanly:
  - subnets: `name, cidr, vlan, site, description`
  - addresses: `address, subnet, state, hostname, device, notes`
  - devices: `name, description`
  Headers are matched by name, case-insensitively, so column order is flexible and a
  leading UTF-8 BOM is tolerated. Export uses the stdlib `encoding/csv`.
- **Upsert on each object's natural identity** so export→import is idempotent:
  subnets key on CIDR, addresses on the address, devices on name. A matching key
  updates; a new key creates. (Device names are not unique, so a name collapses to
  the first such device — acceptable for the basic on-ramp and documented.)
- **Every row is validated against the form rules before anything is written.**
  Subnets: valid IPv4 CIDR (incl. `/31`,`/32`), VLAN range, resolved site, and no
  overlap with an existing subnet *or* another row in the file (an exact-CIDR match
  is an update, not an overlap). Addresses: valid IPv4, valid state, must fall inside
  an existing subnet (located by containment), and an optional device resolved by
  exact name (unknown/ambiguous is an error). The validators are pure functions over
  an `importContext` snapshot, so they are unit-tested without a database.
- **Dry-run preview, then apply on confirm.** `POST /import/{type}` parses the upload
  and renders a per-row preview (create/update/error with messages); the raw CSV
  rides forward in a hidden field. `POST /import/{type}/apply` **re-validates** that
  text and, only if no row has an error, applies the whole batch in **one
  transaction** — an invalid file is never partially applied, and a DB error rolls
  the batch back. Each import audits with created/updated counts.
- **No new dependency, no schema change.** It is stdlib `encoding/csv` over the
  existing tables. The import preview types live in `store` so the `ui` templates can
  render them without an import cycle.

## Consequences

- An operator can bulk-retag/restate/delete records and move inventory in and out via
  spreadsheet, closing the last carried-forward Phase 1 item.
- Export→import is idempotent: re-importing an unedited export reports all updates and
  changes nothing.
- Import is safe by construction — same validation as the forms, all-or-nothing apply,
  a dry run before any write, and an audit trail.
- This is the basic CSV format. A NetBox-compatible import/export remains a separate
  Phase 6 item; the two can coexist (different endpoints/columns).
- Device identity in CSV is the (non-unique) name, so duplicate names collapse on
  import and device links in the addresses CSV resolve by exact name. A future CSV
  revision could carry a stable device id if round-tripping duplicate names matters.
- IPv4 only, matching the rest of LightIPAM.
