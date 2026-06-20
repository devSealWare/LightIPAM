# ADR 0019: Custom Fields for Subnets, Addresses, and Devices

## Status

Accepted.

## Context

A Phase 1–5 audit (2026-06-19) found one earlier-phase feature claimed complete but
never actually delivered: **custom fields**. They are listed under Phase 1 in
`docs/ROADMAP.md`, in `docs/MVP.md` ("Tags and custom fields"), and in backlog items
#2 ("Tables for … tags, and custom fields") and #5 ("Notes, tags, and custom
fields"). The backlog declares #1–#10 merged, and the schema tables
(`custom_fields`, `custom_field_values`, migration 1) do exist — so #2's
*schema* criterion was met — but no Go code or UI ever read or wrote them, so the
user-facing feature from #5 was missing. Tags, by contrast, were fully wired.

The need is the ordinary IPAM one: operators want to record a few site-specific
attributes (owner, asset tag, cost center, circuit ID…) on a subnet, address, or
device without a schema change for each. The data model has been stable since Phase
1, so the work was unblocked; it is closed here as part of the Phase 5 audit so the
"all backlog merged" claim is honest before Phase 6 begins.

Constraints are the project's existing ones: the web app stays unprivileged; strict
CSP with no inline JS (the feature is plain server-rendered forms, no script needed);
admin-only configuration with viewers read-only; and every mutation is audited.

## Decision

- **Definitions are operator-managed on an admin Settings tab.** A new **Custom
  fields** tab (`GET /settings/custom-fields`, admin-only via `requireAdmin`) defines
  a field by *entity type* (`subnet` / `ip_address` / `device`, matching the
  `taggings` entity-type vocabulary) and *name*. Names are unique per entity type
  (case-insensitively); a clash returns the new `store.ErrDuplicate`. The MVP field
  type is `text`; the `field_type` column leaves room for richer types later without a
  schema change. Create and delete are CSRF-protected and audited
  (`custom_field.created` / `custom_field.deleted`); deletion routes through the
  shared `confirm.html` because it cascades to stored values.

- **Values are sparse and edited inline on each entity's form.** The entity forms
  (subnet, address, device) render one input per defined field, named
  `cf_<definition-id>`, via a shared `custom_fields_form` template partial. On create
  and update the handler calls `store.SetCustomFieldValues`, which is bounded to the
  entity type's real definitions (an unexpected key is ignored) and stores sparsely —
  a blank value deletes the row. Detail pages (subnet, device) show values via a
  `custom_fields_display` partial; addresses have no separate detail page, so the
  edit form doubles as their view. When no fields are defined, the partials render
  nothing, so the feature is invisible until used.

- **Address values are set on edit, not on inline create.** The address "create" form
  is the compact panel on the subnet detail page; custom-field inputs live on the
  full address *edit* form, so an operator adds an address then edits it to set custom
  fields. Subnets and devices, which have full-page new forms, accept custom-field
  values at create time.

- **Supplemental, never load-bearing.** Saving values is best-effort: a custom-fields
  error is logged but does not fail the entity save or break a core IPAM page. The
  store work is a new `internal/store/custom_fields.go`; `SetCustomFieldValues` runs
  in one transaction (upsert/delete per field).

- **No schema change, no new dependency.** It is the migration-1 tables plus stdlib.
  The pure form parser (`parseCustomFieldValues`) and the entity-label helpers are
  unit-tested, and the new Settings tab + form/detail partials are covered by the UI
  render tests.

## Consequences

- An operator can define extra text attributes per object type and record them on
  any subnet, address, or device — closing the last unbuilt Phase 1 item and making
  the backlog's "merged" claim accurate.
- The Settings page gains a sixth tab (**Custom fields**), continuing the Phase 5
  "configurable from the UI" direction (`docs/SETTINGS.md`).
- Storage is sparse and the UI is zero-impact until a field is defined, so existing
  installs see no change.
- CSV import/export still covers the standard form columns only; carrying custom
  fields in CSV (and in the future NetBox format) is a possible follow-up.
- Field type is `text` for now; `select`/`number`/`date` types can be added on the
  existing `field_type` column without a migration.
