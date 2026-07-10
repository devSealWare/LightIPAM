# 0007 — Audit log metadata mostly empty; `scan.discovery.recorded` mislabels a count as `status`

- **Priority:** Low-Medium
- **Area:** Observability
- **Status:** Open — not yet fixed

## Summary

Two related gaps in the audit log's usefulness for forensics:

1. Most events write metadata `"{}"` because `a.audit(...)` hardcodes it
   (`internal/app/app.go:1625-1628`). For example, `subnet.created` records no
   CIDR or name — an investigator has to cross-reference the opaque subject ID
   against current (or, if since-deleted, unavailable) IPAM state.
2. `scan.discovery.recorded` writes `{"status": "17"}` where `17` is actually a
   **count** of discoveries recorded, not a status
   (`internal/scanner/orchestrator/orchestrator.go:224`, which calls the generic
   `s.audit(ctx, nil, "scan.discovery.recorded", job.ID, strconv.Itoa(recorded))`,
   and `auditSubject` at line 481-486 always wraps the string as
   `{"status": %q}`).

There is already a structured-metadata path (`auditMeta`, `internal/app/app.go`
just below `audit`) that several call sites presumably use — this is about
extending that pattern to the call sites that currently pass through the
bare `audit()`/`s.audit()` helpers with no context.

## Affected code

- `internal/app/app.go:1625-1628` — `audit()`, hardcodes `"{}"`.
- `internal/app/app.go` (`auditMeta`, just after `audit`) — the existing
  structured-metadata helper; the pattern to extend, not replace.
- `internal/scanner/orchestrator/orchestrator.go:477-486` — `audit()` /
  `auditSubject()`, which always shapes metadata as `{"status": %q}` regardless
  of what the caller's `status` string actually represents.
- `internal/scanner/orchestrator/orchestrator.go:224` — the specific
  `scan.discovery.recorded` call passing a count through the `status` field.
- Every call site currently using the bare `a.audit(...)` for a
  `subnet.*`/`address.*`/`device.*`/`mac.*` mutation (grep
  `a.audit(r, &session.User.ID, "subnet.` etc. across `internal/app/*.go`) is a
  candidate for switching to `auditMeta` with real context (CIDR, name, old/new
  value where relevant).

## Fix instructions

1. **`scan.discovery.recorded` mislabel (small, isolated fix):** change
   `auditSubject`'s metadata shape to accept a proper field name, or add a
   sibling helper (e.g. `auditCount`) so `scan.discovery.recorded` writes
   `{"recorded_count": 17}` instead of `{"status": "17"}`. Check other callers of
   `s.audit`/`s.auditSubject` in the orchestrator first — some may legitimately
   be reporting a status string (e.g. `succeeded`/`failed`), so don't rename the
   field globally without checking each call site's actual semantics.
2. **Sparse metadata (broader, do incrementally):** for each mutation event
   currently using the bare `audit()` helper, switch it to `auditMeta(...)` with
   a small `map[string]string` of the fields an investigator would actually
   want — e.g. `subnet.created`/`subnet.updated` → `{"cidr": ..., "name": ...}`,
   `device.created` → `{"hostname": ...}`. Keep it to cheap, already-in-hand
   values from the handler — don't add extra DB reads just to enrich audit
   metadata.
3. This can land as one PR per logical group (e.g. subnets, then addresses,
   then devices) rather than one giant diff, consistent with "one issue/task per
   branch" — or as a single scoped PR if the total diff stays small and
   reviewable; the implementer should judge based on actual diff size.
4. Add/extend tests asserting the new metadata shape for at least one
   representative event per category (a JSON-decode-and-check-keys test is
   sufficient — no need to test every field of every event exhaustively).
5. No migration needed — `audit_log.metadata` is already a flexible JSON column
   per the append-only audit log design in `AGENTS.md`.
