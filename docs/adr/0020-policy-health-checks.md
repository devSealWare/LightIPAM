# ADR 0020: Policy / Health Checks

## Status

Accepted.

## Context

Phases 1–5 made Light IPAM a credible system of record: manual IPAM, multi-source
discovery, and production hardening (roles, MFA, SSO, sealed secrets, backups). What
it lacked was a way to tell an operator *whether the data is healthy*. Problems
accumulate silently — a subnet imported from an old dump overlaps another, an
assigned address points at a host that was decommissioned months ago, a server
appears on the network running services that were never recorded in IPAM. Nothing
surfaced these; an operator had to notice them by hand.

This is the first slice of **Phase 6 (Advanced Automation)** and the
roadmap-recommended starting point: it is fully app-side, adds no new privilege or
scanner surface, and reuses data the app already holds. The project constraints are
unchanged — the web app stays unprivileged, the strict same-origin CSP is untouched
(this slice adds **no** client JS), store methods live in `internal/store`, handlers
in `internal/app`, settings follow the runtime-editable `app_settings` pattern, and
mutations are audited.

## Decision

A read-only **Policy / Health** view (`GET /policy`, sidebar under *System*) that runs
hygiene checks on demand against the managed IPAM data and lists findings grouped by
check, each ranked by severity (critical / warning / info) and linked to the offending
record. The view is visible to **any** signed-in user (including a viewer); it changes
nothing, so it carries no CSRF token or audit entry. Tuning the checks is admin-only.

### Checks

- **Overlapping subnets** (critical). Pairwise CIDR overlap/containment over
  `subnets.cidr`. The create and CSV-import paths already reject an overlapping subnet
  (`cidr && $1`), so in normal operation this finds nothing — it is an **invariant
  verifier** that catches space introduced out of band (a restored older dump, a direct
  DB edit), which is exactly when a silent overlap is most dangerous.
- **Stale records** (warning; never-seen → info, opt-in). Managed addresses in an
  in-use state (`assigned`/`reserved`) and devices whose most recent `last_seen_at`
  (for a device, the max across its linked addresses) is older than a configurable
  threshold (default 30 days). A record a scan has **never** confirmed is a lower-
  severity *info* finding and only when the operator opts in — off by default so a
  manual-only deployment that never runs discovery is not flooded. `available` and
  `deprecated` addresses are excluded by design (they are not expected to be seen), and
  a device with no address is skipped (nothing to be seen). No schema change: device
  staleness is **derived** from the existing `ip_addresses.last_seen_at` rather than
  adding a column to `devices`.
- **Unmanaged & conflicting services** (conflict → critical, unmanaged-with-services →
  warning). Reuses the **existing reconciliation classification** stored on
  `scan_discoveries` (`reconcile_status` new/match/conflict, ADR 0007): a pending
  discovery in `conflict` surfaces its stored conflict note as critical; a pending
  `new` discovery running one or more services is a warning ("a host is on the network
  running services but is not in IPAM"). A pending `new` discovery with no services is
  ignored — it is just an un-imported ping and already lives in the review queue.

### Pure, unit-tested decision functions

Following the project pattern (`evaluateLockout`, `parseBulkRequest`,
`parseSecuritySettingsForm`), all the logic is pure functions over plain snapshot
structs, tested without a DB or socket (`internal/app/policy_test.go`):

- `evaluateOverlaps([]store.PolicySubnet) []store.PolicyFinding` (+ `cidrsOverlap`).
- `evaluateStaleRecords([]store.PolicyRecord, PolicySettings, now) []store.PolicyFinding`.
- `evaluateUnmanagedServices([]store.PolicyDiscoveryRecord) []store.PolicyFinding`.
- `summarizeFindings([]store.PolicyFinding) store.PolicySummary`.
- `parsePolicySettingsForm(url.Values) (PolicySettings, error)`.

A thin store query layer (`internal/store/policy.go`) feeds them the snapshots
(`PolicySubnets`, `PolicyAddressRecords`, `PolicyDeviceRecords`,
`PolicyDiscoveryRecords`). The shared result types (`PolicyFinding`,
`PolicyFindingGroup`, `PolicySummary`, and the snapshot structs) live in **store** — not
app — so the `ui` templates can render them without an `app → ui → app` import cycle,
the same arrangement ADR 0016 used for `ImportResult`. `app.computePolicy` runs only the
enabled checks (a disabled check fetches nothing) and returns the grouped findings plus a
severity summary; it is shared by the `/policy` page and the dashboard widget.

### Runtime-editable settings (Policy tab)

A new **Policy** tab on the Settings page (admin-only) toggles each check on/off and
sets the stale threshold (in days) and the include-never-seen flag, following the exact
Security-tab pattern: a pure `parsePolicySettingsForm` validator, values persisted in
`app_settings`, the typed `PolicySettings` cached behind the existing `settingsMu` and
refreshed on save, and an audited `settings.policy.updated` event. Env seeds only the
boot default for the threshold (`POLICY_STALE_AFTER`, default `720h`); a stored value
overrides it, and a missing/invalid value falls back to the default so the table can
never disable a check unintentionally or set a zero threshold. The stale/aging idea that
`docs/SETTINGS.md` had tentatively placed under a future *Discovery* tab now lives here.

### Dashboard widget

A "Policy & health" card on the dashboard shows the finding count (colored by the
highest severity present) and links to `/policy`, mirroring how the review-queue and
scan-status widgets were wired to live data. The dashboard computes the summary through
the same `computePolicy` helper.

## Consequences

- An operator gets a single place to see data-hygiene problems — overlaps, stale
  records, unmanaged/conflicting services — computed on demand, with each finding
  linking straight to the record to fix.
- No migration, no new dependency, no client JS, no new privilege. It reuses existing
  tables (`subnets`, `ip_addresses`, `scan_discoveries`), the `app_settings` store
  (migration 13), and the discovery reconciliation already computed at scan time.
- The checks are advisory and read-only; nothing is auto-remediated. Severities and the
  stale threshold are tunable so the signal-to-noise ratio fits the deployment.
- Findings are computed per request (and on each dashboard load). At small-business
  scale the snapshot queries are cheap; a very large deployment could later cache the
  result or move computation to the scheduler. Documented as the known scaling trade-off.
- The overlap check is effectively an invariant verifier given the create/import guards;
  it is kept because it is cheap and is the only thing that would catch an overlap
  introduced out of band.
- This sets the template for the remaining Phase 6 slices (scheduled scan windows,
  change webhooks, NetBox import/export): pure decision functions, a thin store layer,
  the runtime-editable settings pattern, and full server-side rendering.
