# ADR 0028: Schedule scope validation + last-run outcome

## Status

Accepted.

## Context

A field deployment hit a confusing failure: scheduled scans simply stopped running. The
only evidence was a stream of `scan.schedule.rejected` audit entries, one per scheduler
tick, with the message:

```
job allowlist: parse allowed CIDR "192.168.5.0.24": netip.ParsePrefix("192.168.5.0.24"): no '/'
```

The operator had typed `192.168.5.0.24` (a `.` where the `/` belongs) in the schedule's
**Allowed IPv4 CIDRs** and **Targets** fields. Two problems compounded:

1. **No save-time validation.** `scheduleInputFromRequest` split the textareas with
   `parseList` but never checked that each entry was a valid IPv4 CIDR/target. The bad
   value was persisted. The *manual* scan form is implicitly protected — it dispatches
   synchronously through `TriggerManual` → `ValidateJobForAgent`, surfacing the error on
   the form — but a schedule only validates at dispatch time, inside the scheduler
   goroutine where no user is watching.
2. **Silent, repeating failure.** A schedule rejected at dispatch stays enabled, so it
   fails again on every tick. The outcome was invisible on the `/schedules` page; it lived
   only in the audit log.

A related, narrower gap: even a syntactically valid schedule could be rejected at dispatch
if its allowed CIDRs were not contained by the chosen **agent's** own allowlist — again,
only discoverable from the audit log.

Standing constraints apply: the web app stays unprivileged, no scanner surface, **no
client JS** under the strict CSP, and schedule mutations stay audited.

## Decision

Three layered changes — reject an invalid schedule at save time, and make the last run's
outcome visible on the schedule.

### 1. Syntax + self-containment validation at save time

`validateScanScope(allowed, targets)` (`internal/app/scans.go`, pure + unit-tested) checks
every allowed entry is a valid IPv4 CIDR and every target a valid IPv4 address or CIDR
contained by the allowlist — the same rules `scanner.ValidateJobTargets` enforces at
dispatch, but returned as friendly, field-specific messages ("Allowed CIDR
`"192.168.5.0.24"` is not valid — use a network and prefix length like `192.168.5.0/24`.").
It is wired into **both** `scanInputFromForm` (manual) and `scheduleInputFromRequest`
(schedule), so a typo is rejected inline on create and edit instead of being saved. The
rules use the same `netip` primitives as the scanner check, so they cannot drift.

### 2. Agent-allowlist containment at save time

`Service.ValidateScope(ctx, input)` (orchestrator) loads the chosen agent and runs
`scanner.ValidateAgentScope` (allowlist containment + job structure) **without** creating
or dispatching anything. The schedule handlers call it via `App.validateScheduleAgentScope`
after the syntax check, so a schedule whose allowed CIDRs fall outside the agent's
allowlist is rejected at save time. It deliberately uses `ValidateAgentScope` rather than
the full `ValidateJobForAgent`, so a schedule may target an agent still **pending**
approval — only the allowlist relationship is enforced here, not the agent's lifecycle
state (which can legitimately change before the schedule first fires).

### 3. Last-run outcome on the schedule

**Migration 21** adds `last_run_status`, `last_run_error`, and `last_job_id` to
`scan_schedules`. `Store.SetScanScheduleLastRun(id, status, error, jobID)` records the most
recent attempt's outcome and stamps `last_run_at`; it is separate from
`MarkScanScheduleRan` (which advances `next_run_at`), so a schedule fires and the eventual
result is written when the dispatch resolves. The orchestrator writes it from two places:

- `run()` calls `recordScheduleRun` — a no-op for a manually triggered job (no schedule
  id) — to set `running` when the job starts and the terminal `succeeded`/`failed` (with
  the headline error) and job id when it finishes.
- `runSchedule()` records `rejected` with the validation message when `enqueue` fails
  before any job is created (`last_job_id` empty).

The `/schedules` page gains a **Last run** column: a status badge (reusing the existing
`status_badge` partial, which already styles `succeeded`/`running`/`failed`/`rejected`),
linking to the scan detail when a job exists, with the failure reason shown beneath a
failed/rejected run. `ScanSchedule.LastRunFailed()` drives the flag. A never-run schedule
shows "Never run".

## Consequences

- The reported typo is now impossible to save: the schedule form rejects it inline with a
  corrective message, on both create and edit. The same friendlier message replaces the
  raw `netip` error on the manual scan form.
- An out-of-scope schedule (allowed CIDRs not within the agent's allowlist) is caught at
  save time instead of failing every tick.
- A schedule that *becomes* broken later (e.g. its agent's allowlist is narrowed, or the
  agent is removed) still fails at dispatch — but now that failure is visible on
  `/schedules` as a red **Last run** badge with the reason, not just an audit entry. This
  is the safety net the save-time checks cannot provide, since they run only on save.
- "Run now" on a schedule also updates its Last run (it executes the schedule), which is
  the intended, consistent meaning of the column.
- No new privilege, no new audit events (the existing `scan.schedule.rejected` /
  `scan.job.failed` events are unchanged); the change webhooks see exactly what they saw
  before.

## Alternatives considered

- **Validate only at dispatch and improve the audit message.** Rejected: the failure would
  still be silent on the page the operator actually manages schedules from, and an invalid
  schedule would still be saved.
- **Disable a schedule automatically after N consecutive rejections.** Rejected for now:
  auto-disabling hides the problem and could silently stop a schedule the operator expects
  to recover (e.g. an agent briefly offline). Surfacing the last failure lets the operator
  decide. A future increment could add an opt-in auto-disable.
- **Reuse `ValidateJobForAgent` (which also requires the agent be active) for save-time
  validation.** Rejected: it would forbid scheduling against a not-yet-approved agent,
  which is a legitimate setup order. `ValidateAgentScope` checks only what's stable at save
  time.

## Implementation

- `internal/db/migrations.go`: migration 21 (three columns on `scan_schedules`).
- `internal/store/scans.go`: `ScanSchedule.LastRunStatus/LastRunError/LastJobID`,
  `SetScanScheduleLastRun`, `LastRunFailed`; columns threaded through Get/List/ListDue.
- `internal/scanner/orchestrator/orchestrator.go`: `ValidateScope`, `recordScheduleRun`,
  the `run`/`runSchedule` wiring.
- `internal/app/scans.go`: `validateScanScope` (+ `validateScanTarget`,
  `prefixWithinAny`), `validateScheduleAgentScope`, wired into the scan + schedule forms.
- `internal/ui/templates/schedules.html`: the Last run column.
- Tests: `internal/app/scans_test.go` (`TestValidateScanScope`),
  `internal/store/scans_test.go` (`TestScanScheduleLastRunFailed`), and the failed-run
  fixture in `internal/ui/ui_test.go`.
