# ADR 0021: Scheduled Scan Windows

## Status

Accepted.

## Context

Light IPAM can run scans on a schedule: `scan_schedules` (migration 5) holds an
interval per enabled schedule, and the app's in-process ticker
(`orchestrator.StartScheduler` → `RunDueSchedules`) enqueues a job for every enabled
schedule whose `next_run_at` has passed. The cadence was interval-only — a schedule
set to "every hour" fired every hour, around the clock.

Operators want scans confined to a maintenance window: "scan the server VLAN every
30 minutes, but only 01:00–05:00 on weekdays". An active nmap sweep adds load and can
trip IDS alerts; a small business wants it to run overnight, not during business
hours. This is the second slice of **Phase 6 (Advanced Automation)** and follows the
slice-(a) Policy/Health template (ADR 0020): a pure, unit-tested decision function, a
thin store change, full server-side rendering, and no new privilege.

The project constraints are unchanged. The web app stays unprivileged — this slice
only changes **when** the existing in-process scheduler dispatches a job, adding no
socket, capability, or agent-side surface. The strict same-origin CSP is untouched
(no client JS; the form uses native `<input type="time">`, checkboxes, and a
`<datalist>`). Store methods live in `internal/store`, handlers in `internal/app`,
and the mutation is audited via the existing schedule create/update events.

## Decision

A schedule may carry an optional **window**: a time-of-day range plus a set of
weekdays, read in the schedule's own timezone. The window is an **additional gate**
layered on top of the interval cadence — the interval still decides when a run is
*due*; the window decides whether a due run may *fire*.

### Out-of-window behaviour: skip and re-check

When `RunDueSchedules` finds a due schedule whose current time is outside its window,
it **skips it that tick and does not advance `next_run_at`**. The schedule stays due,
so it fires on the next tick once the clock enters the window. This was chosen over
"advance `next_run_at` to the next window opening" because it is simpler, keeps
`RunDueSchedules` cheap (one in-memory check per due schedule, no next-opening
computation across wrap-around/empty-day/DST edge cases), and is self-correcting:
nothing is lost if the window definition changes between ticks. The cost — re-checking
a waiting schedule each tick — is negligible at the scheduler's scale (a handful of
schedules, a 30-second default tick).

### Timezone: per-schedule, evaluated with embedded tzdata

The window is interpreted in a **per-schedule IANA timezone** (`window_tz`, default
`UTC`), evaluated with `time.LoadLocation`. A maintenance window is inherently a
wall-clock, local concept ("01:00–05:00"), and a per-schedule zone is DST-correct
(the window tracks 01:00 local across the spring/autumn shift) — which a fixed
server-UTC interpretation is not. The app image is Alpine, which ships no
`/usr/share/zoneinfo`, so `cmd/server` imports `_ "time/tzdata"` to embed the zone
database in the binary; the lookup then works in any container with no OS package. An
empty or unrecognized zone falls back to UTC so a bad value never blocks scans.

### Storage: minutes-since-midnight integers (migration 18)

Migration 18 adds four columns to `scan_schedules`:

- `window_start_min integer` / `window_end_min integer` — minutes since midnight
  (0..1439), `NULL` meaning **no time-of-day restriction**. Stored as integers rather
  than Postgres `time` because the codebase uses no `pgtype`; an `*int` scans cleanly
  and the pure decision function compares plain ints.
- `window_days integer[] NOT NULL DEFAULT '{}'` — allowed weekdays, `0=Sunday..
  6=Saturday` to match `time.Weekday`; an empty array means **any day**.
- `window_tz text NOT NULL DEFAULT 'UTC'` — the IANA zone the bounds and days are read
  in.

All-unset (NULL bounds, empty days, UTC) = **no window = the previous always-allowed
behaviour**, so every existing schedule is unchanged after the migration.

### Pure, unit-tested decision function

`windowAllows(w scanWindow, now time.Time) bool` in
`internal/scanner/orchestrator/windows.go` is pure (depends only on its arguments) and
unit-tested without a DB or real clock, mirroring `evaluateLockout` /
`parseBulkRequest` / the slice-(a) policy checks. `windowFromSchedule` resolves a
`store.ScanSchedule` into the `scanWindow` (loading the zone, mapping nil bounds to
"unset"). The semantics, all chosen so an empty window reproduces today's behaviour:

- No time restriction (either bound unset) → any time of day allowed.
- No day restriction (empty set) → any weekday allowed.
- The time comparison is half-open `[start, end)`: a tick at `start` is inside, a tick
  at `end` is outside.
- `start == end` is the whole day (a degenerate always-in range), never empty.
- `start > end` **wraps past midnight** (e.g. 22:00–06:00): inside when now is
  at/after `start` **or** before `end`.
- The weekday filter is evaluated against **now's local weekday**. For a wrap-around
  window this means the after-midnight tail belongs to the new calendar day — e.g.
  `22:00–06:00 Mon–Fri` includes Friday 23:00 but not the Saturday 02:00 tail. This is
  unambiguous for the common no-wrap case (`01:00–05:00 Mon–Fri`) and avoids
  start-day-anchoring complexity; it is documented here as the accepted simplification.

### Form, display, and validation

The schedule form (`internal/ui/templates/schedule_form.html`) gains a "Run window
(optional)" section: two native `<input type="time">` fields, seven weekday
checkboxes (all named `window_day`, values 0–6), and a `window_tz` text input with a
`<datalist>` of common zones. It is fully server-rendered and works with JavaScript
disabled. A pure `parseScheduleWindow(url.Values)` validator (in `internal/app/scans.go`,
unit-tested) enforces that the start and end are supplied together (or both blank),
parses `HH:MM`, range-checks the weekday set, and validates the IANA zone — falling
back to errors surfaced inline on the form. `store.ScanSchedule.WindowLabel()` renders
the window for the schedules table ("Mon–Fri 01:00–05:00 UTC", "22:00–06:00
America/New_York", "Mon–Fri", or "Any time").

This is **per-schedule** configuration, not a Settings tab — `docs/SETTINGS.md` is
unchanged. The window rides on the existing audited `scan.schedule.created` /
`scan.schedule.updated` events; no new audit action is needed.

## Consequences

- An operator can confine a recurring scan to a maintenance window — a time-of-day
  range, a weekday set, or both — in the schedule's own timezone, without touching the
  agent or its privileges.
- Backward compatible: existing schedules get an empty window (NULL bounds, no days)
  and keep firing purely on interval. The migration is additive and idempotent.
- No new privilege, dependency, scanner surface, or client JS. The only build change is
  embedding `time/tzdata` (~450 KB) so zone lookups work on the Alpine image.
- The skip-and-recheck design keeps `RunDueSchedules` cheap and self-correcting at the
  cost of re-evaluating a waiting schedule each tick — acceptable at the scheduler's
  scale. A very large deployment could later switch to advancing `next_run_at` to the
  next opening; the pure `windowAllows` function would be reused unchanged.
- The wrap-around-plus-weekday "tail belongs to the new day" rule is a documented
  simplification; the common no-wrap window is unambiguous.
- Sets up the remaining Phase 6 slices to keep the same shape: a pure decision
  function, a thin store change, the runtime/per-record settings pattern, and
  server-side rendering.
