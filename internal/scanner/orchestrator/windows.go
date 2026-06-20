package orchestrator

import (
	"time"

	"github.com/devSealWare/LightIPAM/internal/store"
)

// scanWindow is the resolved form of a schedule's allowed firing window, ready
// for the pure windowAllows decision. It is built from a store.ScanSchedule by
// windowFromSchedule.
type scanWindow struct {
	startMin int                   // minutes since midnight in loc; -1 = no time restriction
	endMin   int                   // minutes since midnight in loc; -1 = no time restriction
	days     map[time.Weekday]bool // allowed weekdays; empty = any day
	loc      *time.Location        // timezone the bounds/days are read in; nil = UTC
}

// windowAllows reports whether now falls inside the schedule's window. The
// decision is pure (it depends only on its arguments) so it is unit-tested
// without a DB or a real clock.
//
// Semantics, all chosen so an all-empty window reproduces the pre-window
// behaviour (always allowed):
//   - No time restriction (startMin or endMin < 0): any time of day is allowed.
//   - No day restriction (empty days): any weekday is allowed.
//   - The time-of-day comparison is half-open [start, end): a tick exactly at
//     start is inside, a tick exactly at end is outside.
//   - start == end is treated as the whole day (a degenerate, always-in range),
//     never an empty one.
//   - A window whose start is after its end wraps past midnight (e.g. 22:00–
//     06:00) and is inside when now is at/after start OR before end.
//   - The weekday filter is evaluated against now's weekday in loc (the current
//     local day), so for a wrap-around window the tail after midnight belongs to
//     the new day — documented in ADR 0021.
func windowAllows(w scanWindow, now time.Time) bool {
	if w.loc != nil {
		now = now.In(w.loc)
	}
	if len(w.days) > 0 && !w.days[now.Weekday()] {
		return false
	}
	if w.startMin < 0 || w.endMin < 0 {
		return true
	}
	cur := now.Hour()*60 + now.Minute()
	switch {
	case w.startMin == w.endMin:
		return true
	case w.startMin < w.endMin:
		return cur >= w.startMin && cur < w.endMin
	default: // wraps past midnight
		return cur >= w.startMin || cur < w.endMin
	}
}

// windowFromSchedule resolves a stored schedule into a scanWindow. The timezone
// is loaded from the schedule's IANA name (embedded tzdata guarantees the lookup
// succeeds in any container); an empty or unknown zone falls back to UTC so a bad
// value never blocks scans. Nil minute bounds become -1 (no time restriction).
func windowFromSchedule(s store.ScanSchedule) scanWindow {
	w := scanWindow{startMin: -1, endMin: -1}
	if s.WindowStartMin != nil {
		w.startMin = *s.WindowStartMin
	}
	if s.WindowEndMin != nil {
		w.endMin = *s.WindowEndMin
	}
	if len(s.WindowDays) > 0 {
		w.days = make(map[time.Weekday]bool, len(s.WindowDays))
		for _, d := range s.WindowDays {
			if d >= 0 && d <= 6 {
				w.days[time.Weekday(d)] = true
			}
		}
	}
	loc := time.UTC
	if name := s.WindowTZ; name != "" && name != "UTC" {
		if l, err := time.LoadLocation(name); err == nil {
			loc = l
		}
	}
	w.loc = loc
	return w
}
