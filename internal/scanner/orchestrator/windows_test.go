package orchestrator

import (
	"testing"
	"time"

	// Embed the zone DB so LoadLocation works regardless of the test host, matching
	// the app binary (cmd/server imports it for the same reason).
	_ "time/tzdata"

	"github.com/devSealWare/LightIPAM/internal/store"
)

func intPtr(v int) *int { return &v }

// at builds a UTC time on a known weekday. 2024-01-01 was a Monday, so adding
// (weekday-1) days lands on the requested weekday for Mon..Sun.
func at(weekday time.Weekday, hour, min int, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	// time.Weekday: Sunday=0..Saturday=6. 2024-01-07 is a Sunday.
	base := time.Date(2024, 1, 7, 0, 0, 0, 0, loc) // Sunday
	return base.AddDate(0, 0, int(weekday)).Add(time.Duration(hour)*time.Hour + time.Duration(min)*time.Minute)
}

func daySet(days ...time.Weekday) map[time.Weekday]bool {
	m := make(map[time.Weekday]bool, len(days))
	for _, d := range days {
		m[d] = true
	}
	return m
}

func TestWindowAllows(t *testing.T) {
	weekdays := daySet(time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday)

	cases := []struct {
		name string
		w    scanWindow
		now  time.Time
		want bool
	}{
		// Empty window = pre-window behaviour: always allowed.
		{"empty window allowed midday", scanWindow{startMin: -1, endMin: -1}, at(time.Wednesday, 12, 0, nil), true},
		{"empty window allowed midnight", scanWindow{startMin: -1, endMin: -1}, at(time.Sunday, 0, 0, nil), true},

		// Time-only, no wrap: 01:00–05:00, half-open [start,end).
		{"before start out", scanWindow{startMin: 60, endMin: 300}, at(time.Monday, 0, 59, nil), false},
		{"at start in", scanWindow{startMin: 60, endMin: 300}, at(time.Monday, 1, 0, nil), true},
		{"inside in", scanWindow{startMin: 60, endMin: 300}, at(time.Monday, 3, 0, nil), true},
		{"just before end in", scanWindow{startMin: 60, endMin: 300}, at(time.Monday, 4, 59, nil), true},
		{"at end out", scanWindow{startMin: 60, endMin: 300}, at(time.Monday, 5, 0, nil), false},
		{"after end out", scanWindow{startMin: 60, endMin: 300}, at(time.Monday, 6, 0, nil), false},

		// Wrap past midnight: 22:00–06:00.
		{"wrap evening in", scanWindow{startMin: 22 * 60, endMin: 6 * 60}, at(time.Monday, 23, 0, nil), true},
		{"wrap at start in", scanWindow{startMin: 22 * 60, endMin: 6 * 60}, at(time.Monday, 22, 0, nil), true},
		{"wrap before start out", scanWindow{startMin: 22 * 60, endMin: 6 * 60}, at(time.Monday, 21, 59, nil), false},
		{"wrap early morning in", scanWindow{startMin: 22 * 60, endMin: 6 * 60}, at(time.Monday, 2, 0, nil), true},
		{"wrap at end out", scanWindow{startMin: 22 * 60, endMin: 6 * 60}, at(time.Monday, 6, 0, nil), false},
		{"wrap midday out", scanWindow{startMin: 22 * 60, endMin: 6 * 60}, at(time.Monday, 12, 0, nil), false},

		// start == end: treated as the whole day, never empty.
		{"equal bounds whole day midnight", scanWindow{startMin: 120, endMin: 120}, at(time.Monday, 0, 0, nil), true},
		{"equal bounds whole day midday", scanWindow{startMin: 120, endMin: 120}, at(time.Monday, 14, 30, nil), true},

		// Days only, no time restriction.
		{"day in set", scanWindow{startMin: -1, endMin: -1, days: weekdays}, at(time.Wednesday, 3, 0, nil), true},
		{"day not in set", scanWindow{startMin: -1, endMin: -1, days: weekdays}, at(time.Sunday, 3, 0, nil), false},

		// Combined day + time.
		{"weekday inside time in", scanWindow{startMin: 60, endMin: 300, days: weekdays}, at(time.Wednesday, 3, 0, nil), true},
		{"weekday outside time out", scanWindow{startMin: 60, endMin: 300, days: weekdays}, at(time.Wednesday, 6, 0, nil), false},
		{"weekend inside time out", scanWindow{startMin: 60, endMin: 300, days: weekdays}, at(time.Sunday, 3, 0, nil), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowAllows(tc.w, tc.now); got != tc.want {
				t.Fatalf("windowAllows = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWindowAllowsTimezone proves the comparison is done in the window's zone, not
// the now value's zone.
func TestWindowAllowsTimezone(t *testing.T) {
	loc := time.FixedZone("UTC-5", -5*3600)
	w := scanWindow{startMin: 60, endMin: 300, loc: loc} // 01:00–05:00 local

	// 06:00 UTC == 01:00 in UTC-5 → at start, inside.
	atStart := time.Date(2024, 1, 8, 6, 0, 0, 0, time.UTC)
	if !windowAllows(w, atStart) {
		t.Fatalf("expected 06:00Z (01:00 local) inside the window")
	}
	// 11:00 UTC == 06:00 in UTC-5 → after end, outside.
	afterEnd := time.Date(2024, 1, 8, 11, 0, 0, 0, time.UTC)
	if windowAllows(w, afterEnd) {
		t.Fatalf("expected 11:00Z (06:00 local) outside the window")
	}
}

func TestWindowFromSchedule(t *testing.T) {
	t.Run("no window", func(t *testing.T) {
		w := windowFromSchedule(store.ScanSchedule{})
		if w.startMin != -1 || w.endMin != -1 {
			t.Fatalf("expected unset bounds, got %d/%d", w.startMin, w.endMin)
		}
		if len(w.days) != 0 {
			t.Fatalf("expected no day restriction")
		}
		if w.loc != time.UTC {
			t.Fatalf("expected UTC, got %v", w.loc)
		}
	})

	t.Run("full window", func(t *testing.T) {
		w := windowFromSchedule(store.ScanSchedule{
			WindowStartMin: intPtr(60),
			WindowEndMin:   intPtr(300),
			WindowDays:     []int{1, 3, 7, -1}, // out-of-range entries are ignored
			WindowTZ:       "America/New_York",
		})
		if w.startMin != 60 || w.endMin != 300 {
			t.Fatalf("bounds = %d/%d", w.startMin, w.endMin)
		}
		if !w.days[time.Monday] || !w.days[time.Wednesday] {
			t.Fatalf("expected Mon+Wed in day set")
		}
		if w.days[time.Sunday] {
			t.Fatalf("did not expect out-of-range day 7 to map to Sunday")
		}
		if w.loc == nil || w.loc.String() != "America/New_York" {
			t.Fatalf("expected America/New_York, got %v", w.loc)
		}
	})

	t.Run("unknown tz falls back to UTC", func(t *testing.T) {
		w := windowFromSchedule(store.ScanSchedule{WindowTZ: "Nowhere/Imaginary"})
		if w.loc != time.UTC {
			t.Fatalf("expected UTC fallback, got %v", w.loc)
		}
	})
}
