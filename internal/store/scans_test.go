package store

import "testing"

func TestFormatWeekdays(t *testing.T) {
	cases := []struct {
		name string
		in   []int
		want string
	}{
		{"empty", nil, ""},
		{"weekdays range", []int{1, 2, 3, 4, 5}, "Mon–Fri"},
		{"weekend pair", []int{0, 6}, "Sun, Sat"},
		{"adjacent pair stays listed", []int{5, 6}, "Fri, Sat"},
		{"scattered", []int{1, 3, 5}, "Mon, Wed, Fri"},
		{"three contiguous compress", []int{2, 3, 4}, "Tue–Thu"},
		{"unsorted with dupes", []int{5, 1, 3, 4, 2, 1}, "Mon–Fri"},
		{"out of range ignored", []int{1, 9, -2, 2, 3}, "Mon–Wed"},
		{"single", []int{3}, "Wed"},
	}
	for _, tc := range cases {
		if got := formatWeekdays(tc.in); got != tc.want {
			t.Errorf("formatWeekdays(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestScanScheduleWindowLabel(t *testing.T) {
	min := func(v int) *int { return &v }
	cases := []struct {
		name string
		s    ScanSchedule
		want string
	}{
		{"no window", ScanSchedule{}, "Any time"},
		{
			"days and time",
			ScanSchedule{WindowStartMin: min(60), WindowEndMin: min(300), WindowDays: []int{1, 2, 3, 4, 5}, WindowTZ: "UTC"},
			"Mon–Fri 01:00–05:00 UTC",
		},
		{
			"time only any day",
			ScanSchedule{WindowStartMin: min(1320), WindowEndMin: min(360), WindowTZ: "America/New_York"},
			"22:00–06:00 America/New_York",
		},
		{
			"days only any time",
			ScanSchedule{WindowDays: []int{6, 0}},
			"Sun, Sat",
		},
		{
			"empty tz defaults to UTC label",
			ScanSchedule{WindowStartMin: min(0), WindowEndMin: min(90)},
			"00:00–01:30 UTC",
		},
	}
	for _, tc := range cases {
		if got := tc.s.WindowLabel(); got != tc.want {
			t.Errorf("%s: WindowLabel() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestScanScheduleHasWindow(t *testing.T) {
	min := func(v int) *int { return &v }
	if (ScanSchedule{}).HasWindow() {
		t.Error("empty schedule should have no window")
	}
	if !(ScanSchedule{WindowDays: []int{1}}).HasWindow() {
		t.Error("day restriction should count as a window")
	}
	if !(ScanSchedule{WindowStartMin: min(0), WindowEndMin: min(60)}).HasWindow() {
		t.Error("time restriction should count as a window")
	}
}
