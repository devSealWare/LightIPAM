package app

import (
	"net/url"
	"reflect"
	"testing"

	// Embed the zone DB so the timezone validation path resolves real IANA names
	// on any test host (the app binary imports it too).
	_ "time/tzdata"
)

func TestParseClockMinutes(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"00:00", 0, true},
		{"01:00", 60, true},
		{"05:30", 330, true},
		{"5:30", 330, true},
		{"23:59", 1439, true},
		{"24:00", 0, false},
		{"01:60", 0, false},
		{"1", 0, false},
		{"", 0, false},
		{"ab:cd", 0, false},
		{"-1:00", 0, false},
	}
	for _, tc := range cases {
		got, err := parseClockMinutes(tc.in)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("parseClockMinutes(%q) = %d, %v; want %d, nil", tc.in, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Errorf("parseClockMinutes(%q) = %d, nil; want error", tc.in, got)
		}
	}
}

func TestParseScheduleWindow(t *testing.T) {
	t.Run("empty is no window", func(t *testing.T) {
		start, end, days, tz, err := parseScheduleWindow(url.Values{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if start != nil || end != nil {
			t.Fatalf("expected no time restriction, got %v/%v", start, end)
		}
		if len(days) != 0 {
			t.Fatalf("expected no days, got %v", days)
		}
		if tz != "UTC" {
			t.Fatalf("expected default UTC, got %q", tz)
		}
	})

	t.Run("full window", func(t *testing.T) {
		form := url.Values{
			"window_start": {"01:00"},
			"window_end":   {"05:00"},
			"window_day":   {"5", "1", "3", "1"}, // unsorted, with a duplicate
			"window_tz":    {"America/New_York"},
		}
		start, end, days, tz, err := parseScheduleWindow(form)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if start == nil || *start != 60 || end == nil || *end != 300 {
			t.Fatalf("bounds = %v/%v, want 60/300", start, end)
		}
		if !reflect.DeepEqual(days, []int{1, 3, 5}) {
			t.Fatalf("days = %v, want [1 3 5] (deduped + sorted)", days)
		}
		if tz != "America/New_York" {
			t.Fatalf("tz = %q", tz)
		}
	})

	t.Run("days only, default tz", func(t *testing.T) {
		start, end, days, tz, err := parseScheduleWindow(url.Values{"window_day": {"0", "6"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if start != nil || end != nil {
			t.Fatalf("expected no time restriction")
		}
		if !reflect.DeepEqual(days, []int{0, 6}) {
			t.Fatalf("days = %v", days)
		}
		if tz != "UTC" {
			t.Fatalf("tz = %q", tz)
		}
	})

	errCases := []struct {
		name string
		form url.Values
	}{
		{"only start", url.Values{"window_start": {"01:00"}}},
		{"only end", url.Values{"window_end": {"05:00"}}},
		{"equal times", url.Values{"window_start": {"01:00"}, "window_end": {"01:00"}}},
		{"bad start", url.Values{"window_start": {"nope"}, "window_end": {"05:00"}}},
		{"bad end", url.Values{"window_start": {"01:00"}, "window_end": {"99:99"}}},
		{"bad day", url.Values{"window_day": {"7"}}},
		{"negative day", url.Values{"window_day": {"-1"}}},
		{"unknown tz", url.Values{"window_tz": {"Nowhere/Imaginary"}}},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, err := parseScheduleWindow(tc.form); err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
		})
	}
}
