package main

import (
	"reflect"
	"testing"
)

func TestParseFields(t *testing.T) {
	strFields := []string{"cidr", "name", "site_id", "description"}
	intFields := []string{"vlan"}

	t.Run("create includes set fields with types", func(t *testing.T) {
		body, err := parseFields("subnets create", []string{"--cidr", "10.0.0.0/24", "--name", "Core", "--vlan", "100"}, strFields, intFields)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := map[string]any{"cidr": "10.0.0.0/24", "name": "Core", "vlan": 100}
		if !reflect.DeepEqual(body, want) {
			t.Fatalf("body = %#v, want %#v", body, want)
		}
	})

	t.Run("update is partial — only set flags", func(t *testing.T) {
		body, err := parseFields("subnets update", []string{"--name", "Renamed"}, strFields, intFields)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(body, map[string]any{"name": "Renamed"}) {
			t.Fatalf("body = %#v, want only name", body)
		}
	})

	t.Run("no flags is an error", func(t *testing.T) {
		if _, err := parseFields("subnets create", nil, strFields, intFields); err == nil {
			t.Fatal("expected an error when no field flags are set")
		}
	})

	t.Run("unknown flag is an error", func(t *testing.T) {
		if _, err := parseFields("subnets create", []string{"--bogus", "x"}, strFields, intFields); err == nil {
			t.Fatal("expected an error for an unknown flag")
		}
	})
}

func TestAPIErrorMessage(t *testing.T) {
	if got := apiErrorMessage([]byte(`{"error":"nope"}`)); got != "nope" {
		t.Fatalf("apiErrorMessage = %q", got)
	}
	if got := apiErrorMessage([]byte(`plain text`)); got != "plain text" {
		t.Fatalf("apiErrorMessage fallback = %q", got)
	}
}
