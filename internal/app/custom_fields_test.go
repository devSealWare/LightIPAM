package app

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseCustomFieldValues(t *testing.T) {
	form := url.Values{}
	form.Set("name", "NAS")                 // a normal entity field, ignored
	form.Set("cf_abc123", "  IT dept  ")    // trimmed on write, raw here
	form.Set("cf_def456", "")               // blank: a clear
	form.Set("cf_", "orphan")               // no id: ignored
	form.Set("csrf_token", "t")             // ignored
	form.Set("description", "cf_ in value") // value containing prefix, key has no prefix

	r := httptest.NewRequest("POST", "/devices", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatalf("parse form: %v", err)
	}

	values := parseCustomFieldValues(r)
	if len(values) != 2 {
		t.Fatalf("expected 2 custom field values, got %d: %v", len(values), values)
	}
	if got, ok := values["abc123"]; !ok || got != "  IT dept  " {
		t.Errorf("abc123 = %q, ok=%v; want raw (untrimmed) value", got, ok)
	}
	if got, ok := values["def456"]; !ok || got != "" {
		t.Errorf("def456 = %q, ok=%v; want present and empty (a clear)", got, ok)
	}
	if _, ok := values[""]; ok {
		t.Error("an empty field id should be ignored")
	}
	if _, ok := values["name"]; ok {
		t.Error("non-prefixed fields should be ignored")
	}
}

func TestEntityTypeLabelFor(t *testing.T) {
	cases := map[string]string{
		"subnet":     "Subnet",
		"ip_address": "Address",
		"device":     "Device",
		"unknown":    "unknown",
	}
	for in, want := range cases {
		if got := entityTypeLabelFor(in); got != want {
			t.Errorf("entityTypeLabelFor(%q) = %q, want %q", in, got, want)
		}
	}
}
