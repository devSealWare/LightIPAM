package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildAndParseName(t *testing.T) {
	when := time.Date(2026, 6, 19, 14, 30, 5, 0, time.UTC)
	name := buildName(when, 16)
	if name != "lightipam-20260619-143005-mig16.dump" {
		t.Fatalf("unexpected name %q", name)
	}
	gotTime, gotMig, err := parseName(name)
	if err != nil {
		t.Fatalf("parseName: %v", err)
	}
	if !gotTime.Equal(when) {
		t.Errorf("time round trip: got %v want %v", gotTime, when)
	}
	if gotMig != 16 {
		t.Errorf("migration: got %d want 16", gotMig)
	}
}

func TestParseNameRejectsTraversal(t *testing.T) {
	for _, bad := range []string{
		"../etc/passwd",
		"lightipam-2026-mig1.dump",
		"lightipam-20260619-143005-mig16.dump.bak",
		"evil.dump",
		"lightipam-20260619-143005-migX.dump",
		"/abs/lightipam-20260619-143005-mig1.dump",
	} {
		if _, _, err := parseName(bad); err == nil {
			t.Errorf("parseName(%q) should fail", bad)
		}
	}
}

func TestManagerDisabled(t *testing.T) {
	m := New("", "postgres://x")
	if m.Enabled() {
		t.Fatal("empty dir should be disabled")
	}
	if _, err := m.List(); err != ErrDisabled {
		t.Errorf("List on disabled: %v", err)
	}
	if _, err := m.Path("lightipam-20260619-143005-mig1.dump"); err != ErrDisabled {
		t.Errorf("Path on disabled: %v", err)
	}
}

func TestPathValidation(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, "postgres://x")
	if !m.Writable() {
		t.Fatal("temp dir should be writable")
	}
	good := "lightipam-20260619-143005-mig1.dump"
	path, err := m.Path(good)
	if err != nil {
		t.Fatalf("Path(good): %v", err)
	}
	if path != filepath.Join(dir, good) {
		t.Errorf("unexpected path %q", path)
	}
	if _, err := m.Path("../escape"); err != ErrInvalidName {
		t.Errorf("traversal name should be rejected, got %v", err)
	}
}

func TestListReadsDir(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, "postgres://x")
	// Two valid backups and one junk file.
	for _, n := range []string{
		"lightipam-20260619-143005-mig15.dump",
		"lightipam-20260620-090000-mig16.dump",
		"notes.txt",
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	list, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 backups, got %d", len(list))
	}
	// Newest first.
	if list[0].Migration != 16 {
		t.Errorf("expected newest (mig16) first, got mig%d", list[0].Migration)
	}
}
