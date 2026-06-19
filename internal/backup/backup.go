// Package backup creates and manages PostgreSQL logical backups (pg_dump custom
// format) for disaster recovery. The web app stays unprivileged: pg_dump is an
// ordinary database client over TCP — no raw sockets or elevated capabilities.
package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// namePattern is the strict backup filename form. It encodes the creation time
// and the schema-migration version, and doubles as the traversal guard for
// download/delete (only names matching this may be served).
var namePattern = regexp.MustCompile(`^lightipam-(\d{8}-\d{6})-mig(\d+)\.dump$`)

const nameTimeLayout = "20060102-150405"

// ErrDisabled is returned when no backup directory is configured.
var ErrDisabled = errors.New("backup: no backup directory configured")

// ErrInvalidName is returned for a filename that does not match the strict form.
var ErrInvalidName = errors.New("backup: invalid backup name")

// Backup describes one stored dump.
type Backup struct {
	Name      string
	Size      int64
	CreatedAt time.Time
	Migration int
}

// Manager creates and lists backups in a directory.
type Manager struct {
	dir           string
	databaseURL   string
	pgDumpPath    string
	pgRestorePath string
	now           func() time.Time
}

// New builds a Manager. An empty dir disables the feature (Enabled reports
// false and operations return ErrDisabled).
func New(dir, databaseURL string) *Manager {
	return &Manager{
		dir:           dir,
		databaseURL:   databaseURL,
		pgDumpPath:    "pg_dump",
		pgRestorePath: "pg_restore",
		now:           time.Now,
	}
}

// Enabled reports whether a backup directory is configured.
func (m *Manager) Enabled() bool { return m.dir != "" }

// Dir returns the configured backup directory (for display).
func (m *Manager) Dir() string { return m.dir }

// Writable reports whether the configured directory exists and can be written.
func (m *Manager) Writable() bool {
	if m.dir == "" {
		return false
	}
	probe := filepath.Join(m.dir, ".writable-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}

// buildName returns the canonical filename for a backup taken at t for the given
// migration version.
func buildName(t time.Time, migration int) string {
	return fmt.Sprintf("lightipam-%s-mig%d.dump", t.UTC().Format(nameTimeLayout), migration)
}

// parseName extracts the creation time and migration version from a backup
// filename, returning ErrInvalidName for anything that does not match.
func parseName(name string) (time.Time, int, error) {
	groups := namePattern.FindStringSubmatch(name)
	if groups == nil {
		return time.Time{}, 0, ErrInvalidName
	}
	t, err := time.Parse(nameTimeLayout, groups[1])
	if err != nil {
		return time.Time{}, 0, ErrInvalidName
	}
	migration, err := strconv.Atoi(groups[2])
	if err != nil {
		return time.Time{}, 0, ErrInvalidName
	}
	return t.UTC(), migration, nil
}

// Create runs pg_dump in custom format and returns the new backup's metadata.
func (m *Manager) Create(ctx context.Context, migration int) (Backup, error) {
	if !m.Enabled() {
		return Backup{}, ErrDisabled
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return Backup{}, fmt.Errorf("backup: ensure dir: %w", err)
	}
	name := buildName(m.now(), migration)
	full := filepath.Join(m.dir, name)
	tmp := full + ".partial"

	cmd := exec.CommandContext(ctx, m.pgDumpPath, "-Fc", "--no-owner", "--no-privileges", "-f", tmp, m.databaseURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmp)
		return Backup{}, fmt.Errorf("backup: pg_dump failed: %w: %s", err, string(out))
	}
	if err := os.Rename(tmp, full); err != nil {
		_ = os.Remove(tmp)
		return Backup{}, fmt.Errorf("backup: finalize: %w", err)
	}
	info, err := os.Stat(full)
	if err != nil {
		return Backup{}, fmt.Errorf("backup: stat: %w", err)
	}
	t, mig, _ := parseName(name)
	return Backup{Name: name, Size: info.Size(), CreatedAt: t, Migration: mig}, nil
}

// List returns the stored backups, newest first.
func (m *Manager) List() ([]Backup, error) {
	if !m.Enabled() {
		return nil, ErrDisabled
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("backup: read dir: %w", err)
	}
	var backups []Backup
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		t, mig, err := parseName(e.Name())
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, Backup{Name: e.Name(), Size: info.Size(), CreatedAt: t, Migration: mig})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt.After(backups[j].CreatedAt) })
	return backups, nil
}

// Path returns the validated absolute path for a backup name, rejecting any name
// that does not match the strict form (traversal guard).
func (m *Manager) Path(name string) (string, error) {
	if !m.Enabled() {
		return "", ErrDisabled
	}
	if _, _, err := parseName(name); err != nil {
		return "", err
	}
	return filepath.Join(m.dir, name), nil
}

// Delete removes a stored backup after validating its name.
func (m *Manager) Delete(name string) error {
	path, err := m.Path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("backup: delete: %w", err)
	}
	return nil
}
