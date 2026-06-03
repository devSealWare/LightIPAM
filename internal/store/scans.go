package store

import (
	"context"
	"fmt"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
)

// ScanAgent is a registered scanner agent the app can dispatch jobs to.
type ScanAgent struct {
	ID                 string
	Name               string
	SiteID             string
	EndpointURL        string
	CertificateSubject string
	AllowedCIDRs       []string
	Status             string
	AutoImport         bool
	Version            string
	LastSeenAt         *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// ScanAgentInput holds editable agent fields.
type ScanAgentInput struct {
	Name               string
	SiteID             string
	EndpointURL        string
	CertificateSubject string
	AllowedCIDRs       []string
	Status             string
	AutoImport         bool
}

// ScanJob is a single dispatched (or queued) scan.
type ScanJob struct {
	ID              string
	AgentID         string
	AgentName       string
	ScheduleID      string
	RequestedBy     string
	RequestedByName string
	ScanType        string
	Mode            string
	AllowedCIDRs    []string
	Targets         []string
	TimeoutSeconds  int
	Status          string
	Error           string
	Result          string
	StartedAt       *time.Time
	FinishedAt      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ScanJobInput holds the fields needed to enqueue a job.
type ScanJobInput struct {
	AgentID        string
	ScheduleID     *string
	RequestedBy    *string
	ScanType       string
	Mode           string
	AllowedCIDRs   []string
	Targets        []string
	TimeoutSeconds int
}

// ScanJobResult captures the terminal state of a dispatched job.
type ScanJobResult struct {
	Status     string
	Error      string
	Result     string
	StartedAt  *time.Time
	FinishedAt *time.Time
}

// ScanSchedule is a recurring scan configuration.
type ScanSchedule struct {
	ID              string
	Name            string
	AgentID         string
	AgentName       string
	ScanType        string
	Mode            string
	AllowedCIDRs    []string
	Targets         []string
	TimeoutSeconds  int
	IntervalSeconds int
	Enabled         bool
	LastRunAt       *time.Time
	NextRunAt       time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ScanScheduleInput holds editable schedule fields.
type ScanScheduleInput struct {
	Name            string
	AgentID         string
	ScanType        string
	Mode            string
	AllowedCIDRs    []string
	Targets         []string
	TimeoutSeconds  int
	IntervalSeconds int
	Enabled         bool
}

// --- Agents ---

func (s *Store) CreateScanAgent(ctx context.Context, input ScanAgentInput) (ScanAgent, error) {
	id, err := auth.RandomToken(12)
	if err != nil {
		return ScanAgent{}, err
	}
	status := input.Status
	if status == "" {
		status = "pending"
	}
	var siteID *string
	if input.SiteID != "" {
		siteID = &input.SiteID
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO scan_agents (id, name, site_id, endpoint_url, certificate_subject, allowed_cidrs, status, auto_import)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, input.Name, siteID, input.EndpointURL, input.CertificateSubject, input.AllowedCIDRs, status, input.AutoImport); err != nil {
		return ScanAgent{}, fmt.Errorf("create scan agent: %w", err)
	}
	return s.GetScanAgent(ctx, id)
}

func (s *Store) UpdateScanAgent(ctx context.Context, id string, input ScanAgentInput) (ScanAgent, error) {
	var siteID *string
	if input.SiteID != "" {
		siteID = &input.SiteID
	}
	tag, err := s.db.Exec(ctx, `
UPDATE scan_agents
SET name = $2, site_id = $3, endpoint_url = $4, certificate_subject = $5, allowed_cidrs = $6, status = $7, auto_import = $8, updated_at = now()
WHERE id = $1`,
		id, input.Name, siteID, input.EndpointURL, input.CertificateSubject, input.AllowedCIDRs, input.Status, input.AutoImport)
	if err != nil {
		return ScanAgent{}, fmt.Errorf("update scan agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ScanAgent{}, ErrNotFound
	}
	return s.GetScanAgent(ctx, id)
}

func (s *Store) GetScanAgent(ctx context.Context, id string) (ScanAgent, error) {
	var a ScanAgent
	var siteID *string
	if err := s.db.QueryRow(ctx, `
SELECT id, name, COALESCE(site_id, ''), endpoint_url, certificate_subject, allowed_cidrs, status, auto_import, version, last_seen_at, created_at, updated_at
FROM scan_agents WHERE id = $1`, id).Scan(
		&a.ID, &a.Name, &siteID, &a.EndpointURL, &a.CertificateSubject, &a.AllowedCIDRs, &a.Status, &a.AutoImport, &a.Version, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return ScanAgent{}, ErrNotFound
		}
		return ScanAgent{}, fmt.Errorf("get scan agent: %w", err)
	}
	if siteID != nil {
		a.SiteID = *siteID
	}
	return a, nil
}

func (s *Store) ListScanAgents(ctx context.Context) ([]ScanAgent, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, name, COALESCE(site_id, ''), endpoint_url, certificate_subject, allowed_cidrs, status, auto_import, version, last_seen_at, created_at, updated_at
FROM scan_agents ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list scan agents: %w", err)
	}
	defer rows.Close()

	var agents []ScanAgent
	for rows.Next() {
		var a ScanAgent
		var siteID *string
		if err := rows.Scan(&a.ID, &a.Name, &siteID, &a.EndpointURL, &a.CertificateSubject, &a.AllowedCIDRs, &a.Status, &a.AutoImport, &a.Version, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan scan agent: %w", err)
		}
		if siteID != nil {
			a.SiteID = *siteID
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

func (s *Store) DeleteScanAgent(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM scan_agents WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete scan agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetScanAgentByEndpoint looks up an agent by its endpoint URL.
func (s *Store) GetScanAgentByEndpoint(ctx context.Context, endpointURL string) (ScanAgent, error) {
	var id string
	if err := s.db.QueryRow(ctx, "SELECT id FROM scan_agents WHERE endpoint_url = $1 LIMIT 1", endpointURL).Scan(&id); err != nil {
		if err == pgx.ErrNoRows {
			return ScanAgent{}, ErrNotFound
		}
		return ScanAgent{}, fmt.Errorf("get scan agent by endpoint: %w", err)
	}
	return s.GetScanAgent(ctx, id)
}

// EnrollDiscoveredAgent registers an agent the app pulled from its /register
// endpoint. If an agent already exists for the endpoint it is left untouched
// (so operator edits to status/allowlist are preserved) and returned with
// created=false; otherwise a new pending agent is created.
func (s *Store) EnrollDiscoveredAgent(ctx context.Context, endpointURL string, input ScanAgentInput) (ScanAgent, bool, error) {
	existing, err := s.GetScanAgentByEndpoint(ctx, endpointURL)
	if err == nil {
		return existing, false, nil
	}
	if err != ErrNotFound {
		return ScanAgent{}, false, err
	}
	input.EndpointURL = endpointURL
	input.Status = string(scanAgentPending)
	agent, err := s.CreateScanAgent(ctx, input)
	if err != nil {
		return ScanAgent{}, false, err
	}
	return agent, true, nil
}

const scanAgentPending = "pending"

// SetScanAgentStatus transitions an agent's lifecycle status (e.g. approving a
// pending agent by setting it active).
func (s *Store) SetScanAgentStatus(ctx context.Context, id, status string) error {
	tag, err := s.db.Exec(ctx, "UPDATE scan_agents SET status = $2, updated_at = now() WHERE id = $1", id, status)
	if err != nil {
		return fmt.Errorf("set scan agent status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchScanAgent records a successful contact and the agent's reported version.
func (s *Store) TouchScanAgent(ctx context.Context, id, version string) error {
	if _, err := s.db.Exec(ctx, `
UPDATE scan_agents SET last_seen_at = now(), version = COALESCE(NULLIF($2, ''), version), updated_at = now()
WHERE id = $1`, id, version); err != nil {
		return fmt.Errorf("touch scan agent: %w", err)
	}
	return nil
}

// --- Jobs ---

func (s *Store) CreateScanJob(ctx context.Context, input ScanJobInput) (ScanJob, error) {
	id, err := auth.RandomToken(12)
	if err != nil {
		return ScanJob{}, err
	}
	timeout := input.TimeoutSeconds
	if timeout <= 0 {
		timeout = 60
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO scan_jobs (id, agent_id, schedule_id, requested_by, scan_type, mode, allowed_cidrs, targets, timeout_seconds, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'queued')`,
		id, input.AgentID, input.ScheduleID, input.RequestedBy, input.ScanType, input.Mode, input.AllowedCIDRs, input.Targets, timeout); err != nil {
		return ScanJob{}, fmt.Errorf("create scan job: %w", err)
	}
	return s.GetScanJob(ctx, id)
}

func (s *Store) GetScanJob(ctx context.Context, id string) (ScanJob, error) {
	var j ScanJob
	var result *string
	if err := s.db.QueryRow(ctx, `
SELECT j.id, j.agent_id, COALESCE(a.name, ''), COALESCE(j.schedule_id, ''), COALESCE(j.requested_by, ''), COALESCE(u.display_name, ''),
	j.scan_type, j.mode, j.allowed_cidrs, j.targets, j.timeout_seconds, j.status, j.error, j.result::text, j.started_at, j.finished_at, j.created_at, j.updated_at
FROM scan_jobs j
LEFT JOIN scan_agents a ON a.id = j.agent_id
LEFT JOIN users u ON u.id = j.requested_by
WHERE j.id = $1`, id).Scan(
		&j.ID, &j.AgentID, &j.AgentName, &j.ScheduleID, &j.RequestedBy, &j.RequestedByName,
		&j.ScanType, &j.Mode, &j.AllowedCIDRs, &j.Targets, &j.TimeoutSeconds, &j.Status, &j.Error, &result, &j.StartedAt, &j.FinishedAt, &j.CreatedAt, &j.UpdatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return ScanJob{}, ErrNotFound
		}
		return ScanJob{}, fmt.Errorf("get scan job: %w", err)
	}
	if result != nil {
		j.Result = *result
	}
	return j, nil
}

func (s *Store) ListScanJobs(ctx context.Context, limit int) ([]ScanJob, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(ctx, `
SELECT j.id, j.agent_id, COALESCE(a.name, ''), COALESCE(j.schedule_id, ''), COALESCE(j.requested_by, ''), COALESCE(u.display_name, ''),
	j.scan_type, j.mode, j.allowed_cidrs, j.targets, j.timeout_seconds, j.status, j.error, j.started_at, j.finished_at, j.created_at, j.updated_at
FROM scan_jobs j
LEFT JOIN scan_agents a ON a.id = j.agent_id
LEFT JOIN users u ON u.id = j.requested_by
ORDER BY j.created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list scan jobs: %w", err)
	}
	defer rows.Close()

	var jobs []ScanJob
	for rows.Next() {
		var j ScanJob
		if err := rows.Scan(
			&j.ID, &j.AgentID, &j.AgentName, &j.ScheduleID, &j.RequestedBy, &j.RequestedByName,
			&j.ScanType, &j.Mode, &j.AllowedCIDRs, &j.Targets, &j.TimeoutSeconds, &j.Status, &j.Error, &j.StartedAt, &j.FinishedAt, &j.CreatedAt, &j.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan scan job: %w", err)
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// UpdateScanJobResult records a terminal (or running) state transition.
func (s *Store) UpdateScanJobResult(ctx context.Context, id string, result ScanJobResult) error {
	var resultJSON *string
	if result.Result != "" {
		resultJSON = &result.Result
	}
	if _, err := s.db.Exec(ctx, `
UPDATE scan_jobs
SET status = $2, error = $3, result = $4::jsonb, started_at = COALESCE($5, started_at), finished_at = $6, updated_at = now()
WHERE id = $1`, id, result.Status, result.Error, resultJSON, result.StartedAt, result.FinishedAt); err != nil {
		return fmt.Errorf("update scan job result: %w", err)
	}
	return nil
}

// --- Schedules ---

func (s *Store) CreateScanSchedule(ctx context.Context, input ScanScheduleInput) (ScanSchedule, error) {
	id, err := auth.RandomToken(12)
	if err != nil {
		return ScanSchedule{}, err
	}
	nextRun := time.Now().Add(time.Duration(input.IntervalSeconds) * time.Second)
	if _, err := s.db.Exec(ctx, `
INSERT INTO scan_schedules (id, name, agent_id, scan_type, mode, allowed_cidrs, targets, timeout_seconds, interval_seconds, enabled, next_run_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		id, input.Name, input.AgentID, input.ScanType, input.Mode, input.AllowedCIDRs, input.Targets, input.TimeoutSeconds, input.IntervalSeconds, input.Enabled, nextRun); err != nil {
		return ScanSchedule{}, fmt.Errorf("create scan schedule: %w", err)
	}
	return s.GetScanSchedule(ctx, id)
}

func (s *Store) UpdateScanSchedule(ctx context.Context, id string, input ScanScheduleInput) (ScanSchedule, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE scan_schedules
SET name = $2, agent_id = $3, scan_type = $4, mode = $5, allowed_cidrs = $6, targets = $7,
	timeout_seconds = $8, interval_seconds = $9, enabled = $10, updated_at = now()
WHERE id = $1`,
		id, input.Name, input.AgentID, input.ScanType, input.Mode, input.AllowedCIDRs, input.Targets, input.TimeoutSeconds, input.IntervalSeconds, input.Enabled)
	if err != nil {
		return ScanSchedule{}, fmt.Errorf("update scan schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ScanSchedule{}, ErrNotFound
	}
	return s.GetScanSchedule(ctx, id)
}

func (s *Store) GetScanSchedule(ctx context.Context, id string) (ScanSchedule, error) {
	var sc ScanSchedule
	if err := s.db.QueryRow(ctx, `
SELECT sc.id, sc.name, sc.agent_id, COALESCE(a.name, ''), sc.scan_type, sc.mode, sc.allowed_cidrs, sc.targets,
	sc.timeout_seconds, sc.interval_seconds, sc.enabled, sc.last_run_at, sc.next_run_at, sc.created_at, sc.updated_at
FROM scan_schedules sc
LEFT JOIN scan_agents a ON a.id = sc.agent_id
WHERE sc.id = $1`, id).Scan(
		&sc.ID, &sc.Name, &sc.AgentID, &sc.AgentName, &sc.ScanType, &sc.Mode, &sc.AllowedCIDRs, &sc.Targets,
		&sc.TimeoutSeconds, &sc.IntervalSeconds, &sc.Enabled, &sc.LastRunAt, &sc.NextRunAt, &sc.CreatedAt, &sc.UpdatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return ScanSchedule{}, ErrNotFound
		}
		return ScanSchedule{}, fmt.Errorf("get scan schedule: %w", err)
	}
	return sc, nil
}

func (s *Store) ListScanSchedules(ctx context.Context) ([]ScanSchedule, error) {
	rows, err := s.db.Query(ctx, `
SELECT sc.id, sc.name, sc.agent_id, COALESCE(a.name, ''), sc.scan_type, sc.mode, sc.allowed_cidrs, sc.targets,
	sc.timeout_seconds, sc.interval_seconds, sc.enabled, sc.last_run_at, sc.next_run_at, sc.created_at, sc.updated_at
FROM scan_schedules sc
LEFT JOIN scan_agents a ON a.id = sc.agent_id
ORDER BY sc.name`)
	if err != nil {
		return nil, fmt.Errorf("list scan schedules: %w", err)
	}
	defer rows.Close()

	var schedules []ScanSchedule
	for rows.Next() {
		var sc ScanSchedule
		if err := rows.Scan(
			&sc.ID, &sc.Name, &sc.AgentID, &sc.AgentName, &sc.ScanType, &sc.Mode, &sc.AllowedCIDRs, &sc.Targets,
			&sc.TimeoutSeconds, &sc.IntervalSeconds, &sc.Enabled, &sc.LastRunAt, &sc.NextRunAt, &sc.CreatedAt, &sc.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan scan schedule: %w", err)
		}
		schedules = append(schedules, sc)
	}
	return schedules, rows.Err()
}

func (s *Store) DeleteScanSchedule(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM scan_schedules WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete scan schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListDueScanSchedules returns enabled schedules whose next_run_at has passed.
func (s *Store) ListDueScanSchedules(ctx context.Context) ([]ScanSchedule, error) {
	rows, err := s.db.Query(ctx, `
SELECT sc.id, sc.name, sc.agent_id, COALESCE(a.name, ''), sc.scan_type, sc.mode, sc.allowed_cidrs, sc.targets,
	sc.timeout_seconds, sc.interval_seconds, sc.enabled, sc.last_run_at, sc.next_run_at, sc.created_at, sc.updated_at
FROM scan_schedules sc
LEFT JOIN scan_agents a ON a.id = sc.agent_id
WHERE sc.enabled AND sc.next_run_at <= now()
ORDER BY sc.next_run_at`)
	if err != nil {
		return nil, fmt.Errorf("list due scan schedules: %w", err)
	}
	defer rows.Close()

	var schedules []ScanSchedule
	for rows.Next() {
		var sc ScanSchedule
		if err := rows.Scan(
			&sc.ID, &sc.Name, &sc.AgentID, &sc.AgentName, &sc.ScanType, &sc.Mode, &sc.AllowedCIDRs, &sc.Targets,
			&sc.TimeoutSeconds, &sc.IntervalSeconds, &sc.Enabled, &sc.LastRunAt, &sc.NextRunAt, &sc.CreatedAt, &sc.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan due scan schedule: %w", err)
		}
		schedules = append(schedules, sc)
	}
	return schedules, rows.Err()
}

// MarkScanScheduleRan advances a schedule's run timestamps after it fires.
func (s *Store) MarkScanScheduleRan(ctx context.Context, id string) error {
	if _, err := s.db.Exec(ctx, `
UPDATE scan_schedules
SET last_run_at = now(), next_run_at = now() + (interval_seconds * interval '1 second'), updated_at = now()
WHERE id = $1`, id); err != nil {
		return fmt.Errorf("mark scan schedule ran: %w", err)
	}
	return nil
}
