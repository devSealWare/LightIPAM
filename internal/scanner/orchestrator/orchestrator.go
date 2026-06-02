// Package orchestrator is the app-side coordinator for scans. It validates and
// enqueues jobs, dispatches them to agents over mTLS (via a Dispatcher), records
// lifecycle transitions and audit entries, and runs due schedules on a ticker.
//
// It performs no scanning itself and adds no privileged behavior to the app.
package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/store"
)

// Dispatcher sends a job to an agent endpoint and returns the reported result.
type Dispatcher interface {
	Dispatch(ctx context.Context, endpointURL string, job scanner.ScanJob) (scanner.ScanResult, error)
	Enabled() bool
}

// Service coordinates scan jobs and schedules.
type Service struct {
	store      *store.Store
	dispatcher Dispatcher
	logger     *slog.Logger
}

// NewService builds a Service. dispatcher may be nil or disabled; jobs then fail
// cleanly with an explanatory error rather than panicking.
func NewService(st *store.Store, dispatcher Dispatcher, logger *slog.Logger) *Service {
	return &Service{store: st, dispatcher: dispatcher, logger: logger}
}

// DispatchEnabled reports whether the app can actually reach an agent. When
// false, jobs are still recorded but fail with a configuration error.
func (s *Service) DispatchEnabled() bool {
	return s.dispatcher != nil && s.dispatcher.Enabled()
}

// TriggerManual validates and enqueues a user-requested job, then dispatches it
// asynchronously. A validation/allowlist failure returns an error and creates no
// job row, so the caller can surface it inline.
func (s *Service) TriggerManual(ctx context.Context, input store.ScanJobInput) (store.ScanJob, error) {
	agent, err := s.store.GetScanAgent(ctx, input.AgentID)
	if err != nil {
		return store.ScanJob{}, err
	}
	return s.enqueue(ctx, agent, input, input.RequestedBy)
}

func (s *Service) enqueue(ctx context.Context, agent store.ScanAgent, input store.ScanJobInput, actor *string) (store.ScanJob, error) {
	if err := scanner.ValidateJobForAgent(scannerJob("preview", input), registrationFromAgent(agent)); err != nil {
		return store.ScanJob{}, err
	}
	job, err := s.store.CreateScanJob(ctx, input)
	if err != nil {
		return store.ScanJob{}, err
	}
	s.audit(ctx, actor, "scan.job.created", job.ID, job.Status)
	go s.run(context.Background(), agent, job, actor)
	return job, nil
}

// run dispatches a queued job and records its terminal state. It is meant to be
// called in its own goroutine.
func (s *Service) run(ctx context.Context, agent store.ScanAgent, job store.ScanJob, actor *string) {
	started := time.Now().UTC()
	if err := s.store.UpdateScanJobResult(ctx, job.ID, store.ScanJobResult{Status: "running", StartedAt: &started}); err != nil {
		s.logger.Error("mark scan job running", "job_id", job.ID, "error", err)
	}

	result := s.dispatch(ctx, agent, job, started)
	if err := s.store.UpdateScanJobResult(ctx, job.ID, result); err != nil {
		s.logger.Error("record scan job result", "job_id", job.ID, "error", err)
	}

	action := "scan.job.completed"
	if result.Status != "succeeded" {
		action = "scan.job.failed"
	} else if err := s.store.TouchScanAgent(ctx, agent.ID, ""); err != nil {
		s.logger.Error("touch scan agent", "agent_id", agent.ID, "error", err)
	}
	s.audit(ctx, actor, action, job.ID, result.Status)
}

func (s *Service) dispatch(ctx context.Context, agent store.ScanAgent, job store.ScanJob, started time.Time) store.ScanJobResult {
	finished := func() *time.Time { t := time.Now().UTC(); return &t }

	if s.dispatcher == nil || !s.dispatcher.Enabled() {
		return store.ScanJobResult{
			Status:     "failed",
			Error:      "scanner dispatch is not configured (set the app's mTLS client certificate)",
			StartedAt:  &started,
			FinishedAt: finished(),
		}
	}

	timeout := time.Duration(job.TimeoutSeconds)*time.Second + 10*time.Second
	dispatchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := s.dispatcher.Dispatch(dispatchCtx, agent.EndpointURL, scannerJobFromStore(job))
	if err != nil {
		return store.ScanJobResult{
			Status:     "failed",
			Error:      err.Error(),
			StartedAt:  &started,
			FinishedAt: finished(),
		}
	}

	out := store.ScanJobResult{
		Status:     string(result.Status),
		StartedAt:  &started,
		FinishedAt: finished(),
	}
	if encoded, err := json.Marshal(result); err == nil {
		out.Result = string(encoded)
	}
	if len(result.Errors) > 0 {
		out.Error = result.Errors[0].Message
	}
	if out.Status == "" {
		out.Status = "failed"
		out.Error = "agent returned no status"
	}
	return out
}

// RunDueSchedules enqueues a job for every enabled schedule whose next run has
// passed, advancing each schedule's timestamps.
func (s *Service) RunDueSchedules(ctx context.Context) {
	schedules, err := s.store.ListDueScanSchedules(ctx)
	if err != nil {
		s.logger.Error("list due scan schedules", "error", err)
		return
	}
	for _, schedule := range schedules {
		s.runSchedule(ctx, schedule)
		if err := s.store.MarkScanScheduleRan(ctx, schedule.ID); err != nil {
			s.logger.Error("mark scan schedule ran", "schedule_id", schedule.ID, "error", err)
		}
	}
}

func (s *Service) runSchedule(ctx context.Context, schedule store.ScanSchedule) {
	agent, err := s.store.GetScanAgent(ctx, schedule.AgentID)
	if err != nil {
		s.logger.Error("scan schedule agent missing", "schedule_id", schedule.ID, "error", err)
		return
	}
	scheduleID := schedule.ID
	input := store.ScanJobInput{
		AgentID:        schedule.AgentID,
		ScheduleID:     &scheduleID,
		ScanType:       schedule.ScanType,
		Mode:           schedule.Mode,
		AllowedCIDRs:   schedule.AllowedCIDRs,
		Targets:        schedule.Targets,
		TimeoutSeconds: schedule.TimeoutSeconds,
	}
	if _, err := s.enqueue(ctx, agent, input, nil); err != nil {
		s.logger.Warn("scheduled scan rejected", "schedule_id", schedule.ID, "error", err)
		s.audit(ctx, nil, "scan.schedule.rejected", schedule.ID, err.Error())
	}
}

// StartScheduler runs RunDueSchedules on an interval until ctx is cancelled.
func (s *Service) StartScheduler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.logger.Info("scan scheduler started", "interval", interval.String())
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("scan scheduler stopped")
			return
		case <-ticker.C:
			s.RunDueSchedules(ctx)
		}
	}
}

func (s *Service) audit(ctx context.Context, actor *string, action, subjectID, status string) {
	metadata := fmt.Sprintf(`{"status":%q}`, status)
	if err := s.store.CreateAuditLog(ctx, actor, action, "scan_job", subjectID, metadata); err != nil {
		s.logger.Error("create scan audit log", "action", action, "error", err)
	}
}

func registrationFromAgent(agent store.ScanAgent) scanner.AgentRegistration {
	return scanner.AgentRegistration{
		ID:                 agent.ID,
		Name:               agent.Name,
		CertificateSubject: agent.CertificateSubject,
		AllowedCIDRs:       agent.AllowedCIDRs,
		Status:             scanner.AgentStatus(agent.Status),
	}
}

func scannerJob(id string, input store.ScanJobInput) scanner.ScanJob {
	requestedBy := ""
	if input.RequestedBy != nil {
		requestedBy = *input.RequestedBy
	}
	return scanner.ScanJob{
		ID:             id,
		AgentID:        input.AgentID,
		RequestedBy:    requestedBy,
		Type:           scanner.ScanType(input.ScanType),
		Mode:           scanner.ScanMode(input.Mode),
		AllowedCIDRs:   input.AllowedCIDRs,
		Targets:        input.Targets,
		TimeoutSeconds: input.TimeoutSeconds,
		CreatedAt:      time.Now().UTC(),
	}
}

func scannerJobFromStore(job store.ScanJob) scanner.ScanJob {
	return scanner.ScanJob{
		ID:             job.ID,
		AgentID:        job.AgentID,
		RequestedBy:    job.RequestedBy,
		Type:           scanner.ScanType(job.ScanType),
		Mode:           scanner.ScanMode(job.Mode),
		AllowedCIDRs:   job.AllowedCIDRs,
		Targets:        job.Targets,
		TimeoutSeconds: job.TimeoutSeconds,
		CreatedAt:      job.CreatedAt,
	}
}
