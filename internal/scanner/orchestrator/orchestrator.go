// Package orchestrator is the app-side coordinator for scans. It validates and
// enqueues jobs, dispatches them to agents over mTLS (via a Dispatcher), records
// lifecycle transitions and audit entries, and runs due schedules on a ticker.
//
// It performs no scanning itself and adds no privileged behavior to the app.
package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
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
	if result.Status == scanner.JobSucceeded && len(result.Observations) > 0 {
		s.recordDiscoveries(ctx, agent, job, result.Observations)
	}
	return out
}

// recordDiscoveries persists each observed host into the review queue. By
// default nothing here mutates IPAM records directly: an operator imports a
// discovery later. When the agent is trusted (auto_import), non-conflicting and
// still-pending observations are imported immediately; conflicts always stay in
// the queue for an operator to resolve.
func (s *Service) recordDiscoveries(ctx context.Context, agent store.ScanAgent, job store.ScanJob, observations []scanner.Observation) {
	recorded, imported := 0, 0
	for _, obs := range observations {
		if strings.TrimSpace(obs.IP) == "" {
			continue
		}
		result, err := s.store.UpsertDiscovery(ctx, store.DiscoveryInput{
			JobID:    job.ID,
			AgentID:  agent.ID,
			IP:       obs.IP,
			MAC:      obs.MAC,
			Vendor:   obs.Vendor,
			Hostname: obs.Hostname,
			OSFamily: obs.OSFamily,
			OSDetail: obs.OSDetail,
			Services: servicesFromObservation(obs.Services),
		})
		if err != nil {
			s.logger.Error("record discovery", "ip", obs.IP, "error", err)
			continue
		}
		recorded++
		if s.maybeAutoImport(ctx, agent, result) {
			imported++
		}
	}
	if recorded > 0 {
		s.audit(ctx, nil, "scan.discovery.recorded", job.ID, strconv.Itoa(recorded))
	}
	if imported > 0 {
		s.audit(ctx, nil, "scan.discovery.auto_imported", job.ID, strconv.Itoa(imported))
	}
}

// maybeAutoImport imports a freshly recorded observation when the agent is
// trusted and the observation is pending review and free of conflicts. An
// observation whose address has no containing subnet is left pending rather than
// treated as an error. Returns whether an import happened.
func (s *Service) maybeAutoImport(ctx context.Context, agent store.ScanAgent, result store.DiscoveryUpsert) bool {
	if !agent.AutoImport || result.ReviewStatus != "pending" || result.ReconcileStatus == store.ReconcileConflict {
		return false
	}
	discovery, err := s.store.ImportDiscovery(ctx, result.ID)
	if err != nil {
		if errors.Is(err, store.ErrNoContainingSubnet) {
			s.logger.Debug("auto-import skipped: no containing subnet", "id", result.ID)
			return false
		}
		s.logger.Error("auto-import discovery", "id", result.ID, "error", err)
		return false
	}
	s.auditSubject(ctx, nil, "scan.discovery.imported", "ip_address", discovery.ImportedAddressID, "auto")
	return true
}

func servicesFromObservation(services []scanner.ServiceObservation) []store.DiscoveryService {
	out := make([]store.DiscoveryService, 0, len(services))
	for _, svc := range services {
		out = append(out, store.DiscoveryService{
			Protocol:    svc.Protocol,
			Port:        svc.Port,
			State:       svc.State,
			ServiceName: svc.ServiceName,
			Product:     svc.Product,
			Version:     svc.Version,
		})
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

// enroller is the subset of the dispatcher used for auto-enrollment. It is an
// optional capability: a dispatcher that does not implement it simply disables
// agent discovery without affecting the scan path.
type enroller interface {
	FetchRegistration(ctx context.Context, endpointURL string) (scanner.AgentRegistration, error)
}

// DiscoverAgent pulls an agent's self-reported identity from its /register
// endpoint over mTLS and enrolls it (as a pending agent if new). The boolean
// reports whether a new agent was created.
func (s *Service) DiscoverAgent(ctx context.Context, endpointURL string) (store.ScanAgent, bool, error) {
	e, ok := s.dispatcher.(enroller)
	if !ok || !s.DispatchEnabled() {
		return store.ScanAgent{}, false, fmt.Errorf("scanner dispatch is not configured")
	}
	reg, err := e.FetchRegistration(ctx, endpointURL)
	if err != nil {
		return store.ScanAgent{}, false, err
	}
	input := store.ScanAgentInput{
		Name:               strings.TrimSpace(reg.Name),
		CertificateSubject: reg.CertificateSubject,
		AllowedCIDRs:       reg.AllowedCIDRs,
	}
	if input.Name == "" {
		input.Name = endpointURL
	}
	agent, created, err := s.store.EnrollDiscoveredAgent(ctx, endpointURL, input)
	if err != nil {
		return store.ScanAgent{}, false, err
	}
	if created {
		s.auditSubject(ctx, nil, "scan.agent.discovered", "scan_agent", agent.ID, agent.Status)
	}
	return agent, created, nil
}

// StartAutoEnroll attempts to enroll the bundled agent at endpointURL shortly
// after boot, retrying a few times while the agent container is still starting.
// It runs in its own goroutine and stops once the agent is enrolled (or it
// exhausts its attempts); the operator can always enroll manually later.
func (s *Service) StartAutoEnroll(ctx context.Context, endpointURL string) {
	if strings.TrimSpace(endpointURL) == "" || !s.DispatchEnabled() {
		return
	}
	go func() {
		for attempt := 0; attempt < 10; attempt++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			if _, _, err := s.DiscoverAgent(ctx, endpointURL); err != nil {
				s.logger.Debug("auto-enroll retry", "endpoint", endpointURL, "attempt", attempt+1, "error", err)
				continue
			}
			s.logger.Info("auto-enroll complete", "endpoint", endpointURL)
			return
		}
		s.logger.Warn("auto-enroll gave up; enroll the agent manually from /agents", "endpoint", endpointURL)
	}()
}

func (s *Service) audit(ctx context.Context, actor *string, action, subjectID, status string) {
	s.auditSubject(ctx, actor, action, "scan_job", subjectID, status)
}

func (s *Service) auditSubject(ctx context.Context, actor *string, action, subjectType, subjectID, status string) {
	metadata := fmt.Sprintf(`{"status":%q}`, status)
	if err := s.store.CreateAuditLog(ctx, actor, action, subjectType, subjectID, metadata); err != nil {
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
