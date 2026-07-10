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

// SetAuditHook registers the audit fan-out hook on the orchestrator's store, so
// scan-lifecycle audit events (job failed/completed, schedule changes) reach the
// change-webhook dispatcher alongside the app handlers' events (ADR 0022).
func (s *Service) SetAuditHook(hook store.AuditHook) {
	s.store.SetAuditHook(hook)
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

// ValidateScope checks that a prospective job's targets and allowlist are well-formed
// and fully contained by the registered agent's own allowlist, without creating or
// dispatching anything. The schedule form calls it at save time so an out-of-scope
// configuration is rejected inline instead of failing on every scheduler tick. It
// deliberately uses ValidateAgentScope (allowlist containment + job structure) rather
// than the full ValidateJobForAgent, so a schedule may target an agent that is still
// pending approval — only the allowlist relationship is enforced here.
func (s *Service) ValidateScope(ctx context.Context, input store.ScanJobInput) error {
	agent, err := s.store.GetScanAgent(ctx, input.AgentID)
	if err != nil {
		return err
	}
	return scanner.ValidateAgentScope(scannerJob("preview", input), agent.AllowedCIDRs)
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
	s.recordScheduleRun(ctx, job, "running", "")

	result := s.dispatch(ctx, agent, job, started)
	if err := s.store.UpdateScanJobResult(ctx, job.ID, result); err != nil {
		s.logger.Error("record scan job result", "job_id", job.ID, "error", err)
	}
	s.recordScheduleRun(ctx, job, result.Status, result.Error)

	action := "scan.job.completed"
	if result.Status != "succeeded" {
		action = "scan.job.failed"
	} else if err := s.store.TouchScanAgent(ctx, agent.ID, ""); err != nil {
		s.logger.Error("touch scan agent", "agent_id", agent.ID, "error", err)
	}
	s.audit(ctx, actor, action, job.ID, result.Status)
}

// recordScheduleRun writes a scheduled job's outcome back onto its schedule so the
// /schedules page can surface the last run's status and reason. It is a no-op for a
// manually triggered job (no schedule id).
func (s *Service) recordScheduleRun(ctx context.Context, job store.ScanJob, status, errMsg string) {
	if job.ScheduleID == "" {
		return
	}
	if err := s.store.SetScanScheduleLastRun(ctx, job.ScheduleID, status, errMsg, job.ID); err != nil {
		s.logger.Error("record schedule last run", "schedule_id", job.ScheduleID, "error", err)
	}
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

	// The dispatch is a single blocking HTTP call that the agent answers only when
	// the whole scan finishes, so the app must outlast the agent's own budget.
	// Derive it from the same per-host budget the agent uses (scanner.ScanBudget),
	// plus network grace — otherwise a multi-host scan trips "context deadline
	// exceeded" on the app side long before the agent is done.
	timeout := scanner.ScanBudget(job.TimeoutSeconds, job.Targets)
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	timeout += 60 * time.Second
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
	out.Error = headlineError(result.Errors)
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
	recorded, imported, synced := 0, 0, 0
	for _, obs := range observations {
		if strings.TrimSpace(obs.IP) == "" {
			continue
		}
		result, err := s.store.UpsertDiscovery(ctx, store.DiscoveryInput{
			JobID:      job.ID,
			AgentID:    agent.ID,
			IP:         obs.IP,
			MAC:        obs.MAC,
			Vendor:     obs.Vendor,
			Hostname:   obs.Hostname,
			OSFamily:   obs.OSFamily,
			OSDetail:   obs.OSDetail,
			HWSerial:   obs.HWSerial,
			HWObjectID: obs.HWObjectID,
			VLAN:       obs.VLAN,
			Services:   servicesFromObservation(obs.Services),
		})
		if err != nil {
			s.logger.Error("record discovery", "ip", obs.IP, "error", err)
			continue
		}
		recorded++
		// A still-pending observation may be auto-imported (creating IPAM records);
		// an already-imported one is instead re-synced so this scan's findings merge
		// onto the existing device. The two are mutually exclusive per observation.
		switch {
		case s.maybeAutoImport(ctx, agent, result):
			imported++
		case s.syncImported(ctx, result):
			synced++
		}
	}
	if recorded > 0 {
		s.auditCount(ctx, "scan.discovery.recorded", job.ID, "recorded_count", recorded)
	}
	if imported > 0 {
		s.auditCount(ctx, "scan.discovery.auto_imported", job.ID, "imported_count", imported)
	}
	if synced > 0 {
		s.auditCount(ctx, "scan.discovery.synced", job.ID, "synced_count", synced)
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
	// Auto-import never sets a manual name; it falls back to the hostname or a
	// generated "host-<ip>" name, which an operator can rename later.
	discovery, err := s.store.ImportDiscovery(ctx, result.ID, "")
	if err != nil {
		if errors.Is(err, store.ErrNoContainingSubnet) {
			s.logger.Debug("auto-import skipped: no containing subnet", "id", result.ID)
			return false
		}
		s.logger.Error("auto-import discovery", "id", result.ID, "error", err)
		return false
	}
	s.auditSubject(ctx, nil, "scan.discovery.imported", "ip_address", discovery.ImportedAddressID, "auto")
	s.autoLinkBySerial(ctx, discovery.ImportedDeviceID)
	return true
}

// syncImported keeps an already-imported host's device current as later scans of
// different types arrive: an nmap service scan and an SNMP/ARP MAC harvest of the
// same host accumulate onto one device record rather than only the first import's
// data landing. Unlike auto-import it is NOT gated on agent trust — importing the
// host was the operator's decision to manage it, and a sync creates no new IPAM
// records, it only refreshes the device the discovery is already linked to.
// Conflicting observations are left for an operator to resolve. Returns whether a
// device was refreshed.
func (s *Service) syncImported(ctx context.Context, result store.DiscoveryUpsert) bool {
	if result.ReviewStatus != "imported" || result.ReconcileStatus == store.ReconcileConflict {
		return false
	}
	deviceID, err := s.store.SyncImportedDiscovery(ctx, result.ID)
	if err != nil {
		s.logger.Error("sync imported discovery", "id", result.ID, "error", err)
		return false
	}
	s.autoLinkBySerial(ctx, deviceID)
	return true
}

// autoLinkBySerial runs the opt-in gold-confidence auto-link (ADR 0030) after a
// device gained scan findings: when the setting is enabled and the device's
// chassis serial exactly matches other devices' (disjoint subnets, dismissed
// pairs respected), they are linked as one physical device and audited. A
// failure is logged, never fatal — the import/sync itself already succeeded.
func (s *Service) autoLinkBySerial(ctx context.Context, deviceID string) {
	if deviceID == "" {
		return
	}
	linked, err := s.store.AutoLinkDeviceBySerial(ctx, deviceID)
	if err != nil {
		s.logger.Error("auto-link device by serial", "device", deviceID, "error", err)
		return
	}
	if len(linked) > 0 {
		s.auditSubject(ctx, nil, "device.link.auto", "device", deviceID, "serial")
	}
}

// headlineError returns the first real failure message to surface as the job's
// summary error, skipping ignored notices (best-effort portions that were
// skipped, e.g. SNMP during a combined scan). A job whose only errors are ignored
// notices therefore shows no headline error and stays a success.
func headlineError(errs []scanner.ScanError) string {
	for _, e := range errs {
		if e.Code == scanner.CodeScanIgnored {
			continue
		}
		return e.Message
	}
	return ""
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
// passed, advancing each schedule's timestamps. A schedule whose firing is
// restricted to a window (Phase 6, ADR 0021) is skipped this tick when the
// current time is outside that window: its next_run_at is left in the past so it
// stays due and fires on the next tick once the window opens.
func (s *Service) RunDueSchedules(ctx context.Context) {
	schedules, err := s.store.ListDueScanSchedules(ctx)
	if err != nil {
		s.logger.Error("list due scan schedules", "error", err)
		return
	}
	now := time.Now()
	for _, schedule := range schedules {
		if !windowAllows(windowFromSchedule(schedule), now) {
			s.logger.Debug("scan schedule due but outside its window; will retry next tick", "schedule_id", schedule.ID)
			continue
		}
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
		// Surface the rejection on the schedule itself (no job was created), so the
		// operator sees it on /schedules instead of only in the audit log.
		if err := s.store.SetScanScheduleLastRun(ctx, schedule.ID, "rejected", err.Error(), ""); err != nil {
			s.logger.Error("record schedule rejection", "schedule_id", schedule.ID, "error", err)
		}
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

// diagnoser is the subset of the dispatcher used to fetch an agent's network
// self-view. Optional, like enroller.
type diagnoser interface {
	Diagnostics(ctx context.Context, endpointURL string) (scanner.AgentDiagnostics, error)
}

// AgentDiagnostics fetches an agent's network self-view (interfaces, scan
// source/route, pin mode, nmap version, capabilities, warnings) over mTLS, for
// the app's agent detail page.
func (s *Service) AgentDiagnostics(ctx context.Context, endpointURL string) (scanner.AgentDiagnostics, error) {
	dg, ok := s.dispatcher.(diagnoser)
	if !ok || !s.DispatchEnabled() {
		return scanner.AgentDiagnostics{}, fmt.Errorf("scanner dispatch is not configured")
	}
	return dg.Diagnostics(ctx, endpointURL)
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

// auditCount writes an audit entry whose metadata is a named integer count,
// rather than being shoehorned into the string-typed "status" field auditSubject
// uses (e.g. scan.discovery.recorded's count of discoveries, not a status).
func (s *Service) auditCount(ctx context.Context, action, subjectID, field string, count int) {
	if err := s.store.CreateAuditLog(ctx, nil, action, "scan_job", subjectID, auditCountMetadata(field, count)); err != nil {
		s.logger.Error("create scan audit log", "action", action, "error", err)
	}
}

func auditCountMetadata(field string, count int) string {
	return fmt.Sprintf(`{%q:%d}`, field, count)
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
