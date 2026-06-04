package scanner

import (
	"fmt"
	"net/netip"
	"time"
)

const ProtocolVersion = "v1"

type AgentStatus string

const (
	AgentPending  AgentStatus = "pending"
	AgentActive   AgentStatus = "active"
	AgentDisabled AgentStatus = "disabled"
	AgentRevoked  AgentStatus = "revoked"
)

type ScanType string

const (
	ScanHostDiscovery ScanType = "host_discovery"
	ScanServiceDetect ScanType = "service_detection"
	ScanOSProbe       ScanType = "os_probe"
	ScanCombined      ScanType = "combined"
)

type ScanMode string

const (
	ModePassive        ScanMode = "passive"
	ModeLightActive    ScanMode = "light_active"
	ModeStandardActive ScanMode = "standard_active"
	ModeDeepActive     ScanMode = "deep_active"
)

type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobSucceeded JobStatus = "succeeded"
	JobFailed    JobStatus = "failed"
	JobCancelled JobStatus = "cancelled"
	JobRejected  JobStatus = "rejected"
)

type AgentRegistration struct {
	ID                 string      `json:"id"`
	Name               string      `json:"name"`
	SiteID             string      `json:"site_id,omitempty"`
	Version            string      `json:"version"`
	CertificateSubject string      `json:"certificate_subject"`
	AllowedCIDRs       []string    `json:"allowed_cidrs"`
	Status             AgentStatus `json:"status"`
	CreatedAt          time.Time   `json:"created_at"`
	LastSeenAt         *time.Time  `json:"last_seen_at,omitempty"`
}

type RateLimit struct {
	ProbesPerSecond int `json:"probes_per_second"`
	Concurrency     int `json:"concurrency"`
}

type PortSelection struct {
	Protocol string `json:"protocol"`
	Ports    []int  `json:"ports"`
}

type ScanJob struct {
	ID             string          `json:"id"`
	AgentID        string          `json:"agent_id"`
	RequestedBy    string          `json:"requested_by"`
	Type           ScanType        `json:"scan_type"`
	Mode           ScanMode        `json:"mode"`
	AllowedCIDRs   []string        `json:"allowed_cidrs"`
	Targets        []string        `json:"targets"`
	Ports          []PortSelection `json:"ports,omitempty"`
	RateLimit      RateLimit       `json:"rate_limit"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	CreatedAt      time.Time       `json:"created_at"`
}

type ScanResult struct {
	ProtocolVersion string        `json:"protocol_version"`
	JobID           string        `json:"job_id"`
	AgentID         string        `json:"agent_id"`
	Status          JobStatus     `json:"status"`
	StartedAt       *time.Time    `json:"started_at,omitempty"`
	FinishedAt      *time.Time    `json:"finished_at,omitempty"`
	Observations    []Observation `json:"observations"`
	Errors          []ScanError   `json:"errors"`
}

type Observation struct {
	IP         string               `json:"ip"`
	MAC        string               `json:"mac,omitempty"`
	Vendor     string               `json:"vendor,omitempty"`
	Hostname   string               `json:"hostname,omitempty"`
	OSFamily   string               `json:"os_family,omitempty"`
	OSDetail   string               `json:"os_detail,omitempty"`
	Services   []ServiceObservation `json:"services,omitempty"`
	Evidence   []Evidence           `json:"evidence,omitempty"`
	ObservedAt time.Time            `json:"observed_at"`
}

type ServiceObservation struct {
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	State       string `json:"state"`
	ServiceName string `json:"service_name,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
}

type Evidence struct {
	Source  string `json:"source"`
	Summary string `json:"summary"`
	Raw     string `json:"raw,omitempty"`
}

type ScanError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Target  string `json:"target,omitempty"`
}

// Valid reports whether the scan type is a known protocol value.
func (t ScanType) Valid() bool {
	switch t {
	case ScanHostDiscovery, ScanServiceDetect, ScanOSProbe, ScanCombined:
		return true
	default:
		return false
	}
}

// Valid reports whether the scan mode is a known protocol value.
func (m ScanMode) Valid() bool {
	switch m {
	case ModePassive, ModeLightActive, ModeStandardActive, ModeDeepActive:
		return true
	default:
		return false
	}
}

// ValidateJob checks that a scan job is structurally well-formed in isolation:
// required fields are present, enums are known, the timeout is positive, and
// every target is contained by the job's own allowlist. It does not consult the
// registered agent; use ValidateJobForAgent for the full agent-aware check.
func ValidateJob(job ScanJob) error {
	if job.ID == "" {
		return fmt.Errorf("scan job requires an id")
	}
	if job.AgentID == "" {
		return fmt.Errorf("scan job requires an agent_id")
	}
	if !job.Type.Valid() {
		return fmt.Errorf("scan job has unknown scan_type %q", job.Type)
	}
	if !job.Mode.Valid() {
		return fmt.Errorf("scan job has unknown mode %q", job.Mode)
	}
	if job.TimeoutSeconds <= 0 {
		return fmt.Errorf("scan job requires a positive timeout_seconds")
	}
	return ValidateJobTargets(job)
}

// ValidateJobForAgent is the app-side check before dispatching: the agent must
// be active, the job must be addressed to that agent (by app-assigned ID), and
// the job's allowlist must be contained by the agent's registered allowlist.
func ValidateJobForAgent(job ScanJob, agent AgentRegistration) error {
	if agent.Status != AgentActive {
		return fmt.Errorf("agent %q is not active (status %q)", agent.ID, agent.Status)
	}
	if job.AgentID != agent.ID {
		return fmt.Errorf("scan job agent_id %q does not match agent %q", job.AgentID, agent.ID)
	}
	return ValidateAgentScope(job, agent.AllowedCIDRs)
}

// ValidateAgentScope is the agent-side check before accepting work. The agent's
// security boundary is its own allowlist (the connecting app is already
// authenticated by mTLS), so this enforces job structure and that the job's
// allowlist is fully contained by the agent's allowlist — without the
// app-side concerns of agent identity or registration status.
func ValidateAgentScope(job ScanJob, agentAllowedCIDRs []string) error {
	if len(agentAllowedCIDRs) == 0 {
		return fmt.Errorf("agent has no allowed CIDRs")
	}
	if len(job.AllowedCIDRs) == 0 {
		return fmt.Errorf("scan job requires at least one allowed CIDR")
	}
	agentPrefixes, err := parseAllowedPrefixes(agentAllowedCIDRs)
	if err != nil {
		return fmt.Errorf("agent allowlist: %w", err)
	}
	jobPrefixes, err := parseAllowedPrefixes(job.AllowedCIDRs)
	if err != nil {
		return fmt.Errorf("job allowlist: %w", err)
	}
	for i, jobPrefix := range jobPrefixes {
		if !withinAny(jobPrefix, agentPrefixes) {
			return fmt.Errorf("job allowed CIDR %q is outside the agent allowlist", job.AllowedCIDRs[i])
		}
	}
	return ValidateJob(job)
}

func ValidateJobTargets(job ScanJob) error {
	if len(job.AllowedCIDRs) == 0 {
		return fmt.Errorf("scan job requires at least one allowed CIDR")
	}
	if len(job.Targets) == 0 {
		return fmt.Errorf("scan job requires at least one target")
	}

	allowed, err := parseAllowedPrefixes(job.AllowedCIDRs)
	if err != nil {
		return err
	}

	for _, target := range job.Targets {
		if err := validateTarget(target, allowed); err != nil {
			return err
		}
	}
	return nil
}

func withinAny(target netip.Prefix, allowed []netip.Prefix) bool {
	for _, allowedPrefix := range allowed {
		if prefixWithin(target, allowedPrefix) {
			return true
		}
	}
	return false
}

func parseAllowedPrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("parse allowed CIDR %q: %w", value, err)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("allowed CIDR %q is not IPv4", value)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func validateTarget(value string, allowed []netip.Prefix) error {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		if !prefix.Addr().Is4() {
			return fmt.Errorf("target %q is not IPv4", value)
		}
		for _, allowedPrefix := range allowed {
			if prefixWithin(prefix.Masked(), allowedPrefix) {
				return nil
			}
		}
		return fmt.Errorf("target %q is outside allowed CIDRs", value)
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("target %q is not an IPv4 address or CIDR", value)
	}
	if !addr.Is4() {
		return fmt.Errorf("target %q is not IPv4", value)
	}
	for _, allowedPrefix := range allowed {
		if allowedPrefix.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("target %q is outside allowed CIDRs", value)
}

func prefixWithin(target, allowed netip.Prefix) bool {
	return allowed.Contains(target.Addr()) && allowed.Bits() <= target.Bits()
}
