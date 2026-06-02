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
