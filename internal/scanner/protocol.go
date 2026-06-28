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
	// ScanARPTable harvests IP↔MAC bindings from a gateway/L3 device's ARP
	// (ipNetToMediaTable) cache over SNMP, rather than probing hosts directly.
	// Targets are the gateway device(s) to query; the agent emits an observation
	// for each cached neighbor that falls within the job allowlist. This is how
	// MAC addresses are recovered for hosts on subnets the agent cannot reach at
	// Layer 2 (ARP does not cross routers).
	ScanARPTable ScanType = "arp_table"
	// ScanSNMPInventory queries an SNMP-capable device's own identity (system
	// group: sysDescr/sysName/...) and its interface/IP-address tables, rather
	// than probing other hosts. Targets are the device(s) to inventory; the agent
	// emits one observation per in-scope IP the device owns, enriched with its
	// name, OS guess, and the MAC of the owning interface. This is how LightIPAM
	// learns what a device is (router, printer, server) and the MACs of its own
	// interfaces — facts nmap cannot fingerprint reliably across subnets but a
	// device readily self-reports over SNMP.
	ScanSNMPInventory ScanType = "snmp_inventory"
	// ScanNameLookup resolves human-readable names for specific hosts without nmap
	// or SNMP, over two unprivileged UDP protocols: a NetBIOS node-status query
	// (UDP/137) returns a Windows/Samba host's machine name and workgroup, and a
	// unicast mDNS reverse query (UDP/5353) returns an Apple/Linux/IoT host's
	// ".local" name. Targets are the host IPs to name; the agent emits one
	// observation per host whose name it learns. This recovers hostnames for hosts
	// with no DNS PTR record — common on small-business LANs — and works across
	// subnets for NetBIOS (the query is unicast), unlike multicast-only mDNS.
	ScanNameLookup ScanType = "name_lookup"
	// ScanDHCPLeases ingests active DHCP leases from a lease file the agent can read
	// (ISC dhcpd's dhcpd.leases or dnsmasq's leases file), recovering the
	// authoritative IP↔MAC binding and the client-supplied hostname for each lease —
	// often the most accurate name a host has on a small LAN. Targets scope which IP
	// ranges to ingest; the agent emits one observation per active lease whose IP
	// falls in a target range. The lease file path lives on the agent
	// (AGENT_DHCP_LEASE_FILE); reading a file needs no extra privilege.
	ScanDHCPLeases ScanType = "dhcp_leases"
	// ScanDNSLookup resolves host names from the network's authoritative DNS, with
	// no nmap or SNMP: a reverse (PTR) lookup turns each target IP into a name, and a
	// forward (A) lookup confirms the name maps back to the same IP. Targets are the
	// host IPs to name; the agent emits one observation per IP that has a PTR record.
	// Where name_lookup recovers names for hosts with *no* DNS record (NetBIOS/mDNS),
	// this reads the DNS the network already runs — the common case for managed hosts
	// — and forward-confirms it, over ordinary UDP/TCP/53 with no NET_RAW.
	ScanDNSLookup ScanType = "dns_lookup"
	// ScanLLDPCDP harvests a switch/router's link-layer neighbor caches over SNMP:
	// the standard LLDP-MIB (lldpRemTable + lldpRemManAddrTable) and Cisco's
	// CISCO-CDP-MIB (cdpCacheTable). Targets are the network device(s) to query; the
	// agent emits one observation per discovered neighbor whose management address
	// falls within the job allowlist — its IP, name, platform/OS, and (from an LLDP
	// MAC-typed chassis id) MAC, with the local/remote port relationship as
	// evidence. This maps physical topology — which devices are wired to which
	// switch ports — that no host probe reveals, over plain UDP/161 with no
	// NET_RAW.
	ScanLLDPCDP ScanType = "lldp_cdp"
)

type ScanMode string

const (
	ModePassive        ScanMode = "passive"
	ModeLightActive    ScanMode = "light_active"
	ModeStandardActive ScanMode = "standard_active"
	ModeDeepActive     ScanMode = "deep_active"
)

// CodeScanIgnored marks a best-effort portion of a scan that produced nothing
// and was skipped rather than failed — e.g. an SNMP query during a combined scan
// that got no response. It is informational: a result carrying only ignored
// notices is still a success, and the UI renders these as muted "skipped" notes
// rather than errors.
const CodeScanIgnored = "scan_ignored"

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
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	OSFamily string `json:"os_family,omitempty"`
	OSDetail string `json:"os_detail,omitempty"`
	// VLAN is the 802.1Q access (untagged) VLAN of the interface this address sits
	// on, learned from an SNMP inventory scan (dot1qPvid). 0 means unknown. It maps
	// the host's IP to a VLAN, which LightIPAM uses to fill the containing subnet's
	// VLAN when it has none.
	VLAN       int                  `json:"vlan,omitempty"`
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

// NetworkInterface is one of the agent's local interfaces and its addresses, as
// reported by the diagnostics endpoint.
type NetworkInterface struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

// AgentDiagnostics is the agent's network self-view, returned by GET /diagnostics
// and surfaced on the app's agent detail page. It lets an operator see the
// source/route/interface picture (and any pin/route mismatch) without a
// docker exec. It is read-only and carries no secrets.
type AgentDiagnostics struct {
	AgentID               string             `json:"agent_id"`
	Interfaces            []NetworkInterface `json:"interfaces"`
	ScanSourceIP          string             `json:"scan_source_ip,omitempty"`
	ResolvedScanInterface string             `json:"resolved_scan_interface,omitempty"`
	DefaultRouteInterface string             `json:"default_route_interface,omitempty"`
	PinMode               string             `json:"pin_mode"`
	NmapVersion           string             `json:"nmap_version,omitempty"`
	Capabilities          []string           `json:"capabilities,omitempty"`
	Warnings              []string           `json:"warnings,omitempty"`
}

// Valid reports whether the scan type is a known protocol value.
func (t ScanType) Valid() bool {
	switch t {
	case ScanHostDiscovery, ScanServiceDetect, ScanOSProbe, ScanCombined, ScanARPTable, ScanSNMPInventory, ScanNameLookup, ScanDNSLookup, ScanDHCPLeases, ScanLLDPCDP:
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
