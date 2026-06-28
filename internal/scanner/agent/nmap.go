package agent

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// Discoverer performs active discovery for an already-validated scan job and
// returns observations. It is the only place in the system that runs privileged
// network probes; it lives in the agent, never the app.
type Discoverer interface {
	Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error)
}

// commandRunner executes the scanner binary with the given arguments and returns
// its stdout. It is injectable so tests can exercise argument building and XML
// parsing without a real nmap binary or raw-socket privileges.
type commandRunner func(ctx context.Context, name string, args []string) ([]byte, error)

// PinMode selects how the egress source pin (EgressOptions) is applied to a
// job's targets. The default is auto: pin only the targets that are layer-2
// adjacent to the scan source interface, and let routed targets use the kernel's
// default route. See ParsePinMode and planEgress.
type PinMode string

const (
	// PinAuto pins a target only when it is L2-adjacent to the scan source
	// interface (its IP/CIDR falls inside the source subnet); routed targets run
	// unpinned. This keeps the #37 same-subnet fix while letting one macvlan agent
	// also scan routed subnets without silently finding zero hosts.
	PinAuto PinMode = "auto"
	// PinAlways pins every target to the source interface/IP (the pre-#37
	// unconditional behavior). Correct only when every target is on the source
	// segment.
	PinAlways PinMode = "always"
	// PinOff never pins; nmap chooses its own egress even when a source IP is set.
	PinOff PinMode = "off"
)

// ParsePinMode interprets the AGENT_SCAN_PIN_MODE value, defaulting to auto. It
// accepts "same-subnet-only" as a back-compat alias of auto (the pin decision is
// identical; auto simply also warns on a routed mismatch) and treats any
// unrecognized value as auto, the safe routing-aware default.
func ParsePinMode(s string) PinMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(PinAlways):
		return PinAlways
	case string(PinOff):
		return PinOff
	default: // "", "auto", "same-subnet-only", or anything unknown
		return PinAuto
	}
}

// EgressOptions pins nmap's raw probes to a specific source interface and
// address. On a dual-homed agent (control-plane bridge + macvlan LAN) the
// default route points at the bridge, so without pinning, nmap's SYN/OS probes
// to a directly-connected LAN target can egress (or have replies return on) the
// wrong interface and never complete: the ARP ping succeeds — so the MAC is
// reported — but service/OS detection silently comes back empty. Pinning a
// same-subnet scan to the LAN interface makes the results consistent.
//
// The pin is applied per-target according to PinMode (see planEgress): in the
// default auto mode only targets inside SourceNet (L2-adjacent) are pinned, so a
// routed target no longer disagrees with the kernel route and silently returns
// zero hosts. Interface/SourceIP are empty by default, in which case nmap chooses
// egress itself (the original bridge-only behavior) regardless of mode.
type EgressOptions struct {
	Interface string     // nmap -e <iface>
	SourceIP  string     // nmap -S <ip>
	PinMode   PinMode    // how the pin is applied per target (default auto)
	SourceNet *net.IPNet // the scan source interface's subnet, for auto L2-adjacency
}

// args renders the egress pin as nmap flags, omitting any unset field.
func (e EgressOptions) args() []string {
	var out []string
	if strings.TrimSpace(e.Interface) != "" {
		out = append(out, "-e", e.Interface)
	}
	if strings.TrimSpace(e.SourceIP) != "" {
		out = append(out, "-S", e.SourceIP)
	}
	return out
}

// effectivePinMode normalizes an empty PinMode (the zero value) to auto, so the
// routing-aware default applies whenever a caller leaves the mode unset.
func (e EgressOptions) effectivePinMode() PinMode {
	if e.PinMode == "" {
		return PinAuto
	}
	return e.PinMode
}

// withoutPin returns a copy with the source interface/address cleared, so its
// args() render no pin — used for the unpinned (routed/default-route) target set.
func (e EgressOptions) withoutPin() EgressOptions {
	e.Interface = ""
	e.SourceIP = ""
	return e
}

// pinConfigured reports whether any source pin is set to apply.
func (e EgressOptions) pinConfigured() bool {
	return strings.TrimSpace(e.Interface) != "" || strings.TrimSpace(e.SourceIP) != ""
}

// NmapDiscoverer drives the nmap binary to perform host discovery, TCP service
// detection, and OS probing. The depth of each scan is bounded by the job's
// mode; passive jobs never reach here.
type NmapDiscoverer struct {
	binary string
	egress EgressOptions
	run    commandRunner
}

// NewNmapDiscoverer returns a discoverer that shells out to the nmap binary at
// the given path (defaulting to "nmap" on PATH). egress optionally pins every
// scan to a source interface/address (see EgressOptions); pass the zero value
// to let nmap choose its own egress.
func NewNmapDiscoverer(binary string, egress EgressOptions) *NmapDiscoverer {
	if strings.TrimSpace(binary) == "" {
		binary = "nmap"
	}
	return &NmapDiscoverer{binary: binary, egress: egress, run: execCommand}
}

func execCommand(ctx context.Context, name string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		// A blown supervising deadline hard-kills nmap (empty stderr); report it
		// as a timeout rather than a bare "nmap failed:".
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("nmap timed out before completing; raise the scan timeout or narrow the targets")
		}
		// nmap writes diagnostics to stderr; surface them when available, and
		// fall back to the exit/signal state so the message is never empty.
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			if stderr == "" {
				stderr = exitErr.ProcessState.String()
			}
			return out, fmt.Errorf("nmap failed: %s", stderr)
		}
		return out, fmt.Errorf("run nmap: %w", err)
	}
	return out, nil
}

// hostDiscoveryTimeoutSeconds bounds each host in the stage-1 discovery sweep.
// Discovery is fast (a ping/ARP probe), so this only caps a straggler; the real
// per-host budget (ScanJob.TimeoutSeconds) applies to the stage-2 port scan.
const hostDiscoveryTimeoutSeconds = 60

// Discover scans in stages, mirroring how a human would: first find which hosts
// are actually alive (a quick host-discovery sweep), then — only for the live
// ones — scan ports and let nmap version-probe just the ports it finds open. A
// target range with nothing alive short-circuits after stage 1 instead of
// wasting the whole budget probing dead address space.
//
// Egress pinning is routing-aware (see planEgress): the targets are partitioned
// into a pinned set (L2-adjacent to the scan source interface) and an unpinned
// set (routed, using the kernel default route), each run through the staged
// passes with its own egress, then merged per host. In the default auto mode this
// keeps the #37 same-subnet pin while letting routed targets succeed instead of
// silently returning zero hosts.
func (n *NmapDiscoverer) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	if job.Mode == scanner.ModePassive {
		return []scanner.Observation{}, []scanner.ScanError{}, nil
	}
	if len(job.Targets) == 0 {
		return nil, nil, fmt.Errorf("scan job has no targets")
	}

	plan := planEgress(n.egress, job.Targets)

	var allObs []scanner.Observation
	errs := append([]scanner.ScanError{}, plan.notices...)
	for _, set := range plan.sets {
		obs, setErrs, err := n.discoverSet(ctx, job, set.targets, set.egress)
		if err != nil {
			return nil, nil, err
		}
		// A set that found nothing alive explains itself when a pin is configured —
		// otherwise a routed scan returns "succeeded" with zero observations and no
		// clue why (the silent failure ADR 0027 fixes).
		if len(obs) == 0 {
			if notice := zeroHostNotice(n.egress, set); notice != nil {
				errs = append(errs, *notice)
			}
		}
		allObs = append(allObs, obs...)
		errs = append(errs, setErrs...)
	}

	return mergeObservations(allObs), errs, nil
}

// zeroHostNotice explains a set that found no live hosts, in terms of the egress
// pin, so an operator can tell an empty subnet from a pin/route mismatch. It
// returns nil when no pin is configured (plain bridge mode — an empty subnet is
// unremarkable). The three configured cases:
//
//   - pinned routed target (always mode pinning across a router): the classic
//     mismatch — probes leave the wrong interface and replies are lost.
//   - unpinned routed target (auto/off over the default route): expected — MAC
//     discovery needs L2 adjacency, so a routed subnet yields no MACs this way.
//   - pinned adjacent target: the local segment is simply empty.
func zeroHostNotice(egress EgressOptions, set egressSet) *scanner.ScanError {
	if !egress.pinConfigured() {
		return nil
	}
	targets := strings.Join(set.targets, ", ")
	var msg string
	switch {
	case set.pinned && setHasRouted(set.targets, egress.SourceNet):
		msg = fmt.Sprintf("No live hosts discovered for %s. The scanner pins egress to %s "+
			"(AGENT_SCAN_PIN_MODE=always), but the target is routed (outside the source subnet %s), so probes "+
			"leave the wrong interface and replies are lost. Set AGENT_SCAN_PIN_MODE=auto, use bridge mode for "+
			"routed scans, or place a scanner on the target VLAN.",
			targets, pinSourceLabel(egress), ipNetString(egress.SourceNet))
	case !set.pinned:
		msg = fmt.Sprintf("No live hosts discovered for %s over the default route (unpinned). MAC discovery needs "+
			"layer-2 adjacency, so a routed subnet yields no MACs this way — scan its gateway with "+
			"arp_table/snmp_inventory, or place a scanner on that VLAN.", targets)
	default:
		msg = fmt.Sprintf("No live hosts discovered for %s on the pinned source segment %s.",
			targets, ipNetString(egress.SourceNet))
	}
	return &scanner.ScanError{Code: scanner.CodeScanIgnored, Message: msg}
}

// setHasRouted reports whether any target in the set is not L2-adjacent to the
// source subnet (so pinning it would disagree with the kernel route).
func setHasRouted(targets []string, srcNet *net.IPNet) bool {
	for _, t := range targets {
		if classifyAdjacency(t, srcNet) != adjacencyLocal {
			return true
		}
	}
	return false
}

// pinSourceLabel renders the configured pin source for a notice ("192.168.0.9 on
// eth0", or just the IP/interface when only one is known).
func pinSourceLabel(e EgressOptions) string {
	switch {
	case e.SourceIP != "" && e.Interface != "":
		return fmt.Sprintf("%s on %s", e.SourceIP, e.Interface)
	case e.SourceIP != "":
		return e.SourceIP
	default:
		return e.Interface
	}
}

// discoverSet runs the staged nmap passes (host discovery, then service/OS on the
// live hosts) over one partition of targets with a specific egress pin, returning
// the raw stage-1 and stage-2 observations unmerged — the caller merges across
// sets. A set with nothing alive short-circuits after stage 1; the host-discovery
// scan type stops after stage 1 unconditionally.
func (n *NmapDiscoverer) discoverSet(ctx context.Context, job scanner.ScanJob, targets []string, egress EgressOptions) ([]scanner.Observation, []scanner.ScanError, error) {
	setJob := job
	setJob.Targets = targets

	// Stage 1: who is alive?
	alive, errs, err := n.runNmap(ctx, hostDiscoveryArgs(setJob, egress))
	if err != nil {
		return nil, nil, err
	}
	// Host discovery is the whole job for that scan type.
	if job.Type == scanner.ScanHostDiscovery {
		return alive, errs, nil
	}
	if len(alive) == 0 {
		// Nothing answered discovery; don't waste time port-scanning dead space.
		return []scanner.Observation{}, errs, nil
	}

	// Stage 2: port + service/OS detection on the live hosts only. nmap scans the
	// mode's ports and version-probes only the ones it finds open.
	scanArgs, err := serviceScanArgs(setJob, egress, observedIPs(alive))
	if err != nil {
		return nil, nil, err
	}
	scanned, scanErrs, err := n.runNmap(ctx, scanArgs)
	if err != nil {
		return nil, nil, err
	}

	return concatObservations(alive, scanned), append(errs, scanErrs...), nil
}

// egressSet is one partition of a job's targets and the egress pin to apply to
// them: the pinned set carries the source pin, the unpinned set has it stripped.
// pinned records which it is, so a zero-host result can explain itself (a pinned
// routed target is a mismatch; an unpinned routed target is an expected no-MAC).
type egressSet struct {
	targets []string
	egress  EgressOptions
	pinned  bool
}

// egressPlan is the routing-aware partition of a job's targets into pinned and
// unpinned sets, plus any notices (e.g. a CIDR that straddles the source subnet).
type egressPlan struct {
	sets    []egressSet
	notices []scanner.ScanError
}

// planEgress partitions targets into the sets to scan, according to the pin mode,
// and reports straddle notices. The classification is pure containment math — it
// never touches real interfaces or the route table — so it is hermetically
// unit-tested. Every target lands in exactly one set.
//
//   - No pin configured, or mode off: a single unpinned set (nmap chooses egress).
//   - Mode always: a single pinned set (the pre-#37 unconditional pin).
//   - Mode auto: targets inside the source subnet are pinned; routed targets are
//     unpinned; a CIDR that straddles the boundary is scanned unpinned with a notice.
func planEgress(egress EgressOptions, targets []string) egressPlan {
	mode := egress.effectivePinMode()

	if !egress.pinConfigured() || mode == PinOff {
		return egressPlan{sets: []egressSet{{targets: targets, egress: egress.withoutPin(), pinned: false}}}
	}
	if mode == PinAlways {
		return egressPlan{sets: []egressSet{{targets: targets, egress: egress, pinned: true}}}
	}

	// auto: pin only the L2-adjacent targets.
	var pinned, unpinned []string
	var notices []scanner.ScanError
	for _, t := range targets {
		switch classifyAdjacency(t, egress.SourceNet) {
		case adjacencyLocal:
			pinned = append(pinned, t)
		case adjacencyStraddle:
			unpinned = append(unpinned, t)
			notices = append(notices, scanner.ScanError{
				Code:   scanner.CodeScanIgnored,
				Target: t,
				Message: fmt.Sprintf("Target %s straddles the scan source subnet %s; scanning it over the default route (unpinned). "+
					"Split the in-subnet portion into its own target to pin it.", t, ipNetString(egress.SourceNet)),
			})
		default: // adjacencyRouted
			unpinned = append(unpinned, t)
		}
	}

	plan := egressPlan{notices: notices}
	if len(pinned) > 0 {
		plan.sets = append(plan.sets, egressSet{targets: pinned, egress: egress, pinned: true})
	}
	if len(unpinned) > 0 {
		plan.sets = append(plan.sets, egressSet{targets: unpinned, egress: egress.withoutPin(), pinned: false})
	}
	return plan
}

// targetAdjacency describes how a scan target relates to the scan source
// interface's own subnet, which decides whether egress is pinned for it in auto
// mode.
type targetAdjacency int

const (
	adjacencyLocal    targetAdjacency = iota // fully inside the source subnet (L2-adjacent → pin)
	adjacencyRouted                          // shares no address with the source subnet (routed → default route)
	adjacencyStraddle                        // a CIDR that encloses the source subnet plus routed space (→ notice)
)

// classifyAdjacency reports how token (a bare IPv4 address or a CIDR) relates to
// srcNet, the scan source interface's subnet. A nil srcNet means the source
// subnet is unknown, so nothing can be proven L2-adjacent and every target is
// treated as routed. Pure containment — no real interfaces, no route table.
func classifyAdjacency(token string, srcNet *net.IPNet) targetAdjacency {
	if srcNet == nil {
		return adjacencyRouted
	}
	if ip := net.ParseIP(token); ip != nil {
		if srcNet.Contains(ip) {
			return adjacencyLocal
		}
		return adjacencyRouted
	}
	if _, tnet, err := net.ParseCIDR(token); err == nil {
		return classifyNets(srcNet, tnet)
	}
	// Unparseable (should not happen after allowlist validation): do not pin.
	return adjacencyRouted
}

// classifyNets relates a target CIDR to the source subnet. Two CIDRs never
// partially overlap — they are either nested or disjoint — so the target is
// either contained by the source subnet (local), encloses it (straddle: part
// local, part routed), or disjoint (routed).
func classifyNets(srcNet, tnet *net.IPNet) targetAdjacency {
	srcOnes, _ := srcNet.Mask.Size()
	tOnes, _ := tnet.Mask.Size()
	switch {
	case srcNet.Contains(tnet.IP) && srcOnes <= tOnes:
		return adjacencyLocal // tnet ⊆ srcNet
	case tnet.Contains(srcNet.IP) && tOnes < srcOnes:
		return adjacencyStraddle // srcNet ⊊ tnet
	default:
		return adjacencyRouted // disjoint
	}
}

// ipNetString renders a *net.IPNet for a message, tolerating nil.
func ipNetString(n *net.IPNet) string {
	if n == nil {
		return "(unknown)"
	}
	return n.String()
}

// runNmap executes one nmap invocation and parses its XML. nmap exits non-zero on
// partial failures but still emits usable XML, so a run error with parseable
// output is reported as a partial (not a hard failure).
func (n *NmapDiscoverer) runNmap(ctx context.Context, args []string) ([]scanner.Observation, []scanner.ScanError, error) {
	out, runErr := n.run(ctx, n.binary, args)
	if runErr != nil {
		if observations, parseErr := parseNmapXML(out); parseErr == nil && len(observations) > 0 {
			return observations, []scanner.ScanError{{Code: "nmap_partial", Message: runErr.Error()}}, nil
		}
		return nil, nil, runErr
	}
	observations, err := parseNmapXML(out)
	if err != nil {
		return nil, nil, err
	}
	return observations, []scanner.ScanError{}, nil
}

// observedIPs returns the IPv4 addresses from a set of observations, for use as
// the explicit target list of a follow-up stage.
func observedIPs(observations []scanner.Observation) []string {
	ips := make([]string, 0, len(observations))
	for _, obs := range observations {
		if obs.IP != "" {
			ips = append(ips, obs.IP)
		}
	}
	return ips
}

// concatObservations joins two observation slices into a fresh slice, never
// aliasing either input's backing array.
func concatObservations(a, b []scanner.Observation) []scanner.Observation {
	out := make([]scanner.Observation, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

// portArgsForMode renders nmap's port selection for a mode: every TCP port for a
// deep scan (-p-), the top 1000 for light and standard. Deep's all-port sweep is
// kept brisk by aggressive timing (see timingArgs) rather than a slower probe; the
// job timeout (--host-timeout) still bounds it.
func portArgsForMode(mode scanner.ScanMode) []string {
	if mode == scanner.ModeDeepActive {
		return []string{"-p-"}
	}
	return []string{"--top-ports", "1000"}
}

// versionAllForMode reports whether the mode runs nmap's exhaustive version
// probes (--version-all). Only standard does: it scans a small port set, so the
// extra probes are affordable there. Deep keeps plain -sV (default intensity) so
// scanning every port stays fast — it still detects services, just without the
// exhaustive per-port version probing. Light keeps -sV at default intensity too.
func versionAllForMode(mode scanner.ScanMode) bool {
	return mode == scanner.ModeStandardActive
}

// timingArgs speeds up a deep scan, which sweeps all 65535 ports. It uses nmap's
// aggressive timing template (-T4) and a low retry cap, and — unless the operator
// pinned an explicit rate — a guaranteed minimum packet rate so the full-port
// sweep does not crawl. Lighter modes keep nmap's gentle defaults and the
// conservative rate cap. Only the port sweep is sped up; service detection (-sV)
// is unchanged.
func timingArgs(mode scanner.ScanMode, rateCapped bool) []string {
	if mode != scanner.ModeDeepActive {
		return nil
	}
	args := []string{"-T4", "--max-retries", "2"}
	if !rateCapped {
		args = append(args, "--min-rate", "1000")
	}
	return args
}

// hostDiscoveryArgs builds the stage-1 nmap command: a fast host-discovery sweep
// (-sn, no port scan) over the raw targets, to learn which hosts are alive (and
// their MAC/vendor on a local segment) before any port probing. Targets are
// appended last, after "--", and are already allowlist-validated.
func hostDiscoveryArgs(job scanner.ScanJob, egress EgressOptions) []string {
	// -oX - emits XML on stdout; --privileged uses raw sockets (NET_RAW), enabling
	// ARP discovery and its reliable MAC reporting on the local segment.
	args := []string{"-oX", "-", "--privileged", "-sn", "-T4"}
	args = append(args, egress.args()...)
	args = append(args, "--host-timeout", strconv.Itoa(hostDiscoveryTimeoutSeconds)+"s")
	args = append(args, "--")
	args = append(args, job.Targets...)
	return args
}

// serviceScanArgs builds the stage-2 nmap command for the already-discovered live
// hosts: it skips host discovery (-Pn, the hosts are known up), scans the mode's
// ports, and lets nmap version-probe only the ports it finds open (-sV) plus
// optional OS detection. Rate/timing and the per-host timeout apply here, where
// the real work is. hosts is the explicit live-host list from stage 1.
func serviceScanArgs(job scanner.ScanJob, egress EgressOptions, hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("service scan has no live hosts")
	}

	// -Pn: discovery already happened in stage 1, so don't repeat it.
	args := []string{"-oX", "-", "--privileged", "-Pn"}
	// Pin the source interface/address when configured, so a dual-homed agent's
	// probes consistently leave the LAN interface (see EgressOptions).
	args = append(args, egress.args()...)

	// Apply an explicit operator rate cap to any mode, and a conservative default
	// cap to the shallow modes. Deep is intentionally left uncapped (unless the
	// operator pinned a rate) so its all-port sweep can run fast under timingArgs.
	rate := job.RateLimit.ProbesPerSecond
	if rate <= 0 && job.Mode != scanner.ModeDeepActive {
		rate = 100
	}
	if rate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(rate))
	}
	if job.RateLimit.Concurrency > 0 {
		args = append(args, "--max-parallelism", strconv.Itoa(job.RateLimit.Concurrency))
	}
	args = append(args, timingArgs(job.Mode, rate > 0)...)
	if job.TimeoutSeconds > 0 {
		// --host-timeout is PER HOST: nmap caps each host at this budget and then
		// moves on, exiting cleanly with partial results. The agent's supervising
		// context (scanner.ScanBudget) allows for this across every host plus grace,
		// so nmap self-limits instead of being hard-killed mid-write.
		args = append(args, "--host-timeout", strconv.Itoa(job.TimeoutSeconds)+"s")
	}

	switch job.Type {
	case scanner.ScanServiceDetect:
		args = append(args, "-sV")
		args = append(args, portArgsForMode(job.Mode)...)
		if versionAllForMode(job.Mode) {
			args = append(args, "--version-all")
		}
	case scanner.ScanOSProbe:
		args = append(args, "-O")
		// Light is OS-only; standard/deep add service detection over the mode's
		// ports so the OS guess is corroborated by running services.
		if job.Mode != scanner.ModeLightActive {
			args = append(args, "-sV")
			args = append(args, portArgsForMode(job.Mode)...)
			if versionAllForMode(job.Mode) {
				args = append(args, "--version-all")
			}
		}
	case scanner.ScanCombined:
		// Combined always probes services and OS together; the CombinedDiscoverer
		// forces deep mode, so this scans every port with fast service detection.
		args = append(args, "-sV", "-O")
		args = append(args, portArgsForMode(job.Mode)...)
		if versionAllForMode(job.Mode) {
			args = append(args, "--version-all")
		}
	default:
		return nil, fmt.Errorf("unsupported scan type %q", job.Type)
	}

	args = append(args, "--")
	args = append(args, hosts...)
	return args, nil
}

// --- nmap XML parsing ---

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames []nmapName    `xml:"hostnames>hostname"`
	Ports     []nmapPort    `xml:"ports>port"`
	OSMatches []nmapOSMatch `xml:"os>osmatch"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr   string `xml:"addr,attr"`
	Type   string `xml:"addrtype,attr"`
	Vendor string `xml:"vendor,attr"`
}

type nmapName struct {
	Name string `xml:"name,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapStatus  `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type nmapOSMatch struct {
	Name     string        `xml:"name,attr"`
	Accuracy int           `xml:"accuracy,attr"`
	Classes  []nmapOSClass `xml:"osclass"`
}

type nmapOSClass struct {
	OSFamily string `xml:"osfamily,attr"`
}

// parseNmapXML converts nmap's XML output into observations, keeping only hosts
// reported as up and ports reported as open.
func parseNmapXML(data []byte) ([]scanner.Observation, error) {
	if len(data) == 0 {
		return []scanner.Observation{}, nil
	}
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}

	now := time.Now().UTC()
	observations := make([]scanner.Observation, 0, len(run.Hosts))
	for _, host := range run.Hosts {
		if host.Status.State != "" && host.Status.State != "up" {
			continue
		}

		obs := scanner.Observation{ObservedAt: now}
		var vendor string
		for _, addr := range host.Addresses {
			switch addr.Type {
			case "ipv4":
				obs.IP = addr.Addr
			case "mac":
				obs.MAC = addr.Addr
				vendor = addr.Vendor
				obs.Vendor = addr.Vendor
			}
		}
		if obs.IP == "" {
			continue
		}
		if len(host.Hostnames) > 0 {
			obs.Hostname = host.Hostnames[0].Name
		}

		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			obs.Services = append(obs.Services, scanner.ServiceObservation{
				Protocol:    port.Protocol,
				Port:        port.PortID,
				State:       port.State.State,
				ServiceName: port.Service.Name,
				Product:     port.Service.Product,
				Version:     port.Service.Version,
			})
		}

		if len(host.OSMatches) > 0 {
			best := host.OSMatches[0]
			obs.OSDetail = best.Name
			if len(best.Classes) > 0 {
				obs.OSFamily = best.Classes[0].OSFamily
			}
		}

		if vendor != "" {
			obs.Evidence = append(obs.Evidence, scanner.Evidence{
				Source:  "nmap",
				Summary: "MAC vendor: " + vendor,
			})
		}

		observations = append(observations, obs)
	}
	return observations, nil
}
