package agent

import (
	"context"
	"encoding/xml"
	"fmt"
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

// EgressOptions pins nmap's raw probes to a specific source interface and
// address. On a dual-homed agent (control-plane bridge + macvlan LAN) the
// default route points at the bridge, so without pinning, nmap's SYN/OS probes
// to a directly-connected LAN target can egress (or have replies return on) the
// wrong interface and never complete: the ARP ping succeeds — so the MAC is
// reported — but service/OS detection silently comes back empty. Pinning every
// scan to the LAN interface makes the results consistent regardless of whether
// the target shares the agent's subnet. Both fields are empty by default, in
// which case nmap chooses egress itself (the original bridge-only behavior).
type EgressOptions struct {
	Interface string // nmap -e <iface>
	SourceIP  string // nmap -S <ip>
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

// Discover runs nmap for the job and parses its XML output into observations.
func (n *NmapDiscoverer) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	args, active, err := nmapArgs(job, n.egress)
	if err != nil {
		return nil, nil, err
	}
	if !active {
		return []scanner.Observation{}, []scanner.ScanError{}, nil
	}

	out, runErr := n.run(ctx, n.binary, args)
	if runErr != nil {
		// nmap exits non-zero on partial failures but still emits usable XML, so
		// try to parse before giving up.
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

// nmapArgs builds the nmap argument list for a job. The boolean is false when
// the job requires no active probing (passive mode), in which case nmap is not
// run at all. Targets are appended last, after "--", and are already validated
// to fall within the job allowlist before this point.
func nmapArgs(job scanner.ScanJob, egress EgressOptions) ([]string, bool, error) {
	if job.Mode == scanner.ModePassive {
		return nil, false, nil
	}
	if len(job.Targets) == 0 {
		return nil, false, fmt.Errorf("scan job has no targets")
	}

	// -oX - emits XML on stdout; --privileged tells nmap to use raw sockets,
	// which the agent container grants via the NET_RAW capability.
	args := []string{"-oX", "-", "--privileged"}
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
		// context (see scanBudget) allows for this across every target plus grace,
		// so nmap self-limits instead of being hard-killed mid-write.
		args = append(args, "--host-timeout", strconv.Itoa(job.TimeoutSeconds)+"s")
	}

	switch job.Type {
	case scanner.ScanHostDiscovery:
		// Host discovery only: ping/ARP sweep, no port scan. Mode does not change
		// a ping sweep, so the depth knobs are intentionally ignored here.
		args = append(args, "-sn")
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
		return nil, false, fmt.Errorf("unsupported scan type %q", job.Type)
	}

	args = append(args, "--")
	args = append(args, job.Targets...)
	return args, true, nil
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
