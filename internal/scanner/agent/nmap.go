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

// NmapDiscoverer drives the nmap binary to perform host discovery, TCP service
// detection, and OS probing. The depth of each scan is bounded by the job's
// mode; passive jobs never reach here.
type NmapDiscoverer struct {
	binary string
	run    commandRunner
}

// NewNmapDiscoverer returns a discoverer that shells out to the nmap binary at
// the given path (defaulting to "nmap" on PATH).
func NewNmapDiscoverer(binary string) *NmapDiscoverer {
	if strings.TrimSpace(binary) == "" {
		binary = "nmap"
	}
	return &NmapDiscoverer{binary: binary, run: execCommand}
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
	args, active, err := nmapArgs(job)
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

// topPortsForMode maps a scan mode to the number of top TCP ports to probe.
func topPortsForMode(mode scanner.ScanMode) int {
	switch mode {
	case scanner.ModeLightActive:
		return 100
	case scanner.ModeStandardActive:
		return 1000
	case scanner.ModeDeepActive:
		return 1000
	default:
		return 100
	}
}

// nmapArgs builds the nmap argument list for a job. The boolean is false when
// the job requires no active probing (passive mode), in which case nmap is not
// run at all. Targets are appended last, after "--", and are already validated
// to fall within the job allowlist before this point.
func nmapArgs(job scanner.ScanJob) ([]string, bool, error) {
	if job.Mode == scanner.ModePassive {
		return nil, false, nil
	}
	if len(job.Targets) == 0 {
		return nil, false, fmt.Errorf("scan job has no targets")
	}

	// -oX - emits XML on stdout; --privileged tells nmap to use raw sockets,
	// which the agent container grants via the NET_RAW capability.
	args := []string{"-oX", "-", "--privileged"}

	rate := job.RateLimit.ProbesPerSecond
	if rate <= 0 {
		rate = 100
	}
	args = append(args, "--max-rate", strconv.Itoa(rate))
	if job.RateLimit.Concurrency > 0 {
		args = append(args, "--max-parallelism", strconv.Itoa(job.RateLimit.Concurrency))
	}
	if job.TimeoutSeconds > 0 {
		// --host-timeout is PER HOST: nmap caps each host at this budget and then
		// moves on, exiting cleanly with partial results. The agent's supervising
		// context (see scanBudget) allows for this across every target plus grace,
		// so nmap self-limits instead of being hard-killed mid-write.
		args = append(args, "--host-timeout", strconv.Itoa(job.TimeoutSeconds)+"s")
	}

	topPorts := topPortsForMode(job.Mode)
	switch job.Type {
	case scanner.ScanHostDiscovery:
		// Host discovery only: ping/ARP sweep, no port scan.
		args = append(args, "-sn")
	case scanner.ScanServiceDetect:
		args = append(args, "-sV", "--top-ports", strconv.Itoa(topPorts))
		if job.Mode == scanner.ModeDeepActive {
			args = append(args, "--version-all")
		}
	case scanner.ScanOSProbe:
		args = append(args, "-O")
		if job.Mode != scanner.ModeLightActive {
			args = append(args, "-sV", "--top-ports", strconv.Itoa(topPorts))
		}
	case scanner.ScanCombined:
		args = append(args, "-sV", "--top-ports", strconv.Itoa(topPorts))
		if job.Mode != scanner.ModeLightActive {
			args = append(args, "-O")
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
