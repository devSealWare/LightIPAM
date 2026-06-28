package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// collectDiagnostics assembles the agent's network self-view for GET
// /diagnostics. The system facts (interfaces, default route, capabilities, nmap
// version) come from injectable seams on the Agent so the assembly is testable
// without touching real interfaces or /proc; the warning computation is a pure
// function of the egress config and the resolved default route.
func (a *Agent) collectDiagnostics(ctx context.Context) scanner.AgentDiagnostics {
	d := scanner.AgentDiagnostics{
		AgentID:               a.cfg.Registration.ID,
		Interfaces:            a.sysInterfaces(),
		ScanSourceIP:          a.cfg.Egress.SourceIP,
		ResolvedScanInterface: a.cfg.Egress.Interface,
		DefaultRouteInterface: a.sysDefaultRoute(),
		PinMode:               string(a.cfg.Egress.effectivePinMode()),
		NmapVersion:           a.nmapVersion(ctx),
		Capabilities:          a.sysCapabilities(),
	}
	d.Warnings = diagnosticsWarnings(a.cfg.Egress, d.DefaultRouteInterface)
	return d
}

// diagnosticsWarnings derives operator-facing warnings from the egress config and
// the kernel's default-route interface. It is pure (no I/O) so it is unit-tested
// directly. The route is used only to explain a likely pin/route mismatch — never
// as the control path for pinning (that is planEgress's pure containment test).
func diagnosticsWarnings(egress EgressOptions, defaultRouteIface string) []string {
	var warnings []string
	if !egress.pinConfigured() {
		return warnings
	}
	if egress.SourceNet == nil {
		warnings = append(warnings, "Could not determine the scan source subnet, so auto mode cannot tell which "+
			"targets are layer-2 adjacent; no target will be pinned. Set AGENT_SCAN_SOURCE_IP to an address on the "+
			"scanning interface.")
	}
	if egress.Interface != "" && defaultRouteIface != "" && egress.Interface != defaultRouteIface {
		switch egress.effectivePinMode() {
		case PinAlways:
			warnings = append(warnings, fmt.Sprintf("The scan source is on %s but the default route is %s; with "+
				"AGENT_SCAN_PIN_MODE=always every target is pinned to %s, so routed targets' probes leave the wrong "+
				"interface and are dropped. Use auto.", egress.Interface, defaultRouteIface, egress.Interface))
		default: // auto / off
			warnings = append(warnings, fmt.Sprintf("The scan source is on %s but the default route is %s; routed "+
				"targets will use the default route (not pinned). MAC discovery for them needs SNMP arp_table or a "+
				"scanner on that VLAN.", egress.Interface, defaultRouteIface))
		}
	}
	return warnings
}

// --- system probes (best-effort; return zero values off-Linux) ---

// listNetworkInterfaces reports the agent's interfaces and their addresses.
func listNetworkInterfaces() []scanner.NetworkInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]scanner.NetworkInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		ni := scanner.NetworkInterface{Name: iface.Name}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ni.Addrs = append(ni.Addrs, addr.String())
			}
		}
		out = append(out, ni)
	}
	return out
}

// readDefaultRouteInterface returns the interface of the kernel's default route,
// or "" when it cannot be determined (e.g. off Linux). Reading the route table is
// unprivileged.
func readDefaultRouteInterface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	return parseDefaultRouteInterface(string(data))
}

// readEffectiveCaps returns the names of the process's effective Linux
// capabilities, or nil when they cannot be read (e.g. off Linux).
func readEffectiveCaps() []string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}
	return parseEffectiveCaps(string(data))
}

// probeNmapVersion runs `nmap --version` and extracts the version string, or ""
// when nmap is missing or errors. Bounded by a short timeout.
func probeNmapVersion(ctx context.Context, binary string) string {
	if strings.TrimSpace(binary) == "" {
		binary = "nmap"
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := execCommand(cctx, binary, []string{"--version"})
	if err != nil {
		return ""
	}
	return parseNmapVersion(string(out))
}

// --- pure parsers ---

// parseDefaultRouteInterface extracts the default-route interface from the
// contents of /proc/net/route: the data row whose Destination column is all
// zeros. Columns are tab/space separated: Iface Destination Gateway Flags ...
func parseDefaultRouteInterface(procNetRoute string) string {
	for i, line := range strings.Split(procNetRoute, "\n") {
		if i == 0 { // header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// parseNmapVersion pulls the version token out of `nmap --version` output, e.g.
// "Nmap version 7.94 ( https://nmap.org )" → "7.94".
func parseNmapVersion(out string) string {
	fields := strings.Fields(out)
	for i, f := range fields {
		if strings.EqualFold(f, "version") && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// capabilityNames maps a Linux capability bit (its index) to its short name.
var capabilityNames = []string{
	"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
	"KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
	"NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK",
	"IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE",
	"SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE",
	"SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE",
	"AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG",
	"WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF",
	"CHECKPOINT_RESTORE",
}

// parseEffectiveCaps decodes the CapEff bitmask from /proc/self/status into the
// set of effective capability names (e.g. ["NET_RAW"] for the hardened agent).
func parseEffectiveCaps(procStatus string) []string {
	for _, line := range strings.Split(procStatus, "\n") {
		rest, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return nil
		}
		return capsFromMask(mask)
	}
	return nil
}

// capsFromMask renders a capability bitmask as the names of its set bits, in bit
// order; an unknown bit becomes "CAP_BIT_<n>" so nothing is silently dropped.
func capsFromMask(mask uint64) []string {
	var out []string
	for bit := 0; bit < 64; bit++ {
		if mask&(uint64(1)<<uint(bit)) == 0 {
			continue
		}
		if bit < len(capabilityNames) {
			out = append(out, capabilityNames[bit])
		} else {
			out = append(out, fmt.Sprintf("CAP_BIT_%d", bit))
		}
	}
	return out
}
