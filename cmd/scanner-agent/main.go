// Command scanner-agent runs the Light IPAM scanner agent. It authenticates the
// app over mTLS, validates submitted scan jobs against its registered allowlist,
// and runs the discovery backend selected by scan type: nmap for active
// host/service/OS probing (raw sockets, NET_RAW), SNMP for ARP-table harvesting,
// device inventory, and LLDP/CDP neighbor harvesting (ordinary UDP/161), and
// NetBIOS/mDNS for host-name resolution (ordinary UDP/137 and UDP/5353) — the SNMP
// and name backends need no extra privilege. All privileged behavior is isolated
// to this component; the web app never carries it.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/scanner/agent"
	"github.com/devSealWare/LightIPAM/internal/scanner/pki"
)

// version is the build version, injected at build time via
// -ldflags "-X main.version=v1.0.0". It defaults to "dev" for local builds.
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "version":
			fmt.Println("scanner-agent", version)
			return
		case "--healthcheck":
			// Self-dialing liveness probe for the Compose healthcheck. The HTTP
			// endpoints require a verified client cert, so a plain wget/nc cannot
			// complete the handshake; a TCP connect to the listener is enough to
			// know the process is up and serving.
			os.Exit(runHealthcheck())
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Light IPAM scanner agent", "version", version, "protocol", scanner.ProtocolVersion)

	listen := getenv("AGENT_LISTEN", ":8443")
	certPath := getenv("SCANNER_TLS_CERT", "/certs/agent.crt")
	keyPath := getenv("SCANNER_TLS_KEY", "/certs/agent.key")
	caPath := getenv("SCANNER_TLS_CA", "/certs/ca.crt")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		logger.Error("read server certificate", "path", certPath, "error", err)
		os.Exit(1)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		logger.Error("read server key", "path", keyPath, "error", err)
		os.Exit(1)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		logger.Error("read CA certificate", "path", caPath, "error", err)
		os.Exit(1)
	}

	// A hot-reloading certificate lets a rotated agent cert be picked up without
	// restarting the process: an out-of-band re-issue (the app's managed CA writes
	// fresh files, or a sidecar/cron does) is applied on the next reload tick. The
	// initial keypair is still validated here.
	if _, err := agent.ServerTLSConfig(certPEM, keyPEM, caPEM); err != nil {
		logger.Error("validate server certificate", "error", err)
		os.Exit(1)
	}
	reloader, err := agent.NewCertReloader(certPath, keyPath, logger)
	if err != nil {
		logger.Error("init cert reloader", "error", err)
		os.Exit(1)
	}
	tlsConfig, err := agent.ServerTLSConfigReloading(reloader, caPEM)
	if err != nil {
		logger.Error("build server TLS config", "error", err)
		os.Exit(1)
	}

	registration := scanner.AgentRegistration{
		ID:                 getenv("AGENT_ID", "agent-local"),
		Name:               getenv("AGENT_NAME", "local-scanner-agent"),
		SiteID:             os.Getenv("AGENT_SITE_ID"),
		Version:            scanner.ProtocolVersion,
		CertificateSubject: pki.AgentServerCN,
		Status:             scanner.AgentActive,
		AllowedCIDRs:       splitCSV(os.Getenv("AGENT_ALLOWED_CIDRS")),
		CreatedAt:          time.Now().UTC(),
	}
	if len(registration.AllowedCIDRs) == 0 {
		logger.Error("AGENT_ALLOWED_CIDRS must list at least one IPv4 CIDR")
		os.Exit(1)
	}

	// Active discovery is performed by nmap, which uses raw sockets granted to
	// this container (and only this container) via the NET_RAW capability. The
	// app never carries this risk profile.
	nmap := agent.NewNmapDiscoverer(os.Getenv("SCANNER_NMAP_BIN"), resolveEgress(logger))

	// SNMP is a separate, unprivileged backend: it speaks UDP/161 from an ordinary
	// socket (no NET_RAW) to read a gateway's neighbor cache (arp_table), a device's
	// own identity and interface/IP tables (snmp_inventory), or a switch/router's
	// LLDP and CDP link-layer neighbor caches (lldp_cdp). The router sends all three
	// SNMP job types to it and everything else to nmap.
	snmp := resolveSNMP(logger)

	// Names is a third unprivileged backend: it speaks NetBIOS (UDP/137) and mDNS
	// (UDP/5353) from ordinary sockets (no NET_RAW) to learn a host's machine name
	// and ".local" name. The router sends name_lookup jobs to it.
	names := resolveNames(logger)

	// DNS is a fourth unprivileged backend: it queries the network's authoritative
	// DNS (UDP/TCP/53, no NET_RAW) for a host's reverse (PTR) name and forward-
	// confirms it. The router sends dns_lookup jobs to it.
	dns := resolveDNS(logger)

	// DHCP is a fifth unprivileged backend: it reads the DHCP server's lease file
	// (when one is mounted and configured) for authoritative IP↔MAC bindings and
	// client-supplied hostnames. The router sends dhcp_leases jobs to it.
	dhcp := resolveDHCP(logger)

	// Combined runs every backend against the targets — deep nmap, plus the two
	// SNMP passes, the name lookup, the DNS lookup, and the DHCP lease lookup as
	// best-effort enrichment — and merges the findings into one picture per host. An
	// unreachable or unconfigured enrichment pass is ignored, not failed.
	combined := agent.NewCombinedDiscoverer(nmap, snmp, names, dns, dhcp)

	router := agent.NewDiscoveryRouter(nmap).
		Register(scanner.ScanARPTable, snmp).
		Register(scanner.ScanSNMPInventory, snmp).
		Register(scanner.ScanLLDPCDP, snmp).
		Register(scanner.ScanNameLookup, names).
		Register(scanner.ScanDNSLookup, dns).
		Register(scanner.ScanDHCPLeases, dhcp).
		Register(scanner.ScanCombined, combined)

	a := agent.New(agent.Config{
		Registration:     registration,
		ExpectedClientCN: getenv("APP_CLIENT_CN", pki.AppClientCN),
		Discoverer:       router,
		Logger:           logger,
	})

	server := &http.Server{
		Addr:              listen,
		Handler:           a.Handler(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Watch the certificate files and hot-reload on rotation.
	go reloader.Watch(ctx, time.Duration(positiveInt(os.Getenv("AGENT_CERT_RELOAD_SECONDS"), 300))*time.Second)

	go func() {
		logger.Info("starting scanner agent",
			"listen", listen,
			"agent_id", registration.ID,
			"allowed_cidrs", registration.AllowedCIDRs,
			"active_scanning", true,
		)
		// Certificates are already in TLSConfig, so the file arguments are empty.
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Error("scanner agent stopped", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown scanner agent", "error", err)
		os.Exit(1)
	}
}

// resolveEgress decides which interface and source address nmap should pin its
// raw probes to, and how that pin is applied per target. On a dual-homed agent
// (control-plane bridge + macvlan LAN) the LAN interface must be pinned for a
// same-subnet target, or service/OS detection silently fails while ARP/MAC still
// works (see agent.EgressOptions, #37). The operator sets AGENT_SCAN_SOURCE_IP
// (typically the agent's macvlan LAN IP) and the agent finds the interface that
// owns it (and that interface's subnet); AGENT_SCAN_INTERFACE can name it
// directly. With neither set, nmap chooses its own egress (the bridge-only
// default).
//
// AGENT_SCAN_PIN_MODE controls when the pin applies: the default "auto" pins only
// targets that are layer-2 adjacent to the source subnet and lets routed targets
// use the kernel's default route, so a single macvlan agent scans both its own
// segment and routed subnets correctly with no config change. "always" restores
// the old unconditional pin; "off" disables pinning.
func resolveEgress(logger *slog.Logger) agent.EgressOptions {
	egress := agent.EgressOptions{
		Interface: os.Getenv("AGENT_SCAN_INTERFACE"),
		SourceIP:  os.Getenv("AGENT_SCAN_SOURCE_IP"),
		PinMode:   agent.ParsePinMode(os.Getenv("AGENT_SCAN_PIN_MODE")),
	}
	switch {
	case egress.SourceIP != "":
		// Resolve the source IP to its owning interface and subnet. The subnet is
		// what auto mode uses to tell L2-adjacent targets from routed ones.
		if iface, srcNet, err := interfaceForIP(egress.SourceIP); err != nil {
			logger.Warn("could not match scan source IP to a local interface; routed targets will not be pinned",
				"source_ip", egress.SourceIP, "error", err)
		} else {
			if egress.Interface == "" {
				egress.Interface = iface
			}
			egress.SourceNet = srcNet
		}
	case egress.Interface != "":
		// Interface named directly without a source IP: best-effort subnet lookup so
		// auto adjacency still works.
		if srcNet := subnetForInterface(egress.Interface); srcNet != nil {
			egress.SourceNet = srcNet
		}
	}
	if egress.Interface != "" || egress.SourceIP != "" {
		logger.Info("nmap egress pinning configured",
			"interface", egress.Interface,
			"source_ip", egress.SourceIP,
			"pin_mode", string(egress.PinMode),
			"source_subnet", ipNetString(egress.SourceNet),
		)
	}
	return egress
}

// ipNetString renders a *net.IPNet for logging, tolerating nil.
func ipNetString(n *net.IPNet) string {
	if n == nil {
		return ""
	}
	return n.String()
}

// runHealthcheck dials the agent's own listen port and returns a process exit
// code (0 healthy, 1 unhealthy). It is invoked as `scanner-agent --healthcheck`
// by the Compose healthcheck. A successful TCP connect proves the listener is up;
// it deliberately does not attempt the mTLS handshake (which needs a client cert
// this self-probe does not carry).
func runHealthcheck() int {
	addr := healthcheckDialAddr(getenv("AGENT_LISTEN", ":8443"))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner-agent healthcheck: dial %s: %v\n", addr, err)
		return 1
	}
	_ = conn.Close()
	return 0
}

// healthcheckDialAddr turns a listen address into a dialable one, replacing a
// wildcard/empty host (":8443", "0.0.0.0:8443", "[::]:8443") with loopback.
func healthcheckDialAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen // unrecognized form; dial as-is
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// resolveSNMP builds the SNMP discovery backend (arp_table + snmp_inventory) from
// the agent's environment. v2c is the only wired version today; the read community
// defaults to "public". The SNMP read credential lives on the agent (here), never
// in the app's job records or audit logs, keeping the secret on the scanning
// component.
func resolveSNMP(logger *slog.Logger) *agent.SNMPDiscoverer {
	cfg := agent.SNMPConfig{
		Version:   agent.SNMPVersion(getenv("AGENT_SNMP_VERSION", "2c")),
		Community: getenv("AGENT_SNMP_COMMUNITY", "public"),
		Port:      uint16(atoiDefault(os.Getenv("AGENT_SNMP_PORT"), 161)),
		Timeout:   time.Duration(atoiDefault(os.Getenv("AGENT_SNMP_TIMEOUT"), 5)) * time.Second,
		Retries:   atoiDefault(os.Getenv("AGENT_SNMP_RETRIES"), 1),
	}
	logger.Info("SNMP discovery enabled (arp_table + snmp_inventory + lldp_cdp)",
		"version", cfg.Version,
		"port", cfg.Port,
		"timeout", cfg.Timeout.String(),
	)
	return agent.NewSNMPDiscoverer(cfg)
}

// resolveNames builds the name-resolution backend (NetBIOS + mDNS) from the
// agent's environment. Both protocols are unprivileged unicast UDP; the ports and
// per-probe timeout are tunable but rarely need changing.
func resolveNames(logger *slog.Logger) *agent.NameDiscoverer {
	cfg := agent.NameConfig{
		NetBIOSPort: uint16(atoiDefault(os.Getenv("AGENT_NETBIOS_PORT"), 137)),
		MDNSPort:    uint16(atoiDefault(os.Getenv("AGENT_MDNS_PORT"), 5353)),
		Timeout:     time.Duration(atoiDefault(os.Getenv("AGENT_NAME_TIMEOUT"), 2)) * time.Second,
	}
	logger.Info("name discovery enabled (NetBIOS + mDNS)",
		"netbios_port", cfg.NetBIOSPort,
		"mdns_port", cfg.MDNSPort,
		"timeout", cfg.Timeout.String(),
	)
	return agent.NewNameDiscoverer(cfg)
}

// resolveDNS builds the DNS enrichment backend from the agent's environment. With
// AGENT_DNS_SERVER set the agent queries that resolver directly (host or host:port,
// defaulting to :53); otherwise it uses the agent's system resolver. Both lookups
// are ordinary UDP/TCP/53 — no extra privilege.
func resolveDNS(logger *slog.Logger) *agent.DNSDiscoverer {
	cfg := agent.DNSConfig{
		Server:  strings.TrimSpace(os.Getenv("AGENT_DNS_SERVER")),
		Timeout: time.Duration(atoiDefault(os.Getenv("AGENT_DNS_TIMEOUT"), 3)) * time.Second,
	}
	resolver := cfg.Server
	if resolver == "" {
		resolver = "system"
	}
	logger.Info("DNS enrichment enabled (reverse PTR + forward confirm)",
		"resolver", resolver,
		"timeout", cfg.Timeout.String(),
	)
	return agent.NewDNSDiscoverer(cfg)
}

// resolveDHCP builds the DHCP lease-ingestion backend from the agent's
// environment. AGENT_DHCP_LEASE_FILE points at a DHCP server's lease file the agent
// can read (mounted read-only); AGENT_DHCP_LEASE_FORMAT selects the parser (isc /
// dnsmasq / auto). With no file configured a dhcp_leases scan reports a clear notice
// rather than failing. Reading a file needs no extra privilege.
func resolveDHCP(logger *slog.Logger) *agent.DHCPDiscoverer {
	cfg := agent.DHCPConfig{
		LeaseFile: strings.TrimSpace(os.Getenv("AGENT_DHCP_LEASE_FILE")),
		Format:    strings.TrimSpace(os.Getenv("AGENT_DHCP_LEASE_FORMAT")),
	}
	if cfg.LeaseFile == "" {
		logger.Info("DHCP lease ingestion idle (set AGENT_DHCP_LEASE_FILE to enable)")
	} else {
		format := cfg.Format
		if format == "" {
			format = "auto"
		}
		logger.Info("DHCP lease ingestion enabled", "lease_file", cfg.LeaseFile, "format", format)
	}
	return agent.NewDHCPDiscoverer(cfg)
}

// atoiDefault parses s as a base-10 int, returning fallback when s is empty or
// malformed.
func atoiDefault(s string, fallback int) int {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return n
}

// interfaceForIP returns the name of the local interface that owns ip and that
// address's subnet (the *net.IPNet from the matching interface address). The
// subnet lets auto pin mode tell L2-adjacent targets from routed ones.
func interfaceForIP(ip string) (string, *net.IPNet, error) {
	target := net.ParseIP(ip)
	if target == nil {
		return "", nil, fmt.Errorf("invalid AGENT_SCAN_SOURCE_IP %q", ip)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(target) {
				return iface.Name, ipNet, nil
			}
		}
	}
	return "", nil, fmt.Errorf("no local interface has address %s", ip)
}

// subnetForInterface returns the first IPv4 subnet on the named interface, or nil
// if the interface is unknown or has no IPv4 address. It is the interface-only
// fallback for auto adjacency when AGENT_SCAN_INTERFACE is set without a source IP.
func subnetForInterface(name string) *net.IPNet {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet
		}
	}
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func positiveInt(value string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
