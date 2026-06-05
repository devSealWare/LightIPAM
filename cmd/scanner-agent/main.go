// Command scanner-agent runs the Light IPAM scanner agent. At this stage it is
// a no-op agent: it authenticates the app over mTLS, validates submitted scan
// jobs against its registered allowlist, and reports empty results. It performs
// no active network scanning. Privileged discovery (Nmap) arrives in a later
// issue and stays isolated to this component.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/scanner/agent"
	"github.com/devSealWare/LightIPAM/internal/scanner/pki"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

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

	tlsConfig, err := agent.ServerTLSConfig(certPEM, keyPEM, caPEM)
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
	discoverer := agent.NewNmapDiscoverer(os.Getenv("SCANNER_NMAP_BIN"), resolveEgress(logger))

	a := agent.New(agent.Config{
		Registration:     registration,
		ExpectedClientCN: getenv("APP_CLIENT_CN", pki.AppClientCN),
		Discoverer:       discoverer,
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
// raw probes to. On a dual-homed agent (control-plane bridge + macvlan LAN) the
// LAN interface must be pinned, or same-subnet service/OS detection silently
// fails while ARP/MAC still works (see agent.EgressOptions). The operator sets
// AGENT_SCAN_SOURCE_IP (typically the agent's macvlan LAN IP) and the agent
// finds the interface that owns it; AGENT_SCAN_INTERFACE can name it directly.
// With neither set, nmap chooses its own egress (the bridge-only default).
func resolveEgress(logger *slog.Logger) agent.EgressOptions {
	egress := agent.EgressOptions{
		Interface: os.Getenv("AGENT_SCAN_INTERFACE"),
		SourceIP:  os.Getenv("AGENT_SCAN_SOURCE_IP"),
	}
	if egress.SourceIP != "" && egress.Interface == "" {
		if iface, err := interfaceForIP(egress.SourceIP); err != nil {
			logger.Warn("could not match scan source IP to a local interface; nmap will choose its own egress",
				"source_ip", egress.SourceIP, "error", err)
		} else {
			egress.Interface = iface
		}
	}
	if egress.Interface != "" || egress.SourceIP != "" {
		logger.Info("pinning nmap egress for consistent cross-subnet scans",
			"interface", egress.Interface, "source_ip", egress.SourceIP)
	}
	return egress
}

// interfaceForIP returns the name of the local interface that owns ip.
func interfaceForIP(ip string) (string, error) {
	target := net.ParseIP(ip)
	if target == nil {
		return "", fmt.Errorf("invalid AGENT_SCAN_SOURCE_IP %q", ip)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(target) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no local interface has address %s", ip)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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
