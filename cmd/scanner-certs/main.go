// Command scanner-certs generates the development mTLS material shared by the
// Light IPAM app and a scanner agent: a CA, an agent server certificate, and an
// app client certificate. It is intended for local and Docker Compose use only.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner/pki"
)

func main() {
	dir := flag.String("dir", "deploy/scanner-certs", "output directory for the generated PKI")
	dnsCSV := flag.String("dns", "", "additional comma-separated DNS SANs for the agent server certificate")
	ipCSV := flag.String("ip", "", "additional comma-separated IP SANs for the agent server certificate")
	validDays := flag.Int("days", 365, "certificate validity in days")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	opts := pki.Options{ValidFor: time.Duration(*validDays) * 24 * time.Hour}
	if names := splitCSV(*dnsCSV); len(names) > 0 {
		opts.ServerDNSNames = append([]string{pki.AgentServerCN, "localhost"}, names...)
	}
	if ips := splitCSV(*ipCSV); len(ips) > 0 {
		parsed := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
		for _, raw := range ips {
			ip := net.ParseIP(raw)
			if ip == nil {
				logger.Error("invalid IP SAN", "value", raw)
				os.Exit(1)
			}
			parsed = append(parsed, ip)
		}
		opts.ServerIPs = parsed
	}

	bundle, err := pki.Generate(opts)
	if err != nil {
		logger.Error("generate pki", "error", err)
		os.Exit(1)
	}
	if err := bundle.WriteDir(*dir); err != nil {
		logger.Error("write pki", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote scanner PKI to %s\n", *dir)
	fmt.Println("  ca.crt    shared trust anchor")
	fmt.Println("  agent.crt/agent.key  scanner agent server identity")
	fmt.Println("  app.crt/app.key      Light IPAM app client identity")
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
