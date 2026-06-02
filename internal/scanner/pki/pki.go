// Package pki generates the development mTLS material the Light IPAM app and a
// scanner agent use to authenticate each other. It produces a private CA, a
// server certificate for the agent, and a client certificate for the app.
//
// This is intended for local/dev and Docker Compose use. Production deployments
// should issue agent certificates from a managed CA with rotation; see
// docs/SCANNER_AGENT.md.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Identities embedded in the generated certificates. The app stores
// AppClientCN as the agent registration's certificate_subject.
const (
	CACommonName     = "Light IPAM Scanner CA"
	AgentServerCN    = "light-ipam-scanner-agent"
	AppClientCN      = "light-ipam-app"
	defaultValidFor  = 365 * 24 * time.Hour
	defaultOrgString = "Light IPAM"
)

// Options controls what subject alternative names the agent server certificate
// is valid for. Defaults are filled in by Generate when fields are empty.
type Options struct {
	// ServerDNSNames are DNS SANs for the agent server certificate. Defaults
	// to [AgentServerCN, "localhost"].
	ServerDNSNames []string
	// ServerIPs are IP SANs for the agent server certificate. Defaults to
	// loopback so a local mTLS round trip works out of the box.
	ServerIPs []net.IP
	// ValidFor is the certificate lifetime. Defaults to one year.
	ValidFor time.Duration
}

// Bundle holds PEM-encoded certificates and keys for a single dev PKI.
type Bundle struct {
	CACertPEM     []byte
	CAKeyPEM      []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

// Generate creates a CA, an agent server certificate, and an app client
// certificate, all signed by the CA.
func Generate(opts Options) (*Bundle, error) {
	if opts.ValidFor == 0 {
		opts.ValidFor = defaultValidFor
	}
	if len(opts.ServerDNSNames) == 0 {
		// "scanner-agent" is the Docker Compose service hostname the app uses.
		opts.ServerDNSNames = []string{AgentServerCN, "scanner-agent", "localhost"}
	}
	if len(opts.ServerIPs) == 0 {
		opts.ServerIPs = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := notBefore.Add(opts.ValidFor)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: CACommonName, Organization: []string{defaultOrgString}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create ca certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse ca certificate: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: AgentServerCN, Organization: []string{defaultOrgString}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     opts.ServerDNSNames,
		IPAddresses:  opts.ServerIPs,
	}
	serverCertPEM, serverKeyPEM, err := signLeaf(serverTemplate, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: AppClientCN, Organization: []string{defaultOrgString}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertPEM, clientKeyPEM, err := signLeaf(clientTemplate, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}

	caKeyPEM, err := encodeKey(caKey)
	if err != nil {
		return nil, fmt.Errorf("encode ca key: %w", err)
	}

	return &Bundle{
		CACertPEM:     encodeCert(caDER),
		CAKeyPEM:      caKeyPEM,
		ServerCertPEM: serverCertPEM,
		ServerKeyPEM:  serverKeyPEM,
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
	}, nil
}

// WriteDir writes the bundle to dir as ca.crt, ca.key, agent.crt, agent.key,
// app.crt, and app.key. Private keys are written 0600.
func (b *Bundle) WriteDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"ca.crt", b.CACertPEM, 0o644},
		{"ca.key", b.CAKeyPEM, 0o600},
		{"agent.crt", b.ServerCertPEM, 0o644},
		{"agent.key", b.ServerKeyPEM, 0o600},
		{"app.crt", b.ClientCertPEM, 0o644},
		{"app.key", b.ClientKeyPEM, 0o600},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return nil
}

func signLeaf(template, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode key: %w", err)
	}
	return encodeCert(der), keyPEM, nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func mustSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(fmt.Sprintf("pki: serial number: %v", err))
	}
	return serial
}
