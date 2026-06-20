package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Managed-CA lifetimes. Leaves are short-lived so revocation can rely on
// expiry; the CA itself is long-lived (rotating it re-establishes trust for all
// agents). These are defaults; callers may pass an explicit TTL.
const (
	DefaultCAValidFor   = 10 * 365 * 24 * time.Hour
	DefaultLeafValidFor = 30 * 24 * time.Hour
	DefaultRenewBefore  = 7 * 24 * time.Hour
)

// CA is a parsed certificate authority that issues and rotates leaf
// certificates. Unlike the one-shot Generate, it keeps a stable signing key so
// re-issued leaves are trusted by anyone who already trusts the CA cert.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// NewCA generates a fresh CA valid for validFor (DefaultCAValidFor if zero).
func NewCA(validFor time.Duration) (*CA, error) {
	if validFor <= 0 {
		validFor = DefaultCAValidFor
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}
	notBefore := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: CACommonName, Organization: []string{defaultOrgString}},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse ca certificate: %w", err)
	}
	return &CA{cert: cert, key: key, certPEM: encodeCert(der)}, nil
}

// LoadCA reconstructs a CA from its stored PEM cert and key.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("pki: invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("pki: invalid CA key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pki: CA key is not ECDSA")
	}
	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// CertPEM returns the CA certificate (the trust root distributed to peers).
func (c *CA) CertPEM() []byte { return c.certPEM }

// KeyPEM returns the PKCS#8-encoded CA private key (store it sealed).
func (c *CA) KeyPEM() ([]byte, error) { return encodeKey(c.key) }

// NotAfter is the CA certificate's expiry.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// Fingerprint returns the CA certificate's SHA-256 fingerprint.
func (c *CA) Fingerprint() string { return fingerprintDER(c.cert.Raw) }

// IssueServer signs a short-lived server (agent) leaf certificate.
func (c *CA) IssueServer(cn string, dnsNames []string, ips []net.IP, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	if ttl <= 0 {
		ttl = DefaultLeafValidFor
	}
	notBefore := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{defaultOrgString}},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	return signLeaf(template, c.cert, c.key)
}

// IssueClient signs a short-lived client (app) leaf certificate.
func (c *CA) IssueClient(cn string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	if ttl <= 0 {
		ttl = DefaultLeafValidFor
	}
	notBefore := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{defaultOrgString}},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return signLeaf(template, c.cert, c.key)
}

// CertNotAfter parses a leaf cert's expiry.
func CertNotAfter(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.New("pki: invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("pki: parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}

// NeedsRenewal reports whether a leaf certificate should be re-issued: it is
// within renewBefore of expiry (or already expired) at time now.
func NeedsRenewal(certPEM []byte, renewBefore time.Duration, now time.Time) (bool, error) {
	notAfter, err := CertNotAfter(certPEM)
	if err != nil {
		return false, err
	}
	return now.Add(renewBefore).After(notAfter), nil
}

// Fingerprint returns a leaf/CA certificate's SHA-256 fingerprint (colon-hex).
func Fingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("pki: invalid certificate PEM")
	}
	return fingerprintDER(block.Bytes), nil
}

func fingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	hexStr := hex.EncodeToString(sum[:])
	var b strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexStr[i : i+2])
	}
	return strings.ToUpper(b.String())
}
