package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// CertReloader holds the agent's current server keypair and reloads it from disk
// when the files change, so a rotated certificate is picked up without
// restarting the process. It is safe for concurrent use and plugs into a
// tls.Config via GetCertificate.
type CertReloader struct {
	certPath string
	keyPath  string

	mu      sync.RWMutex
	current *tls.Certificate
	modTime time.Time
	logger  *slog.Logger
}

// NewCertReloader loads the initial keypair from the given files.
func NewCertReloader(certPath, keyPath string, logger *slog.Logger) (*CertReloader, error) {
	if logger == nil {
		logger = slog.Default()
	}
	r := &CertReloader{certPath: certPath, keyPath: keyPath, logger: logger}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reload reads the certificate/key files and swaps in the new keypair.
func (r *CertReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}
	mod := latestModTime(r.certPath, r.keyPath)
	r.mu.Lock()
	r.current = &cert
	r.modTime = mod
	r.mu.Unlock()
	return nil
}

// GetCertificate returns the current keypair for tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current, nil
}

// changed reports whether the cert/key files have a newer modification time
// than the loaded keypair.
func (r *CertReloader) changed() bool {
	r.mu.RLock()
	loaded := r.modTime
	r.mu.RUnlock()
	return latestModTime(r.certPath, r.keyPath).After(loaded)
}

// Watch reloads the keypair whenever the files change, until ctx is cancelled.
// An out-of-band rotation (sidecar/cron re-issuing the cert) is therefore
// applied live; a reload error keeps the previous keypair serving.
func (r *CertReloader) Watch(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !r.changed() {
				continue
			}
			if err := r.reload(); err != nil {
				r.logger.Warn("agent cert reload failed; keeping current", "error", err)
				continue
			}
			r.logger.Info("agent certificate reloaded after rotation")
		}
	}
}

func latestModTime(paths ...string) time.Time {
	var latest time.Time
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest
}

// ServerTLSConfigReloading builds the agent's mTLS server config using a
// hot-reloadable certificate. The CA pool that verifies app client certs is
// fixed at startup (rotating the trust root is an operator action).
func ServerTLSConfigReloading(reloader *CertReloader, caPEM []byte) (*tls.Config, error) {
	pool, err := certPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		GetCertificate: reloader.GetCertificate,
		ClientCAs:      pool,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		MinVersion:     tls.VersionTLS12,
	}, nil
}
