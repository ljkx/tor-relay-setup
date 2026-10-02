package serve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// TLSConfig returns the server's TLS configuration, or nil for plain HTTP.
//
// With tls_cert/tls_key the files are read through h and re-read when
// they change (checked at most once a minute), so a renewal by certbot or
// similar needs no restart. With acme_domains, certificates come from
// Let's Encrypt through the TLS-ALPN-01 challenge, which is answered on
// the TLS listener itself: Let's Encrypt connects to port 443 of each
// domain, so listen on :443 (or forward 443 to the listen port). No port
// 80 handler is needed.
func TLSConfig(c Config, h host.Host) (*tls.Config, error) {
	switch {
	case c.TLSCert != "":
		r := &certReloader{h: h, certFile: c.TLSCert, keyFile: c.TLSKey, now: time.Now}
		if _, err := r.load(); err != nil {
			return nil, err
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.get}, nil
	case len(c.ACMEDomains) > 0:
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(c.ACMEDomains...),
			Cache:      hostCache{h: h, dir: c.ACMECache},
			Email:      c.ACMEEmail,
		}
		cfg := m.TLSConfig()
		cfg.MinVersion = tls.VersionTLS12
		return cfg, nil
	}
	return nil, nil
}

// certReloader serves a certificate from files and reloads it when they
// change.
type certReloader struct {
	h                 host.Host
	certFile, keyFile string
	now               func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	checked time.Time
	stamp   string
}

func (r *certReloader) stampOf() string {
	var b strings.Builder
	for _, f := range []string{r.certFile, r.keyFile} {
		if info, err := r.h.Stat(f); err == nil {
			fmt.Fprintf(&b, "%d/%d;", info.ModTime().UnixNano(), info.Size())
		}
	}
	return b.String()
}

func (r *certReloader) load() (*tls.Certificate, error) {
	certPEM, err := r.h.ReadFile(r.certFile)
	if err != nil {
		return nil, fmt.Errorf("tls_cert: %w", err)
	}
	keyPEM, err := r.h.ReadFile(r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls_key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls_cert/tls_key: %w", err)
	}
	r.mu.Lock()
	r.cert, r.checked, r.stamp = &cert, r.now(), r.stampOf()
	r.mu.Unlock()
	return &cert, nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	cert, due := r.cert, r.now().Sub(r.checked) > time.Minute
	if due {
		r.checked = r.now()
	}
	stamp := r.stamp
	r.mu.Unlock()
	if due && r.stampOf() != stamp {
		if c, err := r.load(); err == nil {
			return c, nil
		}
	}
	return cert, nil
}

// hostCache stores ACME account keys and certificates under dir through
// internal/host, with private permissions.
type hostCache struct {
	h   host.Host
	dir string
}

func (c hostCache) file(key string) (string, error) {
	if key == "" || strings.ContainsAny(key, `/\`) || strings.Contains(key, "..") {
		return "", fmt.Errorf("acme cache: bad key %q", key)
	}
	return path.Join(c.dir, key), nil
}

func (c hostCache) Get(_ context.Context, key string) ([]byte, error) {
	f, err := c.file(key)
	if err != nil {
		return nil, err
	}
	data, err := c.h.ReadFile(f)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, autocert.ErrCacheMiss
	}
	return data, err
}

func (c hostCache) Put(_ context.Context, key string, data []byte) error {
	f, err := c.file(key)
	if err != nil {
		return err
	}
	if err := c.h.MkdirAll(c.dir, 0o700, ""); err != nil {
		return err
	}
	_, err = c.h.WriteFile(f, data, host.FileOptions{Mode: 0o600})
	return err
}

func (c hostCache) Delete(_ context.Context, key string) error {
	f, err := c.file(key)
	if err != nil {
		return err
	}
	if err := c.h.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
