package serve

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

func TestRunRefusesPlainHTTPOffLoopback(t *testing.T) {
	d := NewDemo(DemoSeed, nil)
	for _, listen := range []string{"0.0.0.0:9850", ":9850", "192.0.2.1:9850", "[::]:9850"} {
		cfg := Defaults()
		cfg.Listen = listen
		cfg.MetricsTokenSHA256 = TokenSum("t")
		called := false
		err := Run(context.Background(), Options{Config: cfg, Inventory: d.Inventory(), Source: d, Host: host.NewFake(),
			Listen: func(string, string) (net.Listener, error) { called = true; return nil, errors.New("no") }})
		if err == nil || !strings.Contains(err.Error(), "plain HTTP") || called {
			t.Errorf("%s: %v (listened: %v)", listen, err, called)
		}
	}
	cfg := Defaults()
	if err := Run(context.Background(), Options{Config: cfg, Inventory: d.Inventory(), Source: d, Host: host.NewFake()}); err == nil || !strings.Contains(err.Error(), "nobody could log in") {
		t.Errorf("no users, no token: %v", err)
	}
}

func TestRunServesAndShutsDownGracefully(t *testing.T) {
	d := NewDemo(DemoSeed, nil)
	cfg := Defaults()
	cfg.Listen = "127.0.0.1:0"
	cfg.MetricsTokenSHA256 = TokenSum(testToken)
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	addr := make(chan net.Addr, 1)
	done := make(chan error, 1)
	cache := host.NewFake()
	go func() {
		done <- Run(ctx, Options{Config: cfg, Inventory: d.Inventory(), Source: d, Host: cache, CachePath: "/cache/fleet.json",
			Log: slog.New(slog.NewTextHandler(&logs, nil)), Ready: func(a net.Addr) { addr <- a }})
	}()
	var base string
	select {
	case a := <-addr:
		base = "http://" + a.String()
	case err := <-done:
		t.Fatal(err)
	}
	// The first round runs right away.
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, err := http.Get(base + "/healthz")
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("never healthy")
		}
		time.Sleep(20 * time.Millisecond)
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), "tor_relay_fleet_hosts 7") {
		t.Errorf("metrics %d\n%.200s", res.StatusCode, body)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no graceful shutdown")
	}
	for _, secret := range []string{testToken, TokenSum(testToken)} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the log contains %q", secret)
		}
	}
	if !strings.Contains(logs.String(), "msg=serving") || !strings.Contains(logs.String(), "probe round") || !strings.Contains(logs.String(), "shutting down") {
		t.Errorf("logs:\n%s", logs.String())
	}
	if _, ok := cache.Files["/cache/fleet.json"]; !ok || cache.Modes["/cache/fleet.json"] != 0o600 {
		t.Errorf("flag cache not saved: %v", cache.Modes)
	}
}

func selfSigned(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func TestTLSFromFilesReloads(t *testing.T) {
	h := host.NewFake()
	c1, k1 := selfSigned(t, "one.example.org")
	h.Files["/tls/cert.pem"], h.Files["/tls/key.pem"] = c1, k1
	cfg := Defaults()
	cfg.TLSCert, cfg.TLSKey = "/tls/cert.pem", "/tls/key.pem"
	tc, err := TLSConfig(cfg, h)
	if err != nil || tc == nil || tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("%+v %v", tc, err)
	}
	cert, err := tc.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || cert.Leaf == nil && len(cert.Certificate) == 0 {
		t.Fatal(err)
	}
	h.Files["/tls/key.pem"] = []byte("garbage")
	if _, err := TLSConfig(cfg, h); err == nil {
		t.Error("a bad key was accepted")
	}
	delete(h.Files, "/tls/cert.pem")
	if _, err := TLSConfig(cfg, h); err == nil {
		t.Error("a missing certificate was accepted")
	}

	// The reloader picks up a renewed certificate after a minute.
	h.Files["/tls/cert.pem"], h.Files["/tls/key.pem"] = c1, k1
	clk := &clock{t: time.Now()}
	r := &certReloader{h: h, certFile: "/tls/cert.pem", keyFile: "/tls/key.pem", now: clk.now}
	if _, err := r.load(); err != nil {
		t.Fatal(err)
	}
	c2, k2 := selfSigned(t, "renewed.example.org")
	h.Files["/tls/cert.pem"], h.Files["/tls/key.pem"] = c2, k2
	got, _ := r.get(nil)
	if leaf, _ := x509.ParseCertificate(got.Certificate[0]); leaf.Subject.CommonName != "one.example.org" {
		t.Error("reloaded within the minute")
	}
	clk.add(2 * time.Minute)
	got, _ = r.get(nil)
	if leaf, _ := x509.ParseCertificate(got.Certificate[0]); leaf.Subject.CommonName != "renewed.example.org" {
		t.Error("the renewed certificate was not loaded")
	}
}

func TestACMEConfigAndCache(t *testing.T) {
	h := host.NewFake()
	cfg, err := Parse([]byte("listen = \"0.0.0.0:443\"\nacme_domains = [\"Fleet.Example.org.\"]\nacme_email = \"ops@example.org\"\nmetrics_token_sha256 = \"" + TokenSum("t") + "\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ACMEDomains[0] != "fleet.example.org" || cfg.ACMECache != DefaultACMECache || cfg.CheckListener() != nil {
		t.Errorf("%+v", cfg)
	}
	tc, err := TLSConfig(cfg, h)
	if err != nil || tc == nil || !strings.Contains(strings.Join(tc.NextProtos, ","), "acme-tls/1") {
		t.Fatalf("acme tls config %+v %v", tc, err)
	}
	c := hostCache{h: h, dir: "/var/lib/tor-relay-setup/acme"}
	ctx := context.Background()
	if _, err := c.Get(ctx, "fleet.example.org"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Errorf("miss: %v", err)
	}
	if err := c.Put(ctx, "fleet.example.org", []byte("cert")); err != nil {
		t.Fatal(err)
	}
	if data, err := c.Get(ctx, "fleet.example.org"); err != nil || string(data) != "cert" || h.Modes["/var/lib/tor-relay-setup/acme/fleet.example.org"] != 0o600 {
		t.Errorf("get %q %v", data, err)
	}
	if err := c.Delete(ctx, "fleet.example.org"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "../x", "a/b"} {
		if err := c.Put(ctx, bad, nil); err == nil {
			t.Errorf("key %q accepted", bad)
		}
	}
}

func TestClientAddressAndTrustedProxies(t *testing.T) {
	p := proxies{}
	for _, s := range []string{"127.0.0.1", "10.0.0.0/8"} {
		pr, _ := parsePrefix(s)
		p = append(p, pr)
	}
	mk := func(remote string, xff ...string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	tests := []struct {
		r    *http.Request
		want string
	}{
		{mk("192.0.2.1:5000", "203.0.113.9"), "192.0.2.1"},                 // untrusted peer: header ignored
		{mk("127.0.0.1:5000", "203.0.113.9"), "203.0.113.9"},               // trusted proxy
		{mk("127.0.0.1:5000", "198.51.100.1, 203.0.113.9"), "203.0.113.9"}, // right-most untrusted
		{mk("127.0.0.1:5000", "203.0.113.9, 10.1.2.3"), "203.0.113.9"},     // through two proxies
		{mk("127.0.0.1:5000", "198.51.100.1", "203.0.113.9, 10.0.0.1"), "203.0.113.9"},
		{mk("127.0.0.1:5000"), "127.0.0.1"},                           // no header
		{mk("127.0.0.1:5000", "garbage"), "127.0.0.1"},                // unparsable
		{mk("[::ffff:127.0.0.1]:5000", "203.0.113.9"), "203.0.113.9"}, // mapped address
	}
	for i, tt := range tests {
		if got := p.clientAddr(tt.r).String(); got != tt.want {
			t.Errorf("%d: %s, want %s", i, got, tt.want)
		}
	}
	none := proxies{}
	if got := none.clientAddr(mk("127.0.0.1:1", "203.0.113.9")).String(); got != "127.0.0.1" {
		t.Errorf("no trusted proxies: %s", got)
	}
}
