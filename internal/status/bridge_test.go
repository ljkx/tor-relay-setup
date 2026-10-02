package status

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/keys"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// testdata/bridgelines-* and obfs4_bridgeline.txt were written by tor
// 0.4.9.13 running a local obfs4 bridge (obfs4proxy 0.0.14, listening on
// 0.0.0.0:18443) and a local WebTunnel bridge (webtunnel 0.0.7).
const (
	obfs4FP      = "9683BB02DA999159D376414EA8D0B4BBBAF95103"
	obfs4Hashed  = "B2331AC0CA67CCA67C104B892DCCFA531B3DF50A"
	webTunnelFP  = "100CBCC8AA86A21C08339B75C72E08329E3AF05E"
	obfs4Cert    = "cert=Gqu7q1FpwhSbV6LegFzxcIIPqM6wHdJ3PTpTFd9pf9pBR5mgl02M2vjANqo4OasIPDUrIQ iat-mode=0"
	webTunnelURL = "https://bridge.example.org/Abc123secretPath"
)

func testdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestBridgeLine(t *testing.T) {
	t.Parallel()
	obfs4 := relay.Bridge{Transport: relay.TransportObfs4, Port: 18443}
	wt := relay.Bridge{Transport: relay.TransportWebTunnel, Port: 15000}
	tests := []struct {
		name     string
		files    map[string]string
		b        relay.Bridge
		ip       string
		want     string
		complete bool
	}{
		{"tor bridgelines with address", map[string]string{"bridgelines": testdata(t, "bridgelines-obfs4")}, obfs4, "203.0.113.5",
			"obfs4 203.0.113.5:18443 " + obfs4FP + " " + obfs4Cert, true},
		{"tor bridgelines, address unknown", map[string]string{"bridgelines": testdata(t, "bridgelines-obfs4")}, obfs4, "",
			"obfs4 <IP ADDRESS>:18443 " + obfs4FP + " " + obfs4Cert, false},
		{"obfs4proxy file only", map[string]string{"pt_state/obfs4_bridgeline.txt": testdata(t, "obfs4_bridgeline.txt")}, obfs4, "203.0.113.5",
			"obfs4 203.0.113.5:18443 " + obfs4FP + " " + obfs4Cert, true},
		{"webtunnel", map[string]string{"bridgelines": testdata(t, "bridgelines-webtunnel")}, wt, "203.0.113.5",
			"webtunnel [2001:db8:bdc0:e3d:9b06:ceb8:f59f:57f2]:443 " + webTunnelFP + " url=" + webTunnelURL + " ver=0.0.7", true},
		{"nothing yet", nil, obfs4, "203.0.113.5", "", false},
		{"other transport only", map[string]string{"bridgelines": testdata(t, "bridgelines-webtunnel")}, obfs4, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := host.NewFake()
			for name, data := range tt.files {
				h.Files["/var/lib/tor/"+name] = []byte(data)
			}
			got, complete := BridgeLine(h, "/var/lib/tor", tt.b, obfs4FP, tt.ip)
			if got != tt.want || complete != tt.complete {
				t.Errorf("BridgeLine = %q, %v\nwant          %q, %v", got, complete, tt.want, tt.complete)
			}
		})
	}
}

func TestParseIPAddr(t *testing.T) {
	t.Parallel()
	out := "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\\       valid_lft forever\n" +
		"3: eth1    inet 100.64.1.2/10 scope global eth1\n" +
		"4: eth2    inet 203.0.113.5/24 brd 203.0.113.255 scope global eth2\n"
	if got := parseIPAddr(out); got != "203.0.113.5" {
		t.Errorf("parseIPAddr = %q", got)
	}
	if got := parseIPAddr("2: eth0 inet 192.168.1.2/24 scope global eth0\n"); got != "" {
		t.Errorf("private only = %q", got)
	}
}

const obfs4Torrc = `Nickname BridgeOne
ContactInfo "email:ops[]example.org ciissversion:3"
BridgeRelay 1
ORPort 9443
ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ServerTransportListenAddr obfs4 0.0.0.0:443
ExtORPort auto
SocksPort 0
SafeLogging 1
`

const webTunnelTorrc = `Nickname BridgeTwo
ContactInfo "email:ops[]example.org ciissversion:3"
BridgeRelay 1
ORPort 127.0.0.1:auto
AssumeReachable 1
ServerTransportPlugin webtunnel exec /usr/bin/webtunnel-server
ServerTransportListenAddr webtunnel 127.0.0.1:15000
ServerTransportOptions webtunnel url=` + webTunnelURL + `
ExtORPort auto
BridgeDistribution https
SocksPort 0
`

// 0x01BB = 443 and 0x3A98 = 15000, listening.
const (
	procTCP443   = procTCPHeader + "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109        0 1 1 0 100 0 0 10 0\n"
	procTCP15000 = procTCPHeader + "   0: 0100007F:3A98 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109        0 1 1 0 100 0 0 10 0\n"
	procTCPBoth  = procTCP443 + "   1: 00000000:24E3 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109        0 2 1 0 100 0 0 10 0\n"
)

func bridgeFixture(torrc, procTCP string) *fixture {
	fx := goodFixture()
	fx.files = map[string]string{
		"/etc/tor/torrc":                  torrc,
		"/var/lib/tor/fingerprint":        "BridgeOne " + obfs4FP + "\n",
		"/var/lib/tor/hashed-fingerprint": "BridgeOne " + obfs4Hashed + "\n",
		"/usr/bin/obfs4proxy":             "elf",
		"/usr/bin/webtunnel-server":       "elf",
		"/proc/net/tcp":                   procTCP,
	}
	fx.journal = bootstrap
	return fx
}

func withCommands(f *host.Fake, extra map[string]host.Result) *host.Fake {
	next := f.Handler
	f.Handler = func(c host.Command) (host.Result, error) {
		if r, ok := extra[c.Name]; ok {
			return r, nil
		}
		return next(c)
	}
	return f
}

func TestCollectObfs4Bridge(t *testing.T) {
	t.Parallel()
	fx := bridgeFixture(obfs4Torrc, procTCPBoth)
	fx.files["/var/lib/tor/bridgelines"] = strings.Replace(testdata(t, "bridgelines-obfs4"), ":18443", ":443", 1)
	f := withCommands(fx.fake(), map[string]host.Result{
		"ip":     {Output: "2: eth0    inet 203.0.113.9/24 scope global eth0\n"},
		"getcap": {Output: "/usr/bin/obfs4proxy cap_net_bind_service=ep\n"},
	})
	r := collect(t, f, Options{})
	if !r.Relay.Bridge || r.Bridge == nil {
		t.Fatalf("not a bridge: %+v", r.Relay)
	}
	b := r.Bridge
	if b.Transport != "obfs4" || b.Port != 443 || !b.Listening || !b.PluginInstalled || b.CapabilityMissing || b.Distribution != "any" {
		t.Errorf("Bridge = %+v", b)
	}
	if b.HashedFingerprint != obfs4Hashed {
		t.Errorf("HashedFingerprint = %q", b.HashedFingerprint)
	}
	if b.Line != "obfs4 203.0.113.9:443 "+obfs4FP+" "+obfs4Cert || !b.LineComplete {
		t.Errorf("Line = %q (complete %v)", b.Line, b.LineComplete)
	}
	if !r.Healthy() {
		t.Errorf("warnings: %q", r.Warnings)
	}
	if got := b.ScanURL(r.PublicIPv4); got != "https://bridges.torproject.org/scan/?address=203.0.113.9&port=443" {
		t.Errorf("ScanURL = %q", got)
	}

	// The self-test address wins over the interface address (NAT).
	fx.journal = bootstrap + strings.ReplaceAll(selfTestV4, "9001", "9443")
	r = collect(t, withCommands(fx.fake(), map[string]host.Result{"ip": {Output: "2: eth0 inet 203.0.113.9/24 scope global eth0\n"}, "getcap": {Output: ""}}), Options{})
	if !strings.HasPrefix(r.Bridge.Line, "obfs4 203.0.113.5:443 ") {
		t.Errorf("Line = %q, want the self-test address", r.Bridge.Line)
	}
	if !r.Bridge.CapabilityMissing || !hasWarning(r, "lacks CAP_NET_BIND_SERVICE") {
		t.Errorf("capability warning missing: %q", r.Warnings)
	}
}

func TestCollectBridgeProblems(t *testing.T) {
	t.Parallel()
	fx := bridgeFixture(obfs4Torrc, procTCPHeader)
	delete(fx.files, "/usr/bin/obfs4proxy")
	r := collect(t, fx.fake(), Options{})
	if !hasWarning(r, "transport binary /usr/bin/obfs4proxy is missing") {
		t.Errorf("missing binary not reported: %q", r.Warnings)
	}

	fx = bridgeFixture(obfs4Torrc, procTCPHeader)
	r = collect(t, withCommands(fx.fake(), map[string]host.Result{"getcap": {Output: "/usr/bin/obfs4proxy cap_net_bind_service=ep"}}), Options{})
	if !hasWarning(r, "obfs4 transport is not listening on TCP 443") || !hasWarning(r, "nothing is listening on the ORPort") {
		t.Errorf("listener warnings missing: %q", r.Warnings)
	}
}

func TestCollectWebTunnelBridge(t *testing.T) {
	t.Parallel()
	fx := bridgeFixture(webTunnelTorrc, procTCP15000)
	fx.files["/var/lib/tor/bridgelines"] = testdata(t, "bridgelines-webtunnel")
	fx.files["/etc/nginx/sites-available/tor-webtunnel-default"] = "server {}"
	r := collect(t, fx.fake(), Options{})
	b := r.Bridge
	if b == nil || b.Transport != "webtunnel" || b.Port != 15000 || !b.Listening || b.Distribution != "https" {
		t.Fatalf("Bridge = %+v", b)
	}
	if !b.LineComplete || !strings.Contains(b.Line, "url="+webTunnelURL) {
		t.Errorf("Line = %q", b.Line)
	}
	// The ORPort is 127.0.0.1:auto: no ORPort listener warning; nginx runs
	// (the fixture's systemctl is-active succeeds).
	if !r.Healthy() || b.WebServer != "active" {
		t.Errorf("warnings %q, web server %q", r.Warnings, b.WebServer)
	}
	fx.active = false
	r = collect(t, fx.fake(), Options{})
	if r.Bridge.WebServer != "inactive" || !hasWarning(r, "nginx is not running") {
		t.Errorf("inactive nginx not reported: %q", r.Warnings)
	}
}

func TestCollectSigningKeyExpiry(t *testing.T) {
	t.Parallel()
	cert, err := os.ReadFile("../keys/testdata/ed25519_signing_cert")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile("../keys/testdata/ed25519_master_id_public_key")
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Unix(2106514800, 0).UTC()
	fx := goodFixture()
	fx.files["/etc/tor/torrc"] = strings.Replace(fx.files["/etc/tor/torrc"], "SafeLogging 1", "SafeLogging 1\nOfflineMasterKey 1", 1)
	fx.files["/var/lib/tor/keys/"+keys.SigningCert] = string(cert)
	fx.files["/var/lib/tor/keys/"+keys.MasterPublic] = string(pub)

	far := collect(t, fx.fake(), Options{Now: func() time.Time { return expiry.Add(-20 * 24 * time.Hour) }})
	if far.Keys == nil || !far.Keys.Offline || !far.Keys.CertExpires.Equal(expiry) || !far.Healthy() {
		t.Fatalf("Keys = %+v, warnings %q", far.Keys, far.Warnings)
	}
	soon := collect(t, fx.fake(), Options{Now: func() time.Time { return expiry.Add(-3 * 24 * time.Hour) }})
	if !hasWarning(soon, "expires in 3 days") {
		t.Errorf("expiry warning missing: %q", soon.Warnings)
	}
	custom := collect(t, fx.fake(), Options{CertWarnDays: 21, Now: func() time.Time { return expiry.Add(-20 * 24 * time.Hour) }})
	if !hasWarning(custom, "expires in 20 days") {
		t.Errorf("CertWarnDays ignored: %q", custom.Warnings)
	}
	gone := collect(t, fx.fake(), Options{Now: func() time.Time { return expiry.Add(time.Hour) }})
	if !hasWarning(gone, "expired on 2036-10-01") {
		t.Errorf("expired warning missing: %q", gone.Warnings)
	}
}

func TestBridgeLineStaysOutOfJSON(t *testing.T) {
	var r Report
	r.Bridge = &Bridge{Line: "obfs4 203.0.113.5:443 ABCDEF cert=secret iat-mode=0"}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "cert=secret") {
		t.Errorf("bridge line leaked into JSON: %s", data)
	}
}
