package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/relay"
)

func validObfs4() Setup {
	s := validGuard()
	s.Relay.Mode = string(relay.ModeBridge)
	s.Relay.ORPort = DefaultBridgePort
	s.Relay.Sandbox = false
	s.Bridge = Bridge{Transport: "obfs4", Obfs4Port: DefaultObfs4Port}
	return s
}

func validWebTunnel() Setup {
	s := validObfs4()
	s.Bridge = Bridge{
		Transport: "webtunnel", Domain: "bridge.example.org", Path: "Abc123secretPath",
		WebServer: WebServerNginx, Certificate: CertCertbot, CertbotAgreeTOS: true,
	}
	return s
}

func TestValidateBridge(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		base   func() Setup
		mutate func(*Setup)
		want   string
	}{
		{"obfs4 ok", validObfs4, func(*Setup) {}, ""},
		{"webtunnel ok", validWebTunnel, func(*Setup) {}, ""},
		{"webtunnel empty path is generated", validWebTunnel, func(s *Setup) { s.Bridge.Path = "" }, ""},
		{"webtunnel manual web server", validWebTunnel, func(s *Setup) { s.Bridge.WebServer, s.Bridge.Certificate = WebServerManual, "" }, ""},
		{"webtunnel existing cert", validWebTunnel, func(s *Setup) {
			s.Bridge.Certificate, s.Bridge.CertFile, s.Bridge.KeyFile = CertExisting, "/etc/ssl/b.pem", "/etc/ssl/b.key"
		}, ""},
		{"obfs4 port missing", validObfs4, func(s *Setup) { s.Bridge.Obfs4Port = 0 }, "bridge.obfs4_port"},
		{"obfs4 port equals ORPort", validObfs4, func(s *Setup) { s.Bridge.Obfs4Port = s.Relay.ORPort }, "must differ"},
		{"bad transport", validObfs4, func(s *Setup) { s.Bridge.Transport = "meek" }, "bridge.transport"},
		{"bad distribution", validObfs4, func(s *Setup) { s.Bridge.Distribution = "moat" }, "bridge.distribution"},
		{"sandbox", validObfs4, func(s *Setup) { s.Relay.Sandbox = true }, "relay.sandbox"},
		{"family", validObfs4, func(s *Setup) { s.Family.Mode = "generate" }, "must not join a relay family"},
		{"kept family ids", validObfs4, func(s *Setup) { s.Family.Keep = []string{strings.Repeat("A", 43)} }, "must not join"},
		{"bad domain", validWebTunnel, func(s *Setup) { s.Bridge.Domain = "203.0.113.5" }, "bridge.domain"},
		{"bad path", validWebTunnel, func(s *Setup) { s.Bridge.Path = "a/b" }, "bridge.path"},
		{"bad web server", validWebTunnel, func(s *Setup) { s.Bridge.WebServer = "apache" }, "bridge.web_server"},
		{"certbot without consent", validWebTunnel, func(s *Setup) { s.Bridge.CertbotAgreeTOS = false }, "certbot_agree_tos"},
		{"certbot bad email", validWebTunnel, func(s *Setup) { s.Bridge.CertbotEmail = "nope" }, "certbot_email"},
		{"no certificate choice", validWebTunnel, func(s *Setup) { s.Bridge.Certificate = "" }, "bridge.certificate"},
		{"relative cert", validWebTunnel, func(s *Setup) {
			s.Bridge.Certificate, s.Bridge.CertFile, s.Bridge.KeyFile = CertExisting, "b.pem", "/etc/ssl/b.key"
		}, "cert_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := tt.base()
			tt.mutate(&s)
			err := s.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("Validate() = %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Fatalf("Validate() = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateExitPolicyChoices(t *testing.T) {
	t.Parallel()
	s := validGuard()
	s.Relay.Mode, s.Exit.ProviderPermission = "exit", true
	for _, p := range []string{"reduced", "default", "web"} {
		s.Exit.Policy = p
		if err := s.Validate(); err != nil {
			t.Errorf("policy %s: %v", p, err)
		}
	}
	s.Exit.Policy = "custom"
	s.Exit.CustomPolicy = []string{"accept *:443"}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "exit.custom_policy") {
		t.Errorf("custom without catch-all: %v", err)
	}
	s.Exit.CustomPolicy = []string{"accept *:443", "reject *:*"}
	if err := s.Validate(); err != nil {
		t.Errorf("custom: %v", err)
	}
	s.Exit.Notice, s.Relay.ORPort = true, 80
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "exit.notice") {
		t.Errorf("notice on the ORPort: %v", err)
	}
}

func TestBridgeWarnings(t *testing.T) {
	t.Parallel()
	s := validObfs4()
	if w := s.Warnings(); len(w) != 0 {
		t.Errorf("clean obfs4 bridge warns: %v", w)
	}
	s.Relay.ORPort, s.Bridge.Obfs4Port = 9001, 443
	w := strings.Join(s.Warnings(), "\n")
	for _, want := range []string{"ORPort 9001", "below 1024", "setcap"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	wt := validWebTunnel()
	wt.Bridge.Distribution = "email"
	if w := strings.Join(wt.Warnings(), "\n"); !strings.Contains(w, "only handed out by the https distributor") {
		t.Errorf("WebTunnel distribution warning missing: %s", w)
	}
	wt.Bridge.Distribution = "none"
	if w := strings.Join(wt.Warnings(), "\n"); !strings.Contains(w, "share its bridge line yourself") {
		t.Errorf("none warning missing: %s", w)
	}
	if w := validGuard().Warnings(); len(w) != 0 {
		t.Errorf("guard warns: %v", w)
	}
}

func TestPublicPorts(t *testing.T) {
	t.Parallel()
	numbers := func(ps []Port) []int {
		var out []int
		for _, p := range ps {
			out = append(out, p.Number)
		}
		return out
	}
	exit := validGuard()
	exit.Relay.Mode, exit.Exit.Notice = "exit", true
	manual := validWebTunnel()
	manual.Bridge.WebServer = WebServerManual
	tests := []struct {
		name string
		s    Setup
		want []int
	}{
		{"guard", validGuard(), []int{9001}},
		{"exit with notice", exit, []int{9001, 80}},
		{"obfs4", validObfs4(), []int{DefaultBridgePort, DefaultObfs4Port}},
		{"webtunnel certbot", validWebTunnel(), []int{443, 80}},
		{"webtunnel manual", manual, []int{443}},
	}
	for _, tt := range tests {
		if got := numbers(tt.s.PublicPorts()); !slices.Equal(got, tt.want) {
			t.Errorf("%s: PublicPorts = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestBridgeRelayConfig(t *testing.T) {
	t.Parallel()
	s := validObfs4()
	s.Family.Keep = []string{strings.Repeat("A", 43)} // never rendered for a bridge
	c := s.RelayConfig([]string{strings.Repeat("B", 43)})
	if c.Mode != relay.ModeBridge || len(c.FamilyIDs) != 0 || c.Sandbox {
		t.Fatalf("bridge config keeps family or sandbox: %+v", c)
	}
	want := relay.Bridge{Transport: relay.TransportObfs4, Plugin: relay.Obfs4ProxyPath, Port: DefaultObfs4Port, Distribution: "any"}
	if c.Bridge != want {
		t.Errorf("Bridge = %+v, want %+v", c.Bridge, want)
	}
	s.Bridge.Plugin = relay.LyrebirdPath
	if got := s.RelayConfig(nil).Bridge.Plugin; got != relay.LyrebirdPath {
		t.Errorf("resolved plugin = %q", got)
	}

	wt := validWebTunnel()
	c = wt.RelayConfig(nil)
	if c.Bridge.URL != "https://bridge.example.org/Abc123secretPath" || c.Bridge.Port != relay.DefaultWebTunnelPort || c.Bridge.Distribution != "https" || c.Bridge.Plugin != relay.WebTunnelPath {
		t.Errorf("WebTunnel bridge = %+v", c.Bridge)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	wt.Bridge.Path = ""
	if got := wt.RelayConfig(nil).Bridge.URL; !strings.HasSuffix(got, "/"+PendingPath) {
		t.Errorf("pending path URL = %q", got)
	}
}

func TestExitRelayConfig(t *testing.T) {
	t.Parallel()
	s := validGuard()
	s.Relay.Mode, s.Exit.ProviderPermission = "exit", true
	s.Exit.Policy, s.Exit.CustomPolicy = "custom", []string{"ACCEPT *:443", "reject *"}
	s.Exit.Notice = true
	s.Relay.Instance = "relay2"
	s.Relay.OfflineMasterKey = true
	c := s.RelayConfig(nil)
	if !slices.Equal(c.ExitPolicyLines, []string{"accept *:443", "reject *:*"}) {
		t.Errorf("ExitPolicyLines = %q", c.ExitPolicyLines)
	}
	if c.ExitNotice != "/etc/tor/instances/relay2/tor-exit-notice.html" {
		t.Errorf("ExitNotice = %q", c.ExitNotice)
	}
	if !c.OfflineMasterKey {
		t.Error("OfflineMasterKey lost")
	}
	s.Relay.Mode = "guard"
	if c := s.RelayConfig(nil); c.ExitNotice != "" || len(c.ExitPolicyLines) != 0 {
		t.Error("a guard relay renders exit settings")
	}
}

func TestFromDocumentBridgeAndExit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, s := range []Setup{validObfs4(), validWebTunnel()} {
		got := FromDocument(relay.ParseDocument(s.RelayConfig(nil).Render("t", now)))
		if got.Relay.Mode != "bridge" || got.Bridge.Transport != s.Bridge.Transport || got.Relay.Sandbox {
			t.Errorf("%s: mode %q transport %q sandbox %v", s.Bridge.Transport, got.Relay.Mode, got.Bridge.Transport, got.Relay.Sandbox)
		}
		if got.Bridge.Obfs4Port != s.Bridge.Obfs4Port || got.Bridge.Domain != s.Bridge.Domain || got.Bridge.Path != s.Bridge.Path {
			t.Errorf("%s: read back %+v, want %+v", s.Bridge.Transport, got.Bridge, s.Bridge)
		}
		if s.IsWebTunnel() && got.Distribution() != "https" {
			t.Errorf("WebTunnel distribution = %q", got.Distribution())
		}
	}

	exit := validGuard()
	exit.Relay.Mode, exit.Exit.ProviderPermission, exit.Exit.Notice = "exit", true, true
	exit.Exit.Policy, exit.Exit.CustomPolicy = "custom", []string{"accept *:22", "reject *:*"}
	exit.Relay.OfflineMasterKey = true
	got := FromDocument(relay.ParseDocument(exit.RelayConfig(nil).Render("t", now)))
	if got.Exit.Policy != "custom" || !slices.Equal(got.Exit.CustomPolicy, exit.Exit.CustomPolicy) || !got.Exit.Notice || !got.Relay.OfflineMasterKey {
		t.Errorf("exit read back: %+v offline=%v", got.Exit, got.Relay.OfflineMasterKey)
	}
	exit.Exit.Policy, exit.Exit.CustomPolicy = "web", nil
	if got := FromDocument(relay.ParseDocument(exit.RelayConfig(nil).Render("t", now))); got.Exit.Policy != "web" {
		t.Errorf("web policy reads back as %q", got.Exit.Policy)
	}
}

// The example configurations in docs/examples parse, and validate once the
// operator filled in what only they can decide.
func TestExampleConfigs(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"relay.toml":            "",
		"bridge-obfs4.toml":     "",
		"bridge-webtunnel.toml": "bridge.certbot_agree_tos", // consent is never preset
	} {
		s, err := Load("../../docs/examples/" + name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = s.Validate()
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
}

func TestBridgeConfigRoundTrip(t *testing.T) {
	t.Parallel()
	s := validWebTunnel()
	s.Bridge.Plugin = relay.LyrebirdPath // never saved
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, data)
	}
	s.Bridge.Plugin = ""
	if got.Bridge != s.Bridge {
		t.Errorf("round trip = %+v, want %+v", got.Bridge, s.Bridge)
	}
	if strings.Contains(string(data), "lyrebird") {
		t.Error("the resolved plugin was saved")
	}
}
