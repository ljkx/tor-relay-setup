package monitor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

func readKey(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestVerifyRealKeys(t *testing.T) {
	for _, tt := range []struct {
		repo Repo
		file string
	}{{GrafanaRepo, "grafana-gpg.key"}, {CaddyRepo, "caddy-gpg.key"}} {
		out, err := tt.repo.VerifyKey(readKey(t, tt.file))
		if err != nil {
			t.Fatalf("%s: %v", tt.repo.Name, err)
		}
		el, err := openpgp.ReadKeyRing(bytes.NewReader(out))
		if err != nil || len(el) != 1 {
			t.Fatalf("%s: re-read keyring: %v (%d entities)", tt.repo.Name, err, len(el))
		}
	}
	// Each key only verifies for its own repository.
	if _, err := GrafanaRepo.VerifyKey(readKey(t, "caddy-gpg.key")); !errors.Is(err, ErrUnexpectedKey) {
		t.Errorf("Caddy key accepted as Grafana's: %v", err)
	}
}

func TestVerifyKeyRejectsExtraKey(t *testing.T) {
	e, err := openpgp.NewEntity("intruder", "", "intruder@example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	var extra bytes.Buffer
	if err := e.Serialize(&extra); err != nil {
		t.Fatal(err)
	}
	real := readKey(t, "grafana-gpg.key")
	block, err := armor.Decode(bytes.NewReader(real))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(block.Body)
	var both bytes.Buffer
	w, _ := armor.Encode(&both, openpgp.PublicKeyType, nil)
	_, _ = w.Write(body)
	_, _ = w.Write(extra.Bytes())
	_ = w.Close()
	if _, err := GrafanaRepo.VerifyKey(both.Bytes()); !errors.Is(err, ErrUnexpectedKey) {
		t.Errorf("key file with an extra key accepted: %v", err)
	}
	if _, err := GrafanaRepo.VerifyKey([]byte("not a key")); !errors.Is(err, ErrUnexpectedKey) {
		t.Errorf("garbage accepted: %v", err)
	}
}

func TestSources(t *testing.T) {
	got := string(GrafanaRepo.Sources())
	for _, want := range []string{"Types: deb\n", "URIs: https://apt.grafana.com\n", "Suites: stable\n", "Components: main\n", "Signed-By: /usr/share/keyrings/grafana-archive-keyring.gpg\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("sources lack %q:\n%s", want, got)
		}
	}
	if !strings.Contains(string(CaddyRepo.Sources()), "Suites: any-version\n") {
		t.Error("caddy suite")
	}
}

func TestNormalize(t *testing.T) {
	ok := Options{Domain: "Grafana.Example.org.", Email: "ops@example.org", FleetPath: "/fleet"}
	if err := ok.Normalize(); err != nil {
		t.Fatal(err)
	}
	if ok.Domain != "grafana.example.org" || ok.Inventory != DefaultInventory || ok.AdminUser != DefaultAdminUser {
		t.Errorf("defaults: %+v", ok)
	}
	for _, o := range []Options{
		{},
		{Domain: "203.0.113.5"},
		{Domain: "localhost"},
		{Domain: "grafana.example.org\nevil"},
		{Domain: "a.example.org", Email: "x y@example.org"},
		{Domain: "a.example.org", Email: `"q"@example.org`},
		{Domain: "a.example.org", FleetPath: "fleet"},
		{Domain: "a.example.org", FleetPath: "/fleet/"},
		{Domain: "a.example.org", FleetPath: "/{x}"},
		{Domain: "a.example.org", AdminUser: "admin"},
		{Domain: "a.example.org", AdminUser: "Root User"},
		{Domain: "a.example.org", Inventory: "fleet.toml"},
		{Domain: "a.example.org", Inventory: "/etc/a b.toml"},
		{Domain: "a.example.org", Executable: "/tmp/x y"},
	} {
		if err := o.Normalize(); err == nil {
			t.Errorf("accepted %+v", o)
		}
	}
}

func TestGrafanaINI(t *testing.T) {
	o := Options{Domain: "grafana.example.org"}
	_ = o.Normalize()
	ini := string(GrafanaINIFile(o, "s3cret"))
	for _, want := range []string{
		"http_addr = 127.0.0.1\n", "http_port = 3000\n", "domain = grafana.example.org\n", "enforce_domain = true\n",
		"root_url = https://grafana.example.org/\n", "reporting_enabled = false\n", "check_for_updates = false\n",
		"check_for_plugin_updates = false\n", "admin_user = tor-admin\n", "secret_key = s3cret\n", "disable_gravatar = true\n",
		"cookie_secure = true\n", "cookie_samesite = strict\n", "allow_embedding = false\n", "strict_transport_security = true\n",
		"x_content_type_options = true\n", "content_security_policy = true\n", "allow_sign_up = false\n",
		"[auth.anonymous]\nenabled = false\n", "[auth.basic]\n", "[snapshots]\nenabled = false\nexternal_enabled = false\n",
		"[public_dashboards]\nenabled = false\n", "plugin_admin_enabled = false\n", "preinstall_disabled = true\n",
		"default_home_dashboard_path = /etc/grafana/dashboards/tor-relay-setup/tor-fleet-overview.json\n",
		"data_source_proxy_whitelist = 127.0.0.1:9090\n",
	} {
		if !strings.Contains(ini, want) {
			t.Errorf("grafana.ini lacks %q", want)
		}
	}
	if strings.Contains(ini, "admin_password") {
		t.Error("grafana.ini must not carry the admin password")
	}
}

func TestExistingSecretKey(t *testing.T) {
	for in, want := range map[string]string{
		"[security]\nsecret_key = abcDEF123\n":            "abcDEF123",
		";secret_key = SW2YcwTIb9zpOOhoPsMm\n":            "",
		"[security]\nsecret_key = SW2YcwTIb9zpOOhoPsMm\n": "",
		"": "",
	} {
		if got := ExistingSecretKey([]byte(in)); got != want {
			t.Errorf("ExistingSecretKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCaddyfile(t *testing.T) {
	o := Options{Domain: "grafana.example.org", Email: "ops@example.org", FleetPath: "/fleet"}
	_ = o.Normalize()
	c := string(CaddyfileContent(o))
	for _, want := range []string{
		"\temail ops@example.org\n", "protocols h1 h2", "grafana.example.org {\n", `Strict-Transport-Security "max-age=31536000"`,
		`X-Frame-Options "DENY"`, "handle /fleet/metrics* {\n\t\trespond 404", "handle /fleet/* {\n\t\treverse_proxy 127.0.0.1:9850",
		"redir /fleet /fleet/ 308", "reverse_proxy 127.0.0.1:3000",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("Caddyfile lacks %q:\n%s", want, c)
		}
	}
	o.Email, o.FleetPath = "", ""
	c = string(CaddyfileContent(o))
	if strings.Contains(c, "email") || strings.Contains(c, "9850") {
		t.Errorf("without email and fleet path:\n%s", c)
	}
}

func TestServeConfigKeepsOperatorSettings(t *testing.T) {
	o := Options{Domain: "g.example.org", FleetPath: "/fleet"}
	_ = o.Normalize()
	fresh := string(ServeConfig(nil, o, "aaa"))
	for _, want := range []string{
		`listen = "127.0.0.1:9850"`, `base_path = "/fleet/"`, `inventory = "/etc/tor-relay-setup/fleet.toml"`,
		`metrics_auth = true`, `metrics_token_sha256 = "aaa"`, `trusted_proxies = ["127.0.0.1", "::1"]`,
		`probe_interval = "30s"`, `privacy = false`,
	} {
		if !strings.Contains(fresh, want+"\n") {
			t.Errorf("new serve.toml lacks %s:\n%s", want, fresh)
		}
	}
	edited := strings.Replace(fresh, `privacy = false`, `privacy = true`, 1) +
		"\n[[users]]\nname = \"alice\"\nhash = \"$argon2id$x\"\nlisten = \"not top level\"\n"
	o.FleetPath = ""
	got := string(ServeConfig([]byte(edited), o, "bbb"))
	for _, want := range []string{`privacy = true`, `metrics_token_sha256 = "bbb"`, `base_path = "/"`, "[[users]]\nname = \"alice\"", `listen = "not top level"`} {
		if !strings.Contains(got, want) {
			t.Errorf("updated serve.toml lacks %s:\n%s", want, got)
		}
	}
	if strings.Count(got, "metrics_token_sha256 =") != 1 || strings.Index(got, "metrics_token_sha256 =") > strings.Index(got, "[[users]]") {
		t.Errorf("managed key duplicated or misplaced:\n%s", got)
	}
	if tomlValue([]byte(got), "metrics_token_sha256") != "bbb" {
		t.Error("tomlValue")
	}
}

func TestUpsertTOMLAppendsBeforeTables(t *testing.T) {
	got := string(upsertTOML([]byte("a = 1\n\n[t]\nb = 2\n"), map[string]string{"c": "3", "a": "4"}))
	if got != "a = 4\nc = 3\n\n[t]\nb = 2\n" {
		t.Errorf("got %q", got)
	}
}

func TestSecrets(t *testing.T) {
	p := NewPassword()
	if len(p) != 32 || strings.ContainsAny(p, "0O1lI") || p == NewPassword() {
		t.Errorf("password %q", p)
	}
	tok := NewToken()
	if len(tok) != 64 || TokenSHA256(tok) == tok || len(TokenSHA256(tok)) != 64 {
		t.Errorf("token %q", tok)
	}
}

func TestPrometheusFiles(t *testing.T) {
	cfg := string(PrometheusConfigFile(PrometheusRules, PrometheusToken, ServeListen))
	for _, want := range []string{
		"scrape_interval: 30s", "  - /etc/prometheus/rules/tor-relay-fleet.yml", "job_name: tor-relay-fleet",
		"credentials_file: /etc/prometheus/tor-relay-fleet.token", `targets: ["127.0.0.1:9850"]`, "metrics_path: /metrics",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("prometheus.yml lacks %q", want)
		}
	}
	if !strings.Contains(string(PrometheusDefaultsFile()), `--web.listen-address=127.0.0.1:9090 --storage.tsdb.retention.time=400d --storage.tsdb.retention.size=20GB"`) {
		t.Errorf("defaults: %s", PrometheusDefaultsFile())
	}
	if !bytes.Contains(FleetRulesFile(), []byte("TorFleetRelayDown")) {
		t.Error("rules not embedded")
	}
}

func TestFleetUnit(t *testing.T) {
	u := string(FleetUnitFile("/usr/local/bin/tor-relay-setup"))
	for _, want := range []string{
		"User=tor-relay-monitor\n", "ExecStart=/usr/local/bin/tor-relay-setup fleet serve --config /etc/tor-relay-setup/serve.toml\n",
		"NoNewPrivileges=yes\n", "CapabilityBoundingSet=\n", "ProtectSystem=strict\n", "ProtectHome=yes\n", "PrivateTmp=yes\n",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n", "SystemCallFilter=@system-service\n", "CacheDirectory=tor-relay-setup-fleet\n", "Environment=XDG_CACHE_HOME=/var/cache/tor-relay-setup-fleet\n",
		"WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
}

// --- install plan on a fake host ---

// rt answers HTTP requests in tests.
type rt func(*http.Request) (*http.Response, error)

func (f rt) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func keyServer(t *testing.T) *http.Client {
	keys := map[string][]byte{GrafanaRepo.KeyURL: readKey(t, "grafana-gpg.key"), CaddyRepo.KeyURL: readKey(t, "caddy-gpg.key")}
	return &http.Client{Transport: rt(func(r *http.Request) (*http.Response, error) {
		body, ok := keys[r.URL.String()]
		if !ok {
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
}

type fakeServer struct {
	*host.Fake
	users  map[string]bool
	active map[string]bool
	stdin  map[string][]byte // command name -> stdin
}

func newFakeServer() *fakeServer {
	s := &fakeServer{Fake: host.NewFake(), users: map[string]bool{"grafana": true, "prometheus": true}, active: map[string]bool{}, stdin: map[string][]byte{}}
	s.Paths["promtool"] = true
	s.Paths["caddy"] = true
	s.Paths["sudo"] = true
	s.Paths["visudo"] = true
	s.Handler = func(c host.Command) (host.Result, error) {
		fail := &host.ExitError{Command: c.String(), ExitCode: 2}
		switch {
		case c.Name == "getent":
			if !s.users[c.Args[1]] {
				return host.Result{}, fail
			}
		case c.Name == "useradd":
			s.users[c.Args[len(c.Args)-1]] = true
		case c.Name == "userdel":
			delete(s.users, c.Args[0])
		case c.Name == "dpkg-query":
			return host.Result{}, &host.ExitError{ExitCode: 1}
		case c.Name == "runuser" && slices.Contains(c.Args, "ssh-keygen"):
			key := c.Args[len(c.Args)-1]
			_, _ = s.WriteFile(key, []byte("PRIVATE"), host.FileOptions{Mode: 0o600})
			_, _ = s.WriteFile(key+".pub", []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOu1fnVr0bHb0nbiU0pWj2uy8W5H8UuK4u3Dd3s4xR9a tor-relay-monitor@mgmt\n"), host.FileOptions{Mode: 0o644})
		case c.Name == "runuser":
			s.stdin["grafana"] = c.Stdin
			_, _ = s.WriteFile(GrafanaDB, []byte("db"), host.FileOptions{})
		case c.Name == "systemctl" && c.Args[0] == "is-active":
			if !s.active[c.Args[len(c.Args)-1]] {
				return host.Result{}, fail
			}
		case c.Name == "systemctl" && (c.Args[0] == "restart" || c.Args[0] == "reload-or-restart"):
			s.active[c.Args[1]] = true
		}
		return host.Result{}, nil
	}
	return s
}

func noble() system.Facts {
	return system.Facts{
		OSID: "ubuntu", VersionID: "24.04", Codename: "noble", PrettyName: "Ubuntu 24.04 LTS", Arch: "amd64",
		Hostname: "mgmt", MemTotalMiB: 4096, Systemd: true, SSHPorts: []int{22, 2222},
		Firewall: system.Firewall{Kind: system.KindNone, Detail: system.DetailNone},
	}
}

type recorder struct{ notes []string }

func (r *recorder) events(e plan.Event) {
	if e.Kind == plan.StepNote || e.Kind == plan.StepFailed {
		r.notes = append(r.notes, e.Text)
	}
}

func runInstall(t *testing.T, s *fakeServer, f system.Facts, o Options) (*Install, *recorder) {
	t.Helper()
	if o.Domain == "" {
		o.Domain = "grafana.example.org"
	}
	if o.Executable == "" {
		o.Executable = "/usr/local/bin/tor-relay-setup"
	}
	in, err := NewInstall(o, f)
	if err != nil {
		t.Fatal(err)
	}
	in.Health = func(context.Context, string) error { return nil }
	in.LookupHost = func(context.Context, string) ([]string, error) { return []string{"203.0.113.10"}, nil }
	env := &plan.Env{Host: s, Facts: f, HTTP: keyServer(t), Now: func() time.Time { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) }}
	var rec recorder
	if err := plan.Run(context.Background(), in.Steps(), env, rec.events); err != nil {
		t.Fatalf("install: %v\nnotes: %q", err, rec.notes)
	}
	return in, &rec
}

func TestInstallOnFreshServer(t *testing.T) {
	s := newFakeServer()
	f := noble()
	f.EUID = 0
	s.Files[DefaultInventory] = []byte("config = \"relay.toml\"\n[[host]]\naddress = \"relay1.example.org\"\n[[host]]\naddress = \"root@relay2.example.org\"\n")
	s.Modes[DefaultInventory] = 0o644
	in, rec := runInstall(t, s, f, Options{Email: "ops@example.org"})

	// Files, modes and owners.
	for path, want := range map[string]struct {
		mode  os.FileMode
		owner string
	}{
		GrafanaRepo.KeyringPath: {0o644, ""},
		GrafanaRepo.SourcesPath: {0o644, ""},
		PrometheusDefaults:      {0o644, ""},
		PrometheusToken:         {0o640, ""},
		PrometheusRules:         {0o640, ""},
		PrometheusConfig:        {0o640, ""},
		ServeConfigPath:         {0o600, MonitorUser},
		FleetUnitPath:           {0o644, ""},
		GrafanaINI:              {0o640, ""},
		GrafanaDatasource:       {0o640, ""},
		GrafanaProvider:         {0o640, ""},
		GrafanaDashboards + "/tor-fleet-overview.json": {0o640, ""},
		GrafanaDashboards + "/tor-fleet-relay.json":    {0o640, ""},
		AdminPasswordPath:                 {0o600, ""},
		Caddyfile:                         {0o644, ""},
		MonitorHome + "/.ssh/config":      {0o600, MonitorUser},
		MonitorHome + "/.ssh/known_hosts": {0o644, MonitorUser},
		StatePath:                         {0o600, ""},
	} {
		if _, ok := s.Files[path]; !ok {
			t.Errorf("%s not written", path)
			continue
		}
		if s.Modes[path] != want.mode || s.Owners[path] != want.owner {
			t.Errorf("%s: mode %o owner %q, want %o %q", path, s.Modes[path], s.Owners[path], want.mode, want.owner)
		}
	}
	if _, err := s.Stat(CaddyRepo.SourcesPath); err == nil {
		t.Error("noble has caddy; no Caddy repository expected")
	}
	// The token is shared: Prometheus gets it, serve.toml only its hash.
	token := strings.TrimSpace(string(s.Files[PrometheusToken]))
	serve := string(s.Files[ServeConfigPath])
	if !strings.Contains(serve, TokenSHA256(token)) || strings.Contains(serve, token) {
		t.Errorf("serve.toml and token do not match:\n%s", serve)
	}
	// The password is generated, stored root-only, given to grafana cli on
	// stdin only, and shown once.
	pw := strings.TrimSpace(string(s.Files[AdminPasswordPath]))
	if in.Password != pw || len(pw) != 32 || string(s.stdin["grafana"]) != pw+"\n" {
		t.Errorf("password %q / %q / stdin %q", in.Password, pw, s.stdin["grafana"])
	}
	for _, l := range s.CommandLines() {
		if strings.Contains(l, pw) || strings.Contains(l, token) {
			t.Errorf("secret on a command line: %s", l)
		}
	}
	for _, want := range [][]string{
		{"apt-get", "--no-install-recommends install prometheus grafana caddy openssh-client ufw"},
		{"ufw allow 22/tcp"}, {"ufw allow 2222/tcp"}, {"ufw allow 80/tcp"}, {"ufw allow 443/tcp"}, {"ufw --force enable"},
		{"useradd --system --user-group --home-dir /var/lib/tor-relay-monitor --create-home --shell /usr/sbin/nologin"},
		{"runuser -u tor-relay-monitor -- ssh-keygen -q -t ed25519 -N '' -C tor-relay-monitor@mgmt"},
		{"promtool check config"}, {"chown root:prometheus /etc/prometheus/tor-relay-fleet.token"},
		{"systemctl restart prometheus"}, {"systemctl daemon-reload"}, {"systemctl restart tor-relay-setup-fleet"},
		{"chown root:grafana /etc/grafana/grafana.ini"},
		{"runuser -u grafana -- /usr/share/grafana/bin/grafana cli --homepath /usr/share/grafana --config /etc/grafana/grafana.ini admin reset-admin-password --password-from-stdin"},
		{"systemctl restart grafana-server"}, {"caddy validate --adapter caddyfile"}, {"systemctl reload-or-restart caddy"},
	} {
		if !s.Ran(want...) {
			t.Errorf("did not run %q", want)
		}
	}
	if s.Ran("ufw allow 3000") || s.Ran("ufw allow 9090") || s.Ran("ufw allow 9850") {
		t.Error("an internal port was opened")
	}
	// Order: the Prometheus defaults exist before apt installs the package,
	// and the firewall is up before Grafana starts.
	lines := s.CommandLines()
	idx := func(sub string) int {
		return slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, sub) })
	}
	ok := idx("install prometheus") < idx("ufw --force enable") && idx("ufw --force enable") < idx("restart grafana-server") && idx("reset-admin-password") < idx("restart grafana-server")
	if !ok {
		t.Errorf("order wrong:\n%s", strings.Join(lines, "\n"))
	}
	if !slices.ContainsFunc(rec.notes, func(n string) bool { return strings.Contains(n, "root@relay2.example.org") }) {
		t.Errorf("no warning about the user@ inventory address: %q", rec.notes)
	}
	if in.PublicKey == "" || !strings.Contains(strings.Join(in.SummaryLines(), "\n"), "fleet authorize --key 'ssh-ed25519 AAAAC3") {
		t.Errorf("summary: %s", strings.Join(in.SummaryLines(), "\n"))
	}
	st, err := ReadState(s)
	if err != nil || st.Domain != "grafana.example.org" || !slices.Contains(st.NewPackages, "grafana") {
		t.Errorf("state %+v %v", st, err)
	}

	// A second run changes nothing and restarts nothing.
	before := len(s.Commands)
	in2, _ := runInstall(t, s, f, Options{Email: "ops@example.org"})
	for _, c := range s.Commands[before:] {
		l := c.String()
		if strings.Contains(l, "restart") || strings.Contains(l, "reset-admin-password") || strings.Contains(l, "ssh-keygen") || strings.Contains(l, "useradd") {
			t.Errorf("second run ran %s", l)
		}
	}
	if in2.Password != "" || strings.TrimSpace(string(s.Files[AdminPasswordPath])) != pw || strings.TrimSpace(string(s.Files[PrometheusToken])) != token {
		t.Error("second run replaced the password or token")
	}

	// --rotate-token replaces the token in both places and restarts both.
	before = len(s.Commands)
	runInstall(t, s, f, Options{Email: "ops@example.org", RotateToken: true})
	tok2 := strings.TrimSpace(string(s.Files[PrometheusToken]))
	if tok2 == token || !strings.Contains(string(s.Files[ServeConfigPath]), TokenSHA256(tok2)) {
		t.Error("token not rotated")
	}
	rest := strings.Join(s.CommandLines()[before:], "\n")
	if !strings.Contains(rest, "restart prometheus") || !strings.Contains(rest, "restart tor-relay-setup-fleet") {
		t.Errorf("rotation did not restart both:\n%s", rest)
	}
}

func TestInstallKeepsOperatorServeSettings(t *testing.T) {
	s := newFakeServer()
	f := noble()
	s.Files[ServeConfigPath] = []byte("listen = \"0.0.0.0:9850\"\nprivacy = true\n\n[[users]]\nname = \"alice\"\n")
	runInstall(t, s, f, Options{})
	got := string(s.Files[ServeConfigPath])
	if !strings.Contains(got, `listen = "127.0.0.1:9850"`) || !strings.Contains(got, "privacy = true") || !strings.Contains(got, "name = \"alice\"") || strings.Contains(got, "probe_interval") {
		t.Errorf("serve.toml:\n%s", got)
	}
	if _, ok := s.Files[ServeConfigPath+".bak.test"]; !ok {
		t.Error("no backup of serve.toml")
	}
}

func TestInstallJammyAddsCaddyRepo(t *testing.T) {
	s := newFakeServer()
	f := noble()
	f.Codename, f.VersionID, f.PrettyName = "jammy", "22.04", "Ubuntu 22.04"
	f.Firewall = system.Firewall{Kind: system.KindUFW, Active: true, Detail: system.DetailActive}
	runInstall(t, s, f, Options{FleetPath: ""})
	if !strings.Contains(string(s.Files[CaddyRepo.SourcesPath]), "dl.cloudsmith.io/public/caddy/stable") {
		t.Error("Caddy repository missing on jammy")
	}
	if s.Ran("ufw allow 22/tcp") || s.Ran("ufw --force enable") || !s.Ran("ufw allow 443/tcp") {
		t.Errorf("active ufw: %q", s.CommandLines())
	}
	if s.Ran("install prometheus grafana caddy openssh-client ufw") {
		t.Error("ufw installed although present")
	}
	if strings.Contains(string(s.Files[Caddyfile]), "9850") {
		t.Error("fleet UI published although disabled")
	}
}

func TestInstallRejectsDuplicateSource(t *testing.T) {
	s := newFakeServer()
	s.Files["/etc/apt/sources.list.d/grafana.list"] = []byte("deb [signed-by=/etc/apt/keyrings/grafana.asc] https://apt.grafana.com stable main\n")
	in, err := NewInstall(Options{Domain: "g.example.org", Executable: "/usr/local/bin/tor-relay-setup"}, noble())
	if err != nil {
		t.Fatal(err)
	}
	env := &plan.Env{Host: s, Facts: noble(), HTTP: keyServer(t), Now: time.Now}
	err = plan.Run(context.Background(), in.Steps()[:1], env, func(plan.Event) {})
	if err == nil || !strings.Contains(err.Error(), "grafana.list") {
		t.Errorf("err = %v", err)
	}
}

func TestInstallUnsupportedRelease(t *testing.T) {
	f := noble()
	f.Codename = "focal"
	if _, err := NewInstall(Options{Domain: "g.example.org"}, f); err == nil {
		t.Error("focal accepted")
	}
}

func TestInstallDryRun(t *testing.T) {
	s := newFakeServer()
	s.Dry = true
	f := noble()
	f.EUID = 1000
	in, _ := runInstall(t, s, f, Options{})
	if len(s.Files) != 0 {
		t.Errorf("dry run wrote %v", slices.Collect(func(yield func(string) bool) {
			for k := range s.Files {
				if !yield(k) {
					return
				}
			}
		}))
	}
	// Every change is planned in the review and recorded as a command.
	if len(plan.Changes(in.Steps())) < 15 || !s.Ran("useradd") || !s.Ran("apt-get") || !s.Ran("systemctl restart grafana-server") {
		t.Errorf("dry run commands: %q", s.CommandLines())
	}
}

func TestUninstall(t *testing.T) {
	s := newFakeServer()
	s.Files[FleetUnitPath] = []byte("unit")
	s.Files[ServeConfigPath] = []byte("x")
	s.Files["/var/lib/grafana/grafana.db"] = []byte("db")
	s.Dirs["/var/lib/grafana"] = true
	st := State{NewPackages: []string{"grafana", "openssh-client", "ufw", "caddy"}}
	env := &plan.Env{Host: s, Now: time.Now}
	if err := plan.Run(context.Background(), UninstallSteps(st, false), env, func(plan.Event) {}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Files[FleetUnitPath]; ok || s.Files[ServeConfigPath] == nil || !s.Ran("systemctl disable --now grafana-server") || s.Ran("apt-get") {
		t.Errorf("uninstall: %q", s.CommandLines())
	}
	s.users[MonitorUser] = true
	if err := plan.Run(context.Background(), UninstallSteps(st, true), env, func(plan.Event) {}); err != nil {
		t.Fatal(err)
	}
	if !s.Ran("apt-get", "purge grafana caddy") || s.Ran("purge", "ufw") || s.Ran("purge", "prometheus") || !s.Ran("userdel tor-relay-monitor") {
		t.Errorf("purge: %q", s.CommandLines())
	}
	if s.Files[ServeConfigPath] != nil || s.Files["/var/lib/grafana/grafana.db"] != nil {
		t.Error("purge kept data")
	}
}

// --- relay side: fleet authorize ---

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOu1fnVr0bHb0nbiU0pWj2uy8W5H8UuK4u3Dd3s4xR9a tor-relay-monitor@mgmt"

func TestParseEd25519Key(t *testing.T) {
	got, err := ParseEd25519Key("  " + testKey + "  ")
	if err != nil || got != testKey {
		t.Fatalf("%q %v", got, err)
	}
	if got, _ := ParseEd25519Key(strings.Replace(testKey, "@mgmt", `@mgmt",command="sh`, 1)); strings.Contains(got, "command") {
		t.Errorf("unsafe comment kept: %q", got)
	}
	for _, bad := range []string{
		"", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ x", "ssh-ed25519", "ssh-ed25519 !!!",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOu1fnVr0bHb0nbiU0pWj2uy8W5H8UuK4u3Dd3s4", // short key
		`command="sh" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOu1fnVr0bHb0nbiU0pWj2uy8W5H8UuK4u3Dd3s4xR9a`,
	} {
		if _, err := ParseEd25519Key(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestAuthorizeFiles(t *testing.T) {
	o := AuthorizeOptions{Keys: []string{testKey}, From: []string{"203.0.113.5", "2001:db8::/64"}, Binary: "/usr/local/bin/tor-relay-setup"}
	if err := o.Normalize(); err != nil {
		t.Fatal(err)
	}
	want := `restrict,command="sudo -n /usr/local/bin/tor-relay-setup fleet-probe",from="203.0.113.5,2001:db8::/64" ` + testKey
	if !strings.Contains(string(AuthorizedKeysFile(o)), want+"\n") {
		t.Errorf("authorized_keys:\n%s", AuthorizedKeysFile(o))
	}
	sudoers := string(SudoersFile(o.Binary))
	if !strings.Contains(sudoers, "tor-relay-probe ALL=(root) NOPASSWD: /usr/local/bin/tor-relay-setup fleet-probe\n") || !strings.Contains(sudoers, "env_reset") {
		t.Errorf("sudoers:\n%s", sudoers)
	}
	for _, bad := range []AuthorizeOptions{
		{Binary: "/usr/local/bin/tor-relay-setup"},
		{Keys: []string{testKey}, From: []string{"relay.example.org"}, Binary: "/usr/local/bin/tor-relay-setup"},
		{Keys: []string{testKey}, Binary: "tor-relay-setup"},
		{Keys: []string{testKey}, Binary: "/opt/my tools/tor-relay-setup"},
		{Keys: []string{testKey}, Binary: "/usr/bin/x", Name: "a b"},
	} {
		if err := bad.Normalize(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func authorizeEnv(s *fakeServer) *plan.Env {
	return &plan.Env{Host: s, Facts: system.Facts{EUID: 0}, Now: time.Now}
}

func TestAuthorizeSteps(t *testing.T) {
	s := newFakeServer()
	o := AuthorizeOptions{Keys: []string{testKey}, Binary: "/usr/local/bin/tor-relay-setup"}
	_ = o.Normalize()
	var rec recorder
	if err := plan.Run(context.Background(), AuthorizeSteps(o), authorizeEnv(s), rec.events); err != nil {
		t.Fatal(err)
	}
	if !s.Ran("stat -c '%u %a %n' /usr/local/bin/tor-relay-setup /usr/local/bin /usr/local /usr /") {
		t.Errorf("binary not checked: %q", s.CommandLines())
	}
	if !s.Ran("useradd --system --user-group --home-dir /var/lib/tor-relay-probe --no-create-home --shell /bin/sh --password '*'") {
		t.Errorf("user: %q", s.CommandLines())
	}
	if s.Owners[ProbeHome] != "" || s.Owners[ProbeSSHDir] != "" || s.Owners[ProbeAuthorizedKey] != "" {
		t.Error("probe user's home, .ssh and authorized_keys must belong to root")
	}
	if !s.Ran("visudo -c -q -f /etc/sudoers.d/tor-relay-setup-probe.new") || s.Modes[SudoersPath] != 0o440 {
		t.Errorf("sudoers: mode %o, %q", s.Modes[SudoersPath], s.CommandLines())
	}
	if _, ok := s.Files[sudoersCandidate]; ok {
		t.Error("candidate left behind")
	}
	// Again: the user exists, sudoers is unchanged and not re-validated.
	n := len(s.Commands)
	if err := plan.Run(context.Background(), AuthorizeSteps(o), authorizeEnv(s), rec.events); err != nil {
		t.Fatal(err)
	}
	for _, l := range s.CommandLines()[n:] {
		if strings.Contains(l, "useradd") || strings.Contains(l, "visudo") {
			t.Errorf("rerun ran %s", l)
		}
	}
	// --remove
	if err := plan.Run(context.Background(), AuthorizeSteps(AuthorizeOptions{Remove: true}), authorizeEnv(s), rec.events); err != nil {
		t.Fatal(err)
	}
	if s.Files[SudoersPath] != nil || s.Files[ProbeAuthorizedKey] != nil || !s.Ran("userdel tor-relay-probe") {
		t.Errorf("remove: %q", s.CommandLines())
	}
}

func TestAuthorizeRefusesWritableBinary(t *testing.T) {
	for _, out := range []string{
		"0 755 /usr/local/bin/tor-relay-setup\n1000 755 /usr/local/bin\n0 755 /usr/local\n0 755 /usr\n0 755 /\n",
		"0 775 /usr/local/bin/tor-relay-setup\n0 755 /usr/local/bin\n0 755 /usr/local\n0 755 /usr\n0 755 /\n",
	} {
		s := newFakeServer()
		next := s.Handler
		s.Handler = func(c host.Command) (host.Result, error) {
			if c.Name == "stat" {
				return host.Result{Output: out}, nil
			}
			return next(c)
		}
		o := AuthorizeOptions{Keys: []string{testKey}, Binary: "/usr/local/bin/tor-relay-setup"}
		_ = o.Normalize()
		err := plan.Run(context.Background(), AuthorizeSteps(o), authorizeEnv(s), func(plan.Event) {})
		if err == nil || !strings.Contains(err.Error(), "must belong to root") || s.Ran("useradd") {
			t.Errorf("stat %q: err %v", out, err)
		}
	}
}

func TestAuthorizeNeedsSudo(t *testing.T) {
	s := newFakeServer()
	delete(s.Paths, "sudo")
	o := AuthorizeOptions{Keys: []string{testKey}, Binary: "/usr/local/bin/tor-relay-setup"}
	_ = o.Normalize()
	if err := plan.Run(context.Background(), AuthorizeSteps(o), authorizeEnv(s), func(plan.Event) {}); err == nil || !strings.Contains(err.Error(), "apt install sudo") {
		t.Errorf("err = %v", err)
	}
}

func TestSSHDWarnings(t *testing.T) {
	s := newFakeServer()
	s.Handler = func(c host.Command) (host.Result, error) {
		if c.Name == "sshd" {
			return host.Result{Output: "allowusers admin\npubkeyauthentication yes\nauthorizedkeysfile /etc/ssh/keys/%u\n"}, nil
		}
		return host.Result{}, nil
	}
	var rec recorder
	sshdWarnings(context.Background(), s, reporterFunc(rec.events))
	if len(rec.notes) != 2 {
		t.Errorf("notes %q", rec.notes)
	}
}

type reporterFunc func(plan.Event)

func (f reporterFunc) Progress(float64, string) {}
func (f reporterFunc) Log(string)               {}
func (f reporterFunc) Note(l plan.Level, msg string) {
	f(plan.Event{Kind: plan.StepNote, Level: l, Text: msg})
}

func TestKnownHostsLine(t *testing.T) {
	s := newFakeServer()
	if KnownHostsLine(s, "relay1") != "" {
		t.Error("line without key")
	}
	s.Files[hostKeyPath] = []byte("ssh-ed25519 AAAAhost root@relay1\n")
	if got := KnownHostsLine(s, "relay1.example.org"); got != "relay1.example.org ssh-ed25519 AAAAhost" {
		t.Errorf("got %q", got)
	}
}
