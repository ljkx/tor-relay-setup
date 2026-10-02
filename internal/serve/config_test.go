package serve

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// cheapHash is an argon2id hash with small parameters, to keep tests fast.
func cheapHash(password string) string { return hashWith(password, 8*1024, 1, 1) }

func TestParseDefaults(t *testing.T) {
	c, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != DefaultListen || c.BasePath != "/" || c.ProbeInterval.Duration != 30*time.Second || c.TLS() || c.MetricsOpen() || c.Privacy {
		t.Errorf("defaults %+v", c)
	}
	if err := c.CheckListener(); err != nil {
		t.Errorf("default listener refused: %v", err)
	}
}

func TestParseFull(t *testing.T) {
	data := `
listen = "127.0.0.1:9900"
base_path = "/fleet"
inventory = "fleet.toml"
probe_interval = "1m"
privacy = true
metrics_auth = false
metrics_token_sha256 = "` + strings.ToUpper(TokenSum("x")) + `"
trusted_proxies = ["127.0.0.1", "10.0.0.0/8", "::1"]

[[users]]
name = "alice"
hash = "` + cheapHash("correct horse battery") + `"
`
	c, err := Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if c.BasePath != "/fleet/" || c.ProbeInterval.Duration != time.Minute || !c.Privacy || !c.MetricsOpen() || c.MetricsTokenSHA256 != TokenSum("x") ||
		len(c.Users) != 1 || len(c.TrustedProxies) != 3 {
		t.Errorf("config %+v", c)
	}
}

func TestParseRejects(t *testing.T) {
	good := cheapHash("correct horse battery")
	tests := map[string]string{
		`listen = "127.0.0.1"`:         "not host:port",
		`listen = "127.0.0.1:99999"`:   "port",
		`base_path = "fleet/"`:         "base_path",
		`base_path = "/a/../b/"`:       "base_path",
		`base_path = "/a b/"`:          "base_path",
		`probe_interval = "1s"`:        "probe_interval",
		`probe_interval = 30`:          "parse",
		`probe_interval = "soon"`:      "parse",
		`metrics_token_sha256 = "abc"`: "64 hex",
		`tls_cert = "/x.pem"`:          "go together",
		"acme_domains = [\"fleet.example.org\"]\ntls_cert = \"a\"\ntls_key = \"b\"":                                      "either",
		`acme_domains = ["not a domain"]`:                                                                                "not a DNS name",
		`acme_email = "ops@example.org"`:                                                                                 "need acme_domains",
		`acme_domains = ["fleet.example.org"]` + "\n" + `acme_cache = "rel"`:                                             "absolute",
		`trusted_proxies = ["proxy.local"]`:                                                                              "trusted_proxies",
		`unknown = 1`:                                                                                                    "unknown keys: unknown",
		"[[users]]\nname = \"alice\"\nhash = \"" + good + "\"\npassword = \"x\"":                                         "unknown keys: users.password",
		"[[users]]\nname = \"bad name\"\nhash = \"" + good + "\"":                                                        "name",
		"[[users]]\nname = \"a\"\nhash = \"" + good + "\"\n[[users]]\nname = \"A\"\nhash = \"" + good + "\"":             "twice",
		"[[users]]\nname = \"a\"\nhash = \"plaintext\"":                                                                  "PHC",
		"[[users]]\nname = \"a\"\nhash = \"$argon2id$v=19$m=4194304,t=3,p=4$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5\"": "memory",
	}
	for data, want := range tests {
		if _, err := Parse([]byte(data)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", data, err, want)
		}
	}
}

func TestLoadChecksPermissionsAndResolvesInventory(t *testing.T) {
	h := host.NewFake()
	path := "/etc/tor-relay-setup/serve.toml"
	if _, err := h.WriteFile(path, []byte("inventory = \"fleet.toml\"\n"), host.FileOptions{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(h, path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("world-readable config accepted: %v", err)
	}
	h.Modes[path] = 0o640
	if _, err := Load(h, path); err == nil {
		t.Error("group-readable config accepted")
	}
	h.Modes[path] = 0o600
	c, err := Load(h, path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Inventory != "/etc/tor-relay-setup/fleet.toml" || c.Path != path {
		t.Errorf("config %+v", c)
	}
	if _, err := Load(h, "/missing.toml"); err == nil {
		t.Error("missing file")
	}
}

func TestListenerRules(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:9850": true, "[::1]:9850": true, "localhost:9850": true, "127.0.0.53:1": true,
		":9850": false, "0.0.0.0:9850": false, "[::]:9850": false, "192.0.2.1:9850": false, "fleet.example.org:443": false, "bad": false,
	} {
		if Loopback(addr) != want {
			t.Errorf("Loopback(%q) = %v", addr, !want)
		}
	}
	c := Defaults()
	c.Listen = "0.0.0.0:9850"
	if err := c.CheckListener(); err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Errorf("plain HTTP on all interfaces: %v", err)
	}
	c.TLSCert, c.TLSKey = "/c.pem", "/k.pem"
	if err := c.CheckListener(); err != nil {
		t.Errorf("TLS on all interfaces: %v", err)
	}
	off := false
	c.MetricsAuth = &off
	if err := c.CheckListener(); err == nil || !strings.Contains(err.Error(), "metrics_auth") {
		t.Errorf("open metrics on all interfaces: %v", err)
	}
	c.Listen = "127.0.0.1:9850"
	if err := c.CheckListener(); err != nil {
		t.Errorf("open metrics on loopback: %v", err)
	}
}

const sample = `# fleet serve
listen = "127.0.0.1:9850" # loopback only
# metrics_token_sha256 = "set by fleet serve token"

[[users]]
# the operator
name = "alice"
hash = "OLD"

[[users]]
name = "bob"
`

func TestSetTokenAndUserKeepTheFile(t *testing.T) {
	sum := TokenSum("t")
	out, err := SetToken([]byte(strings.Replace(sample, `hash = "OLD"`, `hash = "`+cheapHash("correct horse battery")+`"`, 1)+`hash = "`+cheapHash("another password!")+`"`+"\n"), sum)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "# fleet serve\n") || !strings.Contains(s, "# metrics_token_sha256 = \"set by fleet serve token\"\n"+`metrics_token_sha256 = "`+sum+`"`+"\n\n[[users]]") {
		t.Errorf("token inserted badly:\n%s", s)
	}
	// Replacing it again changes the line in place.
	sum2 := TokenSum("u")
	out2, err := SetToken(out, sum2)
	if err != nil || strings.Contains(string(out2), sum) || strings.Count(string(out2), "\nmetrics_token_sha256 = ") != 1 {
		t.Errorf("second token:\n%s (%v)", out2, err)
	}

	alice := cheapHash("a new password!!")
	out3, err := SetUser(out2, "ALICE", alice)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := Parse(out3)
	if c.Users[0].Hash != alice || !strings.Contains(string(out3), "# the operator\nname = \"alice\"\nhash = \""+alice) {
		t.Errorf("alice:\n%s", out3)
	}
	carol := cheapHash("carols password")
	out4, err := SetUser(out3, "carol", carol)
	if err != nil {
		t.Fatal(err)
	}
	c, _ = Parse(out4)
	if len(c.Users) != 3 || c.Users[2].Name != "carol" || c.Users[2].Hash != carol || c.MetricsTokenSHA256 != sum2 {
		t.Errorf("carol: %+v\n%s", c, out4)
	}

	// A user entry without a hash line gets one.
	out5, err := SetUser([]byte("[[users]]\nname = \"dave\"\n"), "dave", carol)
	if err != nil || !strings.Contains(string(out5), "name = \"dave\"\nhash = \""+carol) {
		t.Errorf("dave:\n%s (%v)", out5, err)
	}
	// Starting from nothing.
	out6, err := SetUser([]byte(starter), "erin", carol)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := Parse(out6); err != nil || len(c.Users) != 1 || c.Inventory == "" {
		t.Errorf("starter: %+v %v", c, err)
	}
	// A broken file is never "fixed" by an edit.
	if _, err := SetToken([]byte("listen = [\n"), sum); err == nil {
		t.Error("edited a file that does not parse")
	}
}

func TestWriteAndReadConfigFile(t *testing.T) {
	h := host.NewFake()
	path := "/etc/tor-relay-setup/serve.toml"
	data, err := ReadConfigFile(h, path)
	if err != nil || string(data) != starter {
		t.Fatalf("missing file: %q %v", data, err)
	}
	if err := WriteConfig(h, path, []byte("x = 1\n")); err != nil {
		t.Fatal(err)
	}
	if h.Modes[path] != 0o600 || !h.Dirs["/etc/tor-relay-setup"] || h.Modes["/etc/tor-relay-setup"].Perm() != 0o750 {
		t.Errorf("modes %v dirs %v", h.Modes, h.Dirs)
	}
	h.Modes[path] = 0o644
	if _, err := ReadConfigFile(h, path); err == nil {
		t.Error("readable file accepted for an edit")
	}
	// An existing directory keeps its permissions.
	h2 := host.NewFake()
	h2.Dirs["/etc/tor-relay-setup"] = true
	if err := WriteConfig(h2, path, []byte("x")); err != nil || h2.Modes["/etc/tor-relay-setup"] != 0 {
		t.Errorf("existing directory changed: %v %v", h2.Modes, err)
	}
}

func TestExampleConfigParses(t *testing.T) {
	data, err := os.ReadFile("../../docs/examples/serve.toml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != DefaultListen || c.Inventory != "fleet.toml" || len(c.TrustedProxies) != 2 || c.CheckListener() != nil {
		t.Errorf("example %+v", c)
	}
}
