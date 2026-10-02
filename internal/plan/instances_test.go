package plan

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// fakeFamilyKey returns a syntactically valid secret family key.
func fakeFamilyKey(fill byte) []byte {
	key := []byte(family.KeyHeader)
	for len(key) < 96 {
		key = append(key, fill)
	}
	return key
}

// namedSetup configures a second relay "relay2" on ORPort 9002.
func namedSetup() config.Setup {
	s := testSetup()
	s.Relay.Instance, s.Relay.ORPort, s.Relay.Nickname = "relay2", 9002, "TestRelay2"
	return s
}

// withDefaultRelay puts a running default-instance relay on the fake host.
func withDefaultRelay(f *host.Fake) {
	f.Files["/etc/tor/torrc"] = []byte("Nickname TestRelay\nORPort 9001\nMetricsPort 127.0.0.1:9035\nFamilyId " + strings.Repeat("A", 43) + "\n")
	f.Files["/var/lib/tor/keys/myfam.secret_family_key"] = fakeFamilyKey('a')
	f.Files["/var/lib/tor/keys/myfam.public_family_id"] = []byte(strings.Repeat("A", 43) + "\n")
}

func TestNamedInstanceDryRun(t *testing.T) {
	t.Parallel()
	_, client := newRepo(t, realKey(t), map[string]int{"bookworm": http.StatusOK})
	s := namedSetup()
	s.Relay.MetricsPort = true
	s.System.Tuning = true
	facts := testFacts()
	facts.EUID = 1000

	f := host.NewFake()
	f.Dry = true
	f.Paths["tor"] = true
	withDefaultRelay(f)
	before := len(f.Files)
	f.Handler = func(c host.Command) (host.Result, error) {
		if c.Mutates {
			t.Errorf("mutating command reached the handler during a dry run: %s", c)
		}
		if slices.Contains(c.Args, "--verify-config") {
			// Like real tor before tor-instance-create: the user is missing.
			return host.Result{Output: "[warn] Error setting configured user: _tor-relay2 not found\n", ExitCode: 1}, &host.ExitError{Command: c.String(), ExitCode: 1}
		}
		return host.Result{}, nil
	}
	steps := Build(s, facts)
	env := NewEnv(f, facts, s, "tor-relay-setup vtest")
	env.HTTP, env.Now = client, func() time.Time { return fixedNow }
	var rec safeRecorder
	if err := Run(context.Background(), steps, env, rec.emit); err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if len(f.Files) != before || len(f.Dirs) != 0 {
		t.Errorf("dry run changed the host: %v", keys(f.Files))
	}
	for _, want := range [][]string{
		{"tor-instance-create", "relay2"},
		{"ufw", "allow", "9002/tcp"},
		{"systemctl", "enable", "tor@relay2"},
		{"systemctl", "restart", "tor@relay2"},
		{"sysctl", "-e", "-p", TuningSysctlPath},
	} {
		if !f.Ran(want...) {
			t.Errorf("no recorded command matching %q; commands:\n%s", want, strings.Join(f.CommandLines(), "\n"))
		}
	}
	if f.Ran("tor@default") {
		t.Error("a named-instance apply touched tor@default")
	}
	if !containsSubstring(rec.notes(), "runs once tor-instance-create has created instance relay2") {
		t.Errorf("notes %q lack the deferred verification", rec.notes())
	}
	if got := env.Setup.Relay.MetricsAddress; got != "127.0.0.1:9036" {
		t.Errorf("MetricsAddress = %q, want the next free port after the default instance's 9035", got)
	}
	if !containsSubstring(rec.notes(), "1 other relay instance(s) on this server; configuring tor@relay2") {
		t.Errorf("notes %q lack the instance summary", rec.notes())
	}
}

func TestNamedInstanceSteps(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	f.Paths["tor"] = true
	withDefaultRelay(f)
	f.Files[relay.InstanceDefaultsTemplate] = []byte("User _tor-@@NAME@@\n")
	s := namedSetup()
	s.Relay.MetricsPort = true
	s.Family.Mode, s.Family.KeyName = "generate", "myfam"
	env := NewEnv(f, testFacts(), s, "p")
	env.Now = func() time.Time { return fixedNow }
	inst := env.Instance
	ctx := context.Background()

	// tor-instance-create runs when the instance does not exist yet.
	var rec safeRecorder
	if err := instanceStep(inst).Run(ctx, env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if !f.Ran("tor-instance-create relay2") {
		t.Fatalf("commands = %q", f.CommandLines())
	}

	// Preflight finds the default instance's key and shares it.
	shared, err := sharedFamily(f, s, OtherInstances(f, inst))
	if err != nil || shared == nil || shared.Instance != "default" || shared.Key.Name != "myfam" {
		t.Fatalf("sharedFamily = %+v, %v", shared, err)
	}
	env.SharedFamily = shared
	if err := familyStep(s).Run(ctx, env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if f.Ran("--keygen-family") {
		t.Error("a second family key was generated next to an existing one")
	}
	dst := "/var/lib/tor-instances/relay2/keys/myfam.secret_family_key"
	if string(f.Files[dst]) != string(fakeFamilyKey('a')) || f.Owners[dst] != "_tor-relay2" || f.Modes[dst] != 0o600 {
		t.Errorf("shared key at %s: owner %q mode %v", dst, f.Owners[dst], f.Modes[dst])
	}
	if env.FamilyID != strings.Repeat("A", 43) {
		t.Errorf("FamilyID = %q", env.FamilyID)
	}

	// The torrc goes to the instance's file, verified with its defaults.
	if err := torrcStep(s).Run(ctx, env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	torrc := string(f.Files["/etc/tor/instances/relay2/torrc"])
	for _, want := range []string{"ORPort 9002\n", "MetricsPort 127.0.0.1:9036\n", "FamilyId " + strings.Repeat("A", 43)} {
		if !strings.Contains(torrc, want) {
			t.Errorf("instance torrc lacks %q:\n%s", want, torrc)
		}
	}
	if !strings.Contains(string(f.Files["/etc/tor/torrc"]), "ORPort 9001") {
		t.Error("the default instance's torrc was touched")
	}
	verify := f.Commands[len(f.Commands)-1]
	if verify.Name != "tor" || verify.Args[0] != "--defaults-torrc" || !strings.Contains(verify.Args[1], "tor-instance-defaults-") {
		t.Errorf("verify command = %s", verify)
	}

	// A cancelled context ends the listener wait at once; only the unit
	// the commands name matters here.
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	if err := serviceStep(s).Run(stopped, env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if !f.Ran("systemctl enable tor@relay2") || !f.Ran("systemctl restart tor@relay2") {
		t.Errorf("commands = %q", f.CommandLines())
	}

	if err := stateStep().Run(ctx, env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Files["/var/lib/tor-relay-setup/state-relay2.json"]; !ok {
		t.Error("named instance state file missing")
	}

	// A re-run finds the instance and does not create it again.
	f.Commands = nil
	if err := instanceStep(inst).Run(ctx, env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if f.Ran("tor-instance-create") || !containsSubstring(rec.notes(), "already exists") {
		t.Errorf("re-run commands %q notes %q", f.CommandLines(), rec.notes())
	}
}

func TestPreflightWithOtherInstances(t *testing.T) {
	t.Parallel()
	famA := strings.Repeat("A", 43)
	tests := []struct {
		name     string
		setup    func(*config.Setup)
		host     func(*host.Fake)
		wantErr  string
		wantNote string
	}{
		{
			name:    "ORPort collision",
			setup:   func(s *config.Setup) { s.Relay.ORPort = 9001 },
			host:    withDefaultRelay,
			wantErr: "ORPort 9001 is already used by tor instance default (/etc/tor/torrc)",
		},
		{
			name: "MetricsPort is moved off a colliding port",
			setup: func(s *config.Setup) {
				s.Relay.MetricsPort = true
			},
			host: func(f *host.Fake) {
				withDefaultRelay(f)
				f.Files["/etc/tor/instances/relay3/torrc"] = []byte("ORPort 9003\nMetricsPort 127.0.0.1:9036\n")
				// relay2's own torrc still names a port relay3 took meanwhile.
				f.Files["/etc/tor/instances/relay2/torrc"] = []byte("ORPort 9002\nMetricsPort 127.0.0.1:9036\n")
			},
			wantNote: "2 other relay instance(s)",
		},
		{
			name:  "different family on the same server is refused",
			setup: func(s *config.Setup) { s.Family.Mode, s.Family.KeyName = "generate", "other" },
			host:  withDefaultRelay,
			wantErr: `tor instance default on this server already uses family key "myfam" (FamilyId ` + famA +
				`); all relays on one server must share one family: set the family key name to "myfam" to reuse it`,
		},
		{
			name:     "same family name is shared",
			setup:    func(s *config.Setup) { s.Family.Mode, s.Family.KeyName = "generate", "myfam" },
			host:     withDefaultRelay,
			wantNote: "is supported",
		},
		{
			name: "own key with the same name but different content is refused",
			setup: func(s *config.Setup) {
				s.Family.Mode, s.Family.KeyName = "generate", "myfam"
			},
			host: func(f *host.Fake) {
				withDefaultRelay(f)
				f.Files["/var/lib/tor-instances/relay2/keys/myfam.secret_family_key"] = fakeFamilyKey('b')
			},
			wantErr: `a family key named "myfam" already exists (/var/lib/tor-instances/relay2/keys/myfam.secret_family_key)`,
		},
		{
			name: "own copy of the shared key is fine on re-apply",
			setup: func(s *config.Setup) {
				s.Family.Mode, s.Family.KeyName = "generate", "myfam"
			},
			host: func(f *host.Fake) {
				withDefaultRelay(f)
				f.Files["/var/lib/tor-instances/relay2/keys/myfam.secret_family_key"] = fakeFamilyKey('a')
			},
			wantNote: "is supported",
		},
		{
			name: "more relays than the authorities accept per IPv4 address",
			host: func(f *host.Fake) {
				withDefaultRelay(f)
				for i := 3; i <= 10; i++ {
					f.Files["/etc/tor/instances/r"+strconv.Itoa(i)+"/torrc"] = []byte("ORPort " + strconv.Itoa(9010+i) + "\n")
				}
			},
			wantNote: "this server would run 10 relays, but the directory authorities list at most 8 per IPv4 address",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, client := newRepo(t, nil, map[string]int{"bookworm": http.StatusOK})
			s := namedSetup()
			if tt.setup != nil {
				tt.setup(&s)
			}
			f := host.NewFake()
			tt.host(f)
			env := NewEnv(f, testFacts(), s, "p")
			env.HTTP = client
			var rec safeRecorder
			err := Build(s, testFacts())[0].Run(context.Background(), env, stepReporter{rec: &rec})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("preflight = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("preflight = %v", err)
			}
			if !containsSubstring(rec.notes(), tt.wantNote) {
				t.Errorf("notes %q lack %q", rec.notes(), tt.wantNote)
			}
			if s.Relay.MetricsPort && env.Setup.Relay.MetricsAddress != "127.0.0.1:9037" {
				t.Errorf("MetricsAddress = %q, want 9037 (9035 and 9036 are taken)", env.Setup.Relay.MetricsAddress)
			}
		})
	}
}

func TestConflicts(t *testing.T) {
	t.Parallel()
	doc := relay.ParseDocument([]byte("ORPort 9001\nORPort [2001:db8::1]:443\nMetricsPort 127.0.0.1:9035\n"))
	others := []relay.InstanceConfig{{Instance: relay.DefaultInstance(), Doc: doc}}
	s := namedSetup()
	if err := Conflicts(s, others); err != nil {
		t.Errorf("Conflicts = %v for distinct ports", err)
	}
	s.Relay.ORPort = 443
	if err := Conflicts(s, others); err == nil || !strings.Contains(err.Error(), "ORPort 443 is already used by tor instance default") {
		t.Errorf("Conflicts = %v, want the IPv6 ORPort collision", err)
	}
	s.Relay.ORPort = 9002
	s.Relay.MetricsPort, s.Relay.MetricsAddress = true, "127.0.0.1:9035"
	if err := Conflicts(s, others); err == nil || !strings.Contains(err.Error(), "MetricsPort 9035 is already used") {
		t.Errorf("Conflicts = %v, want the MetricsPort collision", err)
	}
	if w := RelaysPerIPv4Warning(8); w != "" {
		t.Errorf("8 relays warned: %q", w)
	}
	if w := RelaysPerIPv4Warning(9); !strings.Contains(w, relay.RelaysPerIPv4URL) {
		t.Errorf("warning %q lacks the link", w)
	}
}

func TestResolveMetricsAddress(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	s := testSetup()
	if got := ResolveMetricsAddress(f, s); got != "" {
		t.Errorf("metrics off resolved to %q", got)
	}
	s.Relay.MetricsPort = true
	if got := ResolveMetricsAddress(f, s); got != "127.0.0.1:9035" {
		t.Errorf("default instance = %q", got)
	}
	f.Files["/etc/tor/torrc"] = []byte("ORPort 9001\nMetricsPort 127.0.0.1:9100\n")
	if got := ResolveMetricsAddress(f, s); got != "127.0.0.1:9100" {
		t.Errorf("default instance keeps its address: %q", got)
	}
	s = namedSetup()
	s.Relay.MetricsPort = true
	if got := ResolveMetricsAddress(f, s); got != "127.0.0.1:9036" {
		t.Errorf("named instance = %q", got)
	}
}

func TestStateFile(t *testing.T) {
	t.Parallel()
	r2, _ := relay.Named("relay2")
	if got := StateFile("/s", relay.DefaultInstance()); got != "/s/state.json" {
		t.Errorf("default = %q", got)
	}
	if got := StateFile("/s", r2); got != "/s/state-relay2.json" {
		t.Errorf("named = %q", got)
	}
}
