package plan

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/system"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

var fixedNow = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// repoServer imitates deb.torproject.org: it serves the signing key and a
// Release file per codename, and records every requested path.
type repoServer struct {
	mu      sync.Mutex
	paths   []string
	key     []byte
	release map[string]int // codename -> status; missing means 404
}

func (s *repoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()
	const base = "/torproject.org/"
	switch {
	case r.URL.Path == base+torproject.SigningKeyFingerprint+".asc":
		_, _ = w.Write(s.key)
	case strings.HasPrefix(r.URL.Path, base+"dists/") && strings.HasSuffix(r.URL.Path, "/Release"):
		codename := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, base+"dists/"), "/Release")
		code, ok := s.release[codename]
		if !ok {
			code = http.StatusNotFound
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte("Origin: TorProject\n"))
	default:
		http.NotFound(w, r)
	}
}

func (s *repoServer) requested() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.paths)
}

// rewriteTransport sends every request to the test server, whatever its URL.
type rewriteTransport struct{ target *url.URL }

func (rt rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme, r2.URL.Host, r2.Host = rt.target.Scheme, rt.target.Host, rt.target.Host
	return http.DefaultTransport.RoundTrip(r2)
}

func realKey(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "torproject", "testdata", "tor-signing-key.asc"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// newRepo starts a fake repository and returns it with a client routed to it.
func newRepo(t *testing.T, key []byte, release map[string]int) (*repoServer, *http.Client) {
	t.Helper()
	repo := &repoServer{key: key, release: release}
	srv := httptest.NewServer(repo)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return repo, &http.Client{Transport: rewriteTransport{target: u}, Timeout: 10 * time.Second}
}

// safeRecorder collects events; steps may report from several goroutines.
type safeRecorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *safeRecorder) emit(e Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *safeRecorder) notes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.events {
		if e.Kind == StepNote {
			out = append(out, e.Text)
		}
	}
	return out
}

func containsSubstring(list []string, sub string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.Contains(s, sub) })
}

// stepReporter adapts the recorder for calling a step's Run directly.
type stepReporter struct {
	rec  *safeRecorder
	step int
}

func (r stepReporter) Progress(p float64, d string) {
	r.rec.emit(Event{Kind: StepProgress, Step: r.step, Percent: p, Text: d})
}
func (r stepReporter) Log(line string) { r.rec.emit(Event{Kind: StepLog, Step: r.step, Text: line}) }
func (r stepReporter) Note(l Level, msg string) {
	r.rec.emit(Event{Kind: StepNote, Step: r.step, Level: l, Text: msg})
}

func TestFullDryRun(t *testing.T) {
	t.Parallel()
	repo, client := newRepo(t, realKey(t), map[string]int{"bookworm": http.StatusOK})

	s := testSetup()
	s.Relay.Mode, s.Exit.ProviderPermission, s.Exit.Unbound, s.Exit.LockResolvConf = "exit", true, true, true
	s.Relay.IPv6, s.Relay.MetricsPort = "2001:db8::1", true
	s.Family.Mode, s.Family.KeyName = "generate", "myfam"
	s.System.Hostname = "relay1"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	facts := testFacts()
	facts.Firewall.Kind, facts.Firewall.Active, facts.Firewall.Detail = "none", false, ""
	facts.EUID = 1000 // a dry run needs no root

	f := host.NewFake()
	f.Dry = true // like host.DryRun: mutating commands and writes are only recorded
	f.Handler = func(c host.Command) (host.Result, error) {
		if c.Mutates {
			t.Errorf("mutating command reached the handler during a dry run: %s", c)
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

	// Nothing on the (fake) machine changed.
	if len(f.Files) != 0 || len(f.Dirs) != 0 || len(f.Links) != 0 {
		t.Errorf("dry run changed the host: files %v dirs %v links %v", keys(f.Files), f.Dirs, f.Links)
	}

	// Every privileged action was still planned (recorded, not executed).
	for _, want := range [][]string{
		{"hostnamectl", "set-hostname", "relay1"},
		{"apt-get", "update"},
		{"apt-get", "install", "tor", "deb.torproject.org-keyring", "nyx", "unbound", "unattended-upgrades", "apt-listchanges", "ufw"},
		{"tor", "--keygen-family", "myfam"},
		{"systemctl", "enable", "--now", "unbound"},
		{"ufw", "allow", "22/tcp"},
		{"ufw", "allow", "9001/tcp"},
		{"ufw", "--force", "enable"},
		{"systemctl", "enable", "tor@default"},
		{"systemctl", "restart", "tor@default"},
	} {
		if !f.Ran(want...) {
			t.Errorf("no recorded command matching %q; commands:\n%s", want, strings.Join(f.CommandLines(), "\n"))
		}
	}
	for _, c := range f.Commands {
		if c.Name == "chattr" || c.Name == "getent" || slices.Contains(c.Args, "--verify-config") {
			t.Errorf("dry run ran %s, which only belongs to a real run", c)
		}
	}

	// Events: every step starts and finishes in order, nothing fails.
	rec.mu.Lock()
	events := slices.Clone(rec.events)
	rec.mu.Unlock()
	next := 0
	started := -1
	for _, e := range events {
		switch e.Kind {
		case StepStarted:
			if e.Step != next || started != -1 {
				t.Fatalf("step %d started out of order (expected %d)", e.Step, next)
			}
			started = e.Step
		case StepFinished:
			if e.Step != started {
				t.Fatalf("step %d finished without starting", e.Step)
			}
			started, next = -1, next+1
		case StepFailed:
			t.Fatalf("step %d failed: %v", e.Step, e.Err)
		case StepProgress:
			if e.Percent < 0 || e.Percent > 100 || e.Step != started {
				t.Errorf("progress event out of range or outside its step: %+v", e)
			}
		default:
			if e.Step != started {
				t.Errorf("event outside its step: %+v", e)
			}
		}
	}
	if next != len(steps) {
		t.Errorf("%d of %d steps finished", next, len(steps))
	}
	notes := rec.notes()
	for _, want := range []string{"is supported", "Signing key fingerprint verified", "tor --verify-config runs once tor is installed"} {
		if !containsSubstring(notes, want) {
			t.Errorf("notes %q lack %q", notes, want)
		}
	}

	// The repository was probed and the key downloaded over env.HTTP.
	paths := repo.requested()
	for _, want := range []string{"/torproject.org/dists/bookworm/Release", "/torproject.org/" + torproject.SigningKeyFingerprint + ".asc"} {
		if !slices.Contains(paths, want) {
			t.Errorf("repository requests %v lack %s", paths, want)
		}
	}

	// dpkg-query reported nothing installed, so every package counts as new.
	if want := Packages(s, facts); !slices.Equal(env.NewPackages, want) {
		t.Errorf("NewPackages = %v, want %v", env.NewPackages, want)
	}
	if env.FamilyID != "" {
		t.Errorf("FamilyID = %q, want empty in a dry run", env.FamilyID)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func selectSteps(t *testing.T, steps []Step, ids ...string) []Step {
	t.Helper()
	out := make([]Step, 0, len(ids))
	for _, id := range ids {
		out = append(out, findStep(t, steps, id))
	}
	return out
}

func TestRepositoryAndTorrcSteps(t *testing.T) {
	t.Parallel()
	_, client := newRepo(t, realKey(t), nil)
	s, facts := testSetup(), testFacts()
	const oldTorrc = "# hand-made torrc\nORPort 9001\n"

	var verified []string
	var mu sync.Mutex
	f := host.NewFake()
	f.Paths["tor"] = true
	f.Files["/etc/tor/torrc"] = []byte(oldTorrc)
	f.Handler = func(c host.Command) (host.Result, error) {
		if c.Name == "tor" && slices.Contains(c.Args, "--verify-config") {
			// Verify must see the candidate, not the live torrc.
			i := slices.Index(c.Args, "-f")
			if i < 0 || i+1 >= len(c.Args) {
				t.Errorf("tor verify without -f: %s", c)
				return host.Result{}, nil
			}
			data, err := os.ReadFile(c.Args[i+1])
			if err != nil {
				t.Errorf("candidate torrc unreadable: %v", err)
			}
			mu.Lock()
			verified = append(verified, string(data))
			mu.Unlock()
			return host.Result{Output: "Configuration was valid\n"}, nil
		}
		t.Errorf("unexpected command %s", c)
		return host.Result{}, nil
	}

	steps := selectSteps(t, Build(s, facts), "repository", "torrc")
	env := NewEnv(f, facts, s, "tor-relay-setup vtest")
	env.HTTP, env.Now = client, func() time.Time { return fixedNow }

	var rec safeRecorder
	if err := Run(context.Background(), steps, env, rec.emit); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	// The keyring is the dearmored, verified key.
	keyring := f.Files[torproject.KeyringPath]
	if len(keyring) == 0 || bytes.HasPrefix(keyring, []byte("-----BEGIN")) {
		t.Fatalf("keyring missing or still armored (%d bytes)", len(keyring))
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(keyring))
	if err != nil {
		t.Fatalf("keyring does not parse as a binary OpenPGP keyring: %v", err)
	}
	if len(entities) != 1 || strings.ToUpper(hex.EncodeToString(entities[0].PrimaryKey.Fingerprint)) != torproject.SigningKeyFingerprint {
		t.Errorf("keyring holds %d entities, want exactly the Tor Project key", len(entities))
	}
	if f.Modes[torproject.KeyringPath] != 0o644 {
		t.Errorf("keyring mode = %v, want 0644", f.Modes[torproject.KeyringPath])
	}
	if got := string(f.Files[torproject.SourcesPath]); got != string(torproject.Sources("bookworm")) {
		t.Errorf("sources = %q", got)
	}
	if !strings.Contains(string(f.Files[torproject.SourcesPath]), "Suites: bookworm\n") {
		t.Errorf("sources do not name the codename:\n%s", f.Files[torproject.SourcesPath])
	}

	// The torrc was verified, then written with a backup of the old one.
	want := string(s.RelayConfig(nil).Render("tor-relay-setup vtest", fixedNow))
	if got := string(f.Files["/etc/tor/torrc"]); got != want {
		t.Errorf("torrc =\n%s\nwant\n%s", got, want)
	}
	if got := string(f.Files["/etc/tor/torrc.bak.test"]); got != oldTorrc {
		t.Errorf("backup = %q, want the previous torrc", got)
	}
	mu.Lock()
	if len(verified) != 1 || verified[0] != want {
		t.Errorf("tor --verify-config saw %d candidates; want exactly the new torrc", len(verified))
	}
	mu.Unlock()
	if f.Ran("--defaults-torrc") {
		t.Error("used --defaults-torrc although the service defaults file is absent")
	}
	notes := rec.notes()
	for _, n := range []string{"Signing key fingerprint verified", "tor --verify-config accepted", "Previous torrc saved as /etc/tor/torrc.bak.test"} {
		if !containsSubstring(notes, n) {
			t.Errorf("notes %q lack %q", notes, n)
		}
	}
	if containsSubstring(notes, torproject.LegacySourcesPath) {
		t.Error("warned about a legacy source that does not exist")
	}

	// A second run changes nothing and makes no new backup.
	delete(f.Files, "/etc/tor/torrc.bak.test")
	var again safeRecorder
	if err := Run(context.Background(), steps, env, again.emit); err != nil {
		t.Fatalf("second Run() = %v", err)
	}
	if _, ok := f.Files["/etc/tor/torrc.bak.test"]; ok || containsSubstring(again.notes(), "Previous torrc") {
		t.Error("an unchanged torrc was backed up again")
	}
}

func TestTorrcStepVariants(t *testing.T) {
	t.Parallel()
	const oldTorrc = "ORPort 9001\n"
	tests := []struct {
		name     string
		prepare  func(f *host.Fake)
		handler  func(c host.Command) (host.Result, error)
		dry      bool
		wantErr  string
		wantCmd  []string
		wantNote string
		written  bool
	}{
		{
			name: "uses the service defaults like tor@default",
			prepare: func(f *host.Fake) {
				f.Paths["tor"] = true
				f.Files[relay.ServiceDefaultsTorrc] = []byte("User debian-tor\n")
			},
			wantCmd: []string{"tor", "--defaults-torrc", relay.ServiceDefaultsTorrc, "--RunAsDaemon", "0", "--verify-config"},
			written: true,
		},
		{
			name:    "tor rejects the torrc",
			prepare: func(f *host.Fake) { f.Paths["tor"] = true },
			handler: func(c host.Command) (host.Result, error) {
				out := "Mar 04 [notice] Tor 0.4.9\nMar 04 [warn] Failed to parse/validate config: Unknown option 'Bogus'.\n"
				return host.Result{Output: out, ExitCode: 1}, &host.ExitError{Command: c.String(), ExitCode: 1, Output: out}
			},
			wantErr: "Unknown option 'Bogus'",
		},
		{
			name:    "a real run needs tor",
			wantErr: "tor rejected the generated torrc",
		},
		{
			name:     "a dry run without tor only notes it",
			dry:      true,
			wantNote: "runs once tor is installed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := host.NewFake()
			f.Dry = tt.dry
			f.Files["/etc/tor/torrc"] = []byte(oldTorrc)
			if tt.prepare != nil {
				tt.prepare(f)
			}
			f.Handler = tt.handler
			s := testSetup()
			env := NewEnv(f, testFacts(), s, "p")
			env.Now = func() time.Time { return fixedNow }
			var rec safeRecorder
			err := torrcStep(s).Run(context.Background(), env, stepReporter{rec: &rec})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Run() = %v, want error containing %q", err, tt.wantErr)
				}
				if got := string(f.Files["/etc/tor/torrc"]); got != oldTorrc {
					t.Errorf("a rejected torrc replaced the live one:\n%s", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Run() = %v", err)
			}
			if tt.wantCmd != nil && !f.Ran(tt.wantCmd...) {
				t.Errorf("commands %q lack %q", f.CommandLines(), tt.wantCmd)
			}
			if tt.wantNote != "" && !containsSubstring(rec.notes(), tt.wantNote) {
				t.Errorf("notes %q lack %q", rec.notes(), tt.wantNote)
			}
			changed := string(f.Files["/etc/tor/torrc"]) != oldTorrc
			if changed != tt.written {
				t.Errorf("torrc written = %v, want %v", changed, tt.written)
			}
		})
	}
}

func TestTorrcStepRejectsInvalidSetup(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	s := testSetup()
	s.Relay.Nickname = "bad nick"
	env := NewEnv(f, testFacts(), s, "p")
	err := torrcStep(s).Run(context.Background(), env, stepReporter{rec: &safeRecorder{}})
	if err == nil || !strings.Contains(err.Error(), "Nickname") {
		t.Fatalf("Run() = %v, want a Nickname validation error", err)
	}
	if len(f.Commands) != 0 || len(f.Files) != 0 {
		t.Error("an invalid setup reached tor or the filesystem")
	}
}

func TestRepositoryStepFailures(t *testing.T) {
	t.Parallel()
	t.Run("wrong key", func(t *testing.T) {
		t.Parallel()
		_, client := newRepo(t, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot a key\n-----END PGP PUBLIC KEY BLOCK-----\n"), nil)
		f := host.NewFake()
		env := NewEnv(f, testFacts(), testSetup(), "p")
		env.HTTP = client
		err := Run(context.Background(), []Step{repositoryStep(testFacts())}, env, func(Event) {})
		if !errors.Is(err, torproject.ErrUnexpectedKey) || !errors.Is(err, ErrStopped) {
			t.Fatalf("Run() = %v, want ErrUnexpectedKey wrapped in ErrStopped", err)
		}
		if _, ok := f.Files[torproject.KeyringPath]; ok {
			t.Error("an unverified key was installed")
		}
	})
	t.Run("legacy source warns", func(t *testing.T) {
		t.Parallel()
		_, client := newRepo(t, realKey(t), nil)
		f := host.NewFake()
		f.Files[torproject.LegacySourcesPath] = []byte("deb https://deb.torproject.org/torproject.org bookworm main\n")
		env := NewEnv(f, testFacts(), testSetup(), "p")
		env.HTTP = client
		var rec safeRecorder
		if err := repositoryStep(testFacts()).Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
			t.Fatal(err)
		}
		if !containsSubstring(rec.notes(), torproject.LegacySourcesPath+" also exists") {
			t.Errorf("notes %q lack the legacy source warning", rec.notes())
		}
	})
}

func TestPreflight(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		setup    func(*config.Setup)
		facts    func(*system.Facts)
		dry      bool
		release  int
		wantErr  string
		wantNote string
	}{
		{name: "supported server", release: 200, wantNote: "Debian GNU/Linux 12 (bookworm) bookworm on amd64 is supported"},
		{name: "non-root real run", facts: func(f *system.Facts) { f.EUID = 1000 }, release: 200, wantErr: "run as root"},
		{name: "non-root dry run", facts: func(f *system.Facts) { f.EUID = 1000 }, dry: true, release: 200, wantNote: "is supported"},
		{name: "unsupported OS", facts: func(f *system.Facts) { f.OSID = "fedora" }, release: 200, wantErr: "unsupported OS"},
		{name: "unsupported architecture", facts: func(f *system.Facts) { f.Arch = "armhf" }, release: 200, wantErr: "architecture"},
		{name: "no systemd", facts: func(f *system.Facts) { f.Systemd = false }, release: 200, wantErr: "systemd"},
		{name: "full disk", facts: func(f *system.Facts) { f.DiskFreeMiB = 100 }, release: 200, wantErr: "only 100 MiB free"},
		{name: "unknown disk space is fine", facts: func(f *system.Facts) { f.DiskFreeMiB = 0 }, release: 200, wantNote: "is supported"},
		{
			name:  "low memory for an exit only warns",
			setup: func(s *config.Setup) { s.Relay.Mode, s.Exit.ProviderPermission = "exit", true },
			facts: func(f *system.Facts) { f.MemTotalMiB = 1024 }, release: 200,
			wantNote: "1024 MiB RAM is below Tor's recommended 1536 MiB",
		},
		{name: "suite not published", release: 404, wantErr: `does not publish "bookworm"`},
		{name: "repository error", release: 503, wantErr: "cannot reach deb.torproject.org"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, client := newRepo(t, nil, map[string]int{"bookworm": tt.release})
			s, facts := testSetup(), testFacts()
			if tt.setup != nil {
				tt.setup(&s)
			}
			if tt.facts != nil {
				tt.facts(&facts)
			}
			f := host.NewFake()
			f.Dry = tt.dry
			env := NewEnv(f, facts, s, "p")
			env.HTTP = client
			var rec safeRecorder
			err := Build(s, facts)[0].Run(context.Background(), env, stepReporter{rec: &rec})
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
		})
	}
}

func TestStateStep(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	env := NewEnv(f, testFacts(), testSetup(), "tor-relay-setup vtest")
	env.Now = func() time.Time { return fixedNow }
	env.NewPackages = []string{"tor", "nyx"}
	env.FamilyID = strings.Repeat("F", 43)
	if err := stateStep().Run(context.Background(), env, stepReporter{rec: &safeRecorder{}}); err != nil {
		t.Fatal(err)
	}
	if !f.Dirs["/var/lib/tor-relay-setup"] {
		t.Error("state directory not created")
	}
	data := f.Files["/var/lib/tor-relay-setup/state.json"]
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("state.json: %v\n%s", err, data)
	}
	if st.Version != "tor-relay-setup vtest" || !st.AppliedAt.Equal(fixedNow) || !slices.Equal(st.NewPackages, env.NewPackages) || st.FamilyID != env.FamilyID {
		t.Errorf("state = %+v", st)
	}
	if f.Modes["/var/lib/tor-relay-setup/state.json"] != 0o600 {
		t.Errorf("state.json mode = %v, want 0600", f.Modes["/var/lib/tor-relay-setup/state.json"])
	}
}
