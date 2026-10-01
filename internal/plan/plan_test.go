package plan

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

// testSetup is a valid guard relay with every default left in place.
func testSetup() config.Setup {
	s := config.Default()
	s.Relay.Nickname = "TestRelay"
	s.Relay.Contact = "tor-ops@example.org"
	s.Bandwidth.MonthlyQuota = "10TB"
	return s
}

// testFacts describes a supported Debian server with an active ufw.
func testFacts() system.Facts {
	return system.Facts{
		OSID: "debian", VersionID: "12", Codename: "bookworm", PrettyName: "Debian GNU/Linux 12 (bookworm)",
		Arch: "amd64", Hostname: "old-host", MemTotalMiB: 4096, DiskFreeMiB: 20000, Systemd: true,
		SSHPorts: []int{22}, Firewall: system.Firewall{Kind: system.KindUFW, Active: true, Detail: system.DetailActive},
	}
}

func stepIDs(steps []Step) []string {
	ids := make([]string, len(steps))
	for i, s := range steps {
		ids[i] = s.ID
	}
	return ids
}

func findStep(t *testing.T, steps []Step, id string) Step {
	t.Helper()
	for _, s := range steps {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no %q step in %v", id, stepIDs(steps))
	return Step{}
}

func TestBuildStepOrder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		setup      func(*config.Setup)
		facts      func(*system.Facts)
		want       []string
		wantTitle  map[string]string // step ID -> substring of its title
		wantChange []string          // substrings expected somewhere in Changes()
		noChange   []string          // substrings that must not appear in Changes()
	}{
		{
			name: "guard minimal",
			setup: func(s *config.Setup) {
				s.System.UnattendedUpgrades, s.System.Firewall = false, "none"
			},
			want: []string{"preflight", "repository", "update", "packages", "torrc", "service", "state"},
		},
		{
			name: "guard defaults with active ufw",
			want: []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"},
			wantTitle: map[string]string{
				"firewall": "Open ORPort 9001 in ufw",
				"packages": "Install tor, deb.torproject.org-keyring, nyx, unattended-upgrades, apt-listchanges",
			},
			wantChange: []string{"ufw allow 9001/tcp comment 'Tor relay ORPort'"},
			noChange:   []string{"SSH", "--force enable"},
		},
		{
			name: "exit with unbound",
			setup: func(s *config.Setup) {
				s.Relay.Mode, s.Exit.ProviderPermission, s.Exit.Unbound, s.Exit.LockResolvConf = "exit", true, true, true
			},
			want:       []string{"preflight", "repository", "update", "packages", "exit-dns", "unattended", "torrc", "firewall", "service", "state"},
			wantChange: []string{"Enable Unbound", "chattr +i", "unbound"},
		},
		{
			name: "exit without unbound",
			setup: func(s *config.Setup) {
				s.Relay.Mode, s.Exit.ProviderPermission, s.Exit.Unbound = "exit", true, false
			},
			want:     []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"},
			noChange: []string{"Unbound"},
		},
		{
			name:       "family generate",
			setup:      func(s *config.Setup) { s.Family.Mode, s.Family.KeyName = "generate", "myfam" },
			want:       []string{"preflight", "repository", "update", "packages", "family", "unattended", "torrc", "firewall", "service", "state"},
			wantTitle:  map[string]string{"family": "Create relay family key myfam"},
			wantChange: []string{"tor --keygen-family"},
		},
		{
			name: "family import",
			setup: func(s *config.Setup) {
				s.Family.Mode, s.Family.ImportKey = "import", "/root/fam.secret_family_key"
			},
			want:       []string{"preflight", "repository", "update", "packages", "family", "unattended", "torrc", "firewall", "service", "state"},
			wantTitle:  map[string]string{"family": "Import relay family key"},
			wantChange: []string{"Install family key /root/fam.secret_family_key for debian-tor"},
		},
		{
			name:       "hostname change",
			setup:      func(s *config.Setup) { s.System.Hostname = "relay1" },
			want:       []string{"preflight", "hostname", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"},
			wantTitle:  map[string]string{"hostname": "Set hostname to relay1"},
			wantChange: []string{"Set the hostname to relay1 and update /etc/hosts"},
		},
		{
			name:  "hostname unchanged",
			setup: func(s *config.Setup) { s.System.Hostname = "old-host" },
			want:  []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"},
		},
		{
			name:  "firewall none leaves ufw alone",
			setup: func(s *config.Setup) { s.System.Firewall = "none" },
			facts: func(f *system.Facts) { f.Firewall = system.Firewall{Kind: system.KindNone} },
			want:  []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "service", "state"},
		},
		{
			name: "auto with inactive ufw allows SSH first and enables",
			facts: func(f *system.Facts) {
				f.Firewall = system.Firewall{Kind: system.KindUFW, Detail: system.DetailInactive}
				f.SSHPorts = []int{22, 2222}
			},
			want:       []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"},
			wantChange: []string{"ufw allow 22/tcp comment SSH", "ufw allow 2222/tcp comment SSH", "ufw --force enable"},
		},
		{
			name:  "auto with inactive ufw without enabling",
			setup: func(s *config.Setup) { s.System.EnableUFW = false },
			facts: func(f *system.Facts) {
				f.Firewall = system.Firewall{Kind: system.KindUFW, Detail: system.DetailInactive}
			},
			want:       []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"},
			wantChange: []string{"ufw allow 22/tcp comment SSH"},
			noChange:   []string{"--force enable"},
		},
		{
			name:       "auto without any firewall installs ufw",
			facts:      func(f *system.Facts) { f.Firewall = system.Firewall{Kind: system.KindNone, Detail: system.DetailNone} },
			want:       []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"},
			wantTitle:  map[string]string{"firewall": "in ufw", "packages": "ufw"},
			wantChange: []string{"ufw allow 22/tcp comment SSH", "ufw --force enable", "apt-listchanges ufw"},
		},
		{
			name: "inactive firewalld is left alone",
			facts: func(f *system.Facts) {
				f.Firewall = system.Firewall{Kind: system.KindFirewalld, Detail: system.DetailInactive}
			},
			want: []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "service", "state"},
		},
		{
			name: "active firewalld gets a port",
			facts: func(f *system.Facts) {
				f.Firewall = system.Firewall{Kind: system.KindFirewalld, Active: true, Detail: system.DetailActive}
			},
			want:       []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"},
			wantChange: []string{"firewall-cmd --permanent --add-port=9001/tcp", "firewall-cmd --reload"},
		},
		{
			name: "nftables with an input chain",
			facts: func(f *system.Facts) {
				f.Firewall = system.Firewall{Kind: system.KindNFTables, Active: true, Detail: system.DetailNFTChainFound}
			},
			want:       []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"},
			wantChange: []string{"nft add rule inet filter input tcp dport 9001 accept"},
		},
		{
			name: "nftables without an input chain",
			facts: func(f *system.Facts) {
				f.Firewall = system.Firewall{Kind: system.KindNFTables, Detail: system.DetailNFTNoChain}
			},
			want: []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "service", "state"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, f := testSetup(), testFacts()
			if tt.setup != nil {
				tt.setup(&s)
			}
			if tt.facts != nil {
				tt.facts(&f)
			}
			steps := Build(s, f)
			if got := stepIDs(steps); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Build() step IDs = %v\nwant %v", got, tt.want)
			}
			for _, st := range steps {
				if st.Title == "" || st.Weight <= 0 || st.Run == nil {
					t.Errorf("step %q is incomplete: title %q weight %v run %v", st.ID, st.Title, st.Weight, st.Run != nil)
				}
			}
			for id, want := range tt.wantTitle {
				if got := findStep(t, steps, id).Title; !strings.Contains(got, want) {
					t.Errorf("step %q title = %q, want it to contain %q", id, got, want)
				}
			}
			changes := strings.Join(Changes(steps), "\n")
			for _, want := range tt.wantChange {
				if !strings.Contains(changes, want) {
					t.Errorf("Changes() missing %q:\n%s", want, changes)
				}
			}
			for _, bad := range tt.noChange {
				if strings.Contains(changes, bad) {
					t.Errorf("Changes() unexpectedly contains %q:\n%s", bad, changes)
				}
			}
		})
	}
}

func TestPackages(t *testing.T) {
	t.Parallel()
	base := []string{"tor", "deb.torproject.org-keyring"}
	tests := []struct {
		name  string
		setup func(*config.Setup)
		facts func(*system.Facts)
		want  []string
	}{
		{"defaults", nil, nil, append(base, "nyx", "unattended-upgrades", "apt-listchanges")},
		{"bare", func(s *config.Setup) { s.System.Nyx, s.System.UnattendedUpgrades = false, false }, nil, base},
		{"exit with unbound", func(s *config.Setup) {
			s.Relay.Mode, s.System.Nyx, s.System.UnattendedUpgrades = "exit", false, false
		}, nil, append(base, "unbound")},
		{"guard never gets unbound", func(s *config.Setup) {
			s.Exit.Unbound, s.System.Nyx, s.System.UnattendedUpgrades = true, false, false
		}, nil, base},
		{"exit without unbound", func(s *config.Setup) {
			s.Relay.Mode, s.Exit.Unbound, s.System.Nyx, s.System.UnattendedUpgrades = "exit", false, false, false
		}, nil, base},
		{"ufw installed when no firewall exists", func(s *config.Setup) {
			s.System.Nyx, s.System.UnattendedUpgrades = false, false
		}, func(f *system.Facts) { f.Firewall = system.Firewall{Kind: system.KindNone} }, append(base, "ufw")},
		{"unknown firewall kind also installs ufw", nil, func(f *system.Facts) { f.Firewall = system.Firewall{} },
			append(base, "nyx", "unattended-upgrades", "apt-listchanges", "ufw")},
		{"no ufw when firewall is left alone", func(s *config.Setup) {
			s.System.Firewall, s.System.Nyx, s.System.UnattendedUpgrades = "none", false, false
		}, func(f *system.Facts) { f.Firewall = system.Firewall{Kind: system.KindNone} }, base},
		{"everything", func(s *config.Setup) { s.Relay.Mode = "exit" },
			func(f *system.Facts) { f.Firewall = system.Firewall{Kind: system.KindNone} },
			append(base, "nyx", "unbound", "unattended-upgrades", "apt-listchanges", "ufw")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, f := testSetup(), testFacts()
			if tt.setup != nil {
				tt.setup(&s)
			}
			if tt.facts != nil {
				tt.facts(&f)
			}
			if got := Packages(s, f); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Packages() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHostsFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, old, host, want string
	}{
		{
			name: "replaces the 127.0.1.1 line",
			old:  "127.0.0.1\tlocalhost\n127.0.1.1\told-host\n::1\tlocalhost ip6-localhost\n",
			host: "relay1",
			want: "127.0.0.1\tlocalhost\n127.0.1.1\trelay1\n::1\tlocalhost ip6-localhost\n",
		},
		{
			name: "replaces a space-separated line with aliases",
			old:  "127.0.0.1 localhost\n127.0.1.1   old.example.org old\n",
			host: "relay1",
			want: "127.0.0.1 localhost\n127.0.1.1\trelay1\n",
		},
		{
			name: "appends when absent",
			old:  "127.0.0.1\tlocalhost\n",
			host: "relay1",
			want: "127.0.0.1\tlocalhost\n127.0.1.1\trelay1\n",
		},
		{
			name: "appends after a missing final newline",
			old:  "127.0.0.1\tlocalhost",
			host: "relay1",
			want: "127.0.0.1\tlocalhost\n127.0.1.1\trelay1\n",
		},
		{
			name: "empty input gets a complete file",
			old:  "",
			host: "relay1",
			want: "127.0.0.1\tlocalhost\n127.0.1.1\trelay1\n::1\tlocalhost ip6-localhost ip6-loopback\n",
		},
		{
			name: "FQDN adds the short name",
			old:  "127.0.1.1 old\n",
			host: "relay1.example.org",
			want: "127.0.1.1\trelay1.example.org relay1\n",
		},
		{
			name: "FQDN in an empty file",
			old:  "",
			host: "relay1.example.org",
			want: "127.0.0.1\tlocalhost\n127.0.1.1\trelay1.example.org relay1\n::1\tlocalhost ip6-localhost ip6-loopback\n",
		},
		{
			name: "multiple 127.0.1.1 lines collapse into the first",
			old:  "127.0.0.1 localhost\n127.0.1.1 a\n10.0.0.1 db\n127.0.1.1 b\n\t127.0.1.1 c\n",
			host: "relay1",
			want: "127.0.0.1 localhost\n127.0.1.1\trelay1\n10.0.0.1 db\n",
		},
		{
			name: "comments mentioning 127.0.1.1 stay",
			old:  "# 127.0.1.1 is the Debian hostname entry\n127.0.0.1 localhost\n",
			host: "relay1",
			want: "# 127.0.1.1 is the Debian hostname entry\n127.0.0.1 localhost\n127.0.1.1\trelay1\n",
		},
		{
			name: "last line without newline is replaced",
			old:  "127.0.0.1 localhost\n127.0.1.1 old",
			host: "relay1",
			want: "127.0.0.1 localhost\n127.0.1.1\trelay1\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := string(HostsFile([]byte(tt.old), tt.host))
			if got != tt.want {
				t.Errorf("HostsFile(%q, %q) =\n%q\nwant\n%q", tt.old, tt.host, got, tt.want)
			}
			// Applying the same hostname again is a no-op.
			if again := string(HostsFile([]byte(got), tt.host)); again != got {
				t.Errorf("HostsFile is not idempotent:\n%q\n%q", got, again)
			}
		})
	}
}

// recorder collects events from Run.
type recorder struct{ events []Event }

func (r *recorder) emit(e Event) { r.events = append(r.events, e) }

func (r *recorder) kinds() []EventKind {
	out := make([]EventKind, len(r.events))
	for i, e := range r.events {
		out[i] = e.Kind
	}
	return out
}

func TestRunStopsAtFirstFailure(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	var ran []string
	steps := []Step{
		{ID: "one", Title: "First", Weight: 1, Run: func(ctx context.Context, e *Env, r Reporter) error {
			ran = append(ran, "one")
			r.Progress(50, "halfway")
			r.Log("a log line")
			r.Note(Success, "worked")
			return nil
		}},
		{ID: "two", Title: "Second", Weight: 1, Run: func(ctx context.Context, e *Env, r Reporter) error {
			ran = append(ran, "two")
			return boom
		}},
		{ID: "three", Title: "Third", Weight: 1, Run: func(ctx context.Context, e *Env, r Reporter) error {
			ran = append(ran, "three")
			return nil
		}},
	}
	var rec recorder
	err := Run(context.Background(), steps, NewEnv(host.NewFake(), testFacts(), testSetup(), "test"), rec.emit)
	if !errors.Is(err, ErrStopped) || !errors.Is(err, boom) {
		t.Fatalf("Run() = %v, want an error wrapping ErrStopped and the step error", err)
	}
	if !strings.Contains(err.Error(), `"Second"`) {
		t.Errorf("Run() error %q does not name the failing step", err)
	}
	if !reflect.DeepEqual(ran, []string{"one", "two"}) {
		t.Errorf("steps run = %v, want [one two]", ran)
	}
	wantKinds := []EventKind{StepStarted, StepProgress, StepLog, StepNote, StepFinished, StepStarted, StepFailed}
	if got := rec.kinds(); !reflect.DeepEqual(got, wantKinds) {
		t.Fatalf("event kinds = %v, want %v", got, wantKinds)
	}
	ev := rec.events
	if ev[0].Step != 0 || ev[0].Text != "First" {
		t.Errorf("first StepStarted = %+v", ev[0])
	}
	if ev[1].Percent != 50 || ev[1].Text != "halfway" || ev[1].Step != 0 {
		t.Errorf("progress event = %+v", ev[1])
	}
	if ev[2].Text != "a log line" || ev[3].Level != Success || ev[3].Text != "worked" {
		t.Errorf("log/note events = %+v / %+v", ev[2], ev[3])
	}
	if ev[5].Step != 1 || ev[5].Text != "Second" {
		t.Errorf("second StepStarted = %+v", ev[5])
	}
	if f := ev[6]; f.Step != 1 || !errors.Is(f.Err, boom) || f.Text != "boom" || f.Elapsed < 0 {
		t.Errorf("StepFailed = %+v", f)
	}
}

func TestRunSucceeds(t *testing.T) {
	t.Parallel()
	steps := []Step{
		{Title: "a", Run: func(context.Context, *Env, Reporter) error { return nil }},
		{Title: "b", Run: func(context.Context, *Env, Reporter) error { return nil }},
	}
	var rec recorder
	if err := Run(context.Background(), steps, &Env{}, rec.emit); err != nil {
		t.Fatal(err)
	}
	want := []EventKind{StepStarted, StepFinished, StepStarted, StepFinished}
	if got := rec.kinds(); !reflect.DeepEqual(got, want) {
		t.Errorf("event kinds = %v, want %v", got, want)
	}
	if err := Run(context.Background(), nil, &Env{}, rec.emit); err != nil {
		t.Errorf("Run(no steps) = %v", err)
	}
}

func TestRunStopsWhenCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secondRan := false
	steps := []Step{
		{Title: "cancel", Run: func(context.Context, *Env, Reporter) error { cancel(); return nil }},
		{Title: "never", Run: func(context.Context, *Env, Reporter) error { secondRan = true; return nil }},
	}
	var rec recorder
	err := Run(ctx, steps, &Env{}, rec.emit)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context.Canceled", err)
	}
	if secondRan {
		t.Error("a step ran after cancellation")
	}
	if got := rec.kinds(); !reflect.DeepEqual(got, []EventKind{StepStarted, StepFinished}) {
		t.Errorf("event kinds = %v", got)
	}
}

func TestChanges(t *testing.T) {
	t.Parallel()
	steps := []Step{
		{Changes: []string{"a", "b"}},
		{},
		{Changes: []string{"c"}},
	}
	if got := Changes(steps); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("Changes() = %v", got)
	}
	if got := Changes(nil); got != nil {
		t.Errorf("Changes(nil) = %v, want nil", got)
	}

	built := Build(testSetup(), testFacts())
	var want []string
	for _, s := range built {
		want = append(want, s.Changes...)
	}
	if got := Changes(built); !slices.Equal(got, want) || len(got) == 0 {
		t.Errorf("Changes(Build()) = %v, want %v", got, want)
	}
}
