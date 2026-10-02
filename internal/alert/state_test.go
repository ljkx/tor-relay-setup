package alert

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

func TestPlanTransitions(t *testing.T) {
	cfg := DefaultConfig() // warning and up, remind every 24h
	down := Alert{ID: "service-inactive", Severity: Critical, Title: "tor@default is not running", Body: "b"}
	keyWarn := Alert{ID: "family-key-missing", Severity: Warning, Title: "family key missing", Body: "b"}
	info := Alert{ID: "metricsport-down", Severity: Info, Title: "the MetricsPort does not answer", Body: "b"}
	t0 := testNow

	type step struct {
		at      time.Duration
		alerts  []Alert
		unknown []string
		want    []string // "status id"
	}
	tests := []struct {
		name  string
		cfg   func(*Config)
		steps []step
	}{
		{
			name: "appear, stay quiet, remind, resolve",
			steps: []step{
				{0, []Alert{down}, nil, []string{"firing service-inactive"}},
				{5 * time.Minute, []Alert{down}, nil, nil},
				{23 * time.Hour, []Alert{down}, nil, nil},
				{24 * time.Hour, []Alert{down}, nil, []string{"reminder service-inactive"}},
				{24*time.Hour + 5*time.Minute, []Alert{down}, nil, nil},
				{25 * time.Hour, nil, nil, []string{"resolved service-inactive"}},
				{26 * time.Hour, nil, nil, nil},
			},
		},
		{
			name: "no reminders with remind_every 0",
			cfg:  func(c *Config) { c.RemindEvery.Duration = 0 },
			steps: []step{
				{0, []Alert{keyWarn}, nil, []string{"firing family-key-missing"}},
				{48 * time.Hour, []Alert{keyWarn}, nil, nil},
			},
		},
		{
			name: "below min_severity is tracked but never sent",
			steps: []step{
				{0, []Alert{info}, nil, nil},
				{48 * time.Hour, []Alert{info}, nil, nil},
				{49 * time.Hour, nil, nil, nil},
			},
		},
		{
			name: "info is sent when min_severity is info",
			cfg:  func(c *Config) { c.MinSeverity = Info },
			steps: []step{
				{0, []Alert{info}, nil, []string{"firing metricsport-down"}},
				{time.Hour, nil, nil, []string{"resolved metricsport-down"}},
			},
		},
		{
			name: "escalation fires again",
			steps: []step{
				{0, []Alert{{ID: "overload-oom", Severity: Info, Title: "t", Body: "b"}}, nil, nil},
				{time.Hour, []Alert{{ID: "overload-oom", Severity: Warning, Title: "t", Body: "b"}}, nil, []string{"firing overload-oom"}},
				{2 * time.Hour, []Alert{{ID: "overload-oom", Severity: Critical, Title: "t", Body: "b"}}, nil, []string{"firing overload-oom"}},
				{3 * time.Hour, []Alert{{ID: "overload-oom", Severity: Warning, Title: "t", Body: "b"}}, nil, nil},
			},
		},
		{
			name: "unknown keeps an open alert instead of resolving it",
			steps: []step{
				{0, []Alert{{ID: "directory-not-running", Severity: Critical, Title: "t", Body: "b"}}, nil, []string{"firing directory-not-running"}},
				{time.Hour, nil, []string{prefixDirectory}, nil},
				{2 * time.Hour, nil, nil, []string{"resolved directory-not-running"}},
			},
		},
		{
			name: "events are sent every time they happen and never resolve",
			steps: []step{
				{0, []Alert{{ID: "flag-lost-Guard", Severity: Warning, Title: "t", Body: "b", Event: true}}, nil, []string{"firing flag-lost-Guard"}},
				{time.Hour, nil, nil, nil},
			},
		},
		{
			name: "ordering: firing by severity, then reminders, then resolved",
			steps: []step{
				{0, []Alert{keyWarn, {ID: "x-old", Severity: Warning, Title: "t", Body: "b"}}, nil, []string{"firing family-key-missing", "firing x-old"}},
				{24 * time.Hour, []Alert{keyWarn, down}, nil, []string{"firing service-inactive", "reminder family-key-missing", "resolved x-old"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cfg
			if tt.cfg != nil {
				tt.cfg(&c)
			}
			var st State
			for i, s := range tt.steps {
				now := t0.Add(s.at)
				notes, next := Plan(st, Evaluation{Alerts: s.alerts, Unknown: s.unknown}, now, c)
				var got []string
				for _, n := range notes {
					got = append(got, string(n.Status)+" "+n.ID)
					if n.Status == StatusReminder || n.Status == StatusResolved {
						if !n.Since.Equal(t0) && n.ID != "x-old" {
							t.Errorf("step %d: %s since %v, want the first sighting", i, n.ID, n.Since)
						}
					}
				}
				if strings.Join(got, "; ") != strings.Join(s.want, "; ") {
					t.Fatalf("step %d (+%v): got %q, want %q", i, s.at, got, s.want)
				}
				if next.Version != stateVersion || !next.UpdatedAt.Equal(now) {
					t.Errorf("step %d: header %+v", i, next)
				}
				st = next
			}
		})
	}
}

func TestStatePersistence(t *testing.T) {
	const path = "/var/lib/tor-relay-setup/alert-state.json"
	fake := host.NewFake()

	st, err := LoadState(fake, path)
	if err != nil || st.Version != 0 || st.Active != nil {
		t.Fatalf("missing file: %+v %v", st, err)
	}

	want := State{
		Version: stateVersion, UpdatedAt: testNow,
		Observed: Observed{Sample: realSample(t, testNow), Flags: []string{"Guard"}, Published: true,
			Overload: map[string]OverloadMark{"oom": {At: testNow, Severity: Warning, Summary: "s"}}},
		Active: map[string]Active{"service-inactive": {Severity: Critical, Title: "t", Since: testNow, LastNotified: testNow}},
	}
	if err := SaveState(fake, path, want); err != nil {
		t.Fatal(err)
	}
	if fake.Modes[path] != 0o600 || !fake.Dirs["/var/lib/tor-relay-setup"] || fake.Modes["/var/lib/tor-relay-setup"].Perm() != 0o700 {
		t.Errorf("modes: file %v dir %v", fake.Modes[path], fake.Modes["/var/lib/tor-relay-setup"])
	}
	got, err := LoadState(fake, path)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Errorf("round trip:\n%s\n%s", a, b)
	}
	if !strings.Contains(string(fake.Files[path]), `"severity": "critical"`) || !strings.Contains(string(fake.Files[path]), `"sockets_limit": 1048544`) {
		t.Errorf("state file:\n%s", fake.Files[path])
	}

	// Corrupt or foreign files start afresh with a warning.
	for _, data := range []string{"{not json", `{"version": 99}`} {
		fake.Files[path] = []byte(data)
		st, err := LoadState(fake, path)
		if err == nil || st.Version != 0 {
			t.Errorf("%q: %+v %v", data, st, err)
		}
	}

	// A dry-run host writes nothing.
	dry := host.NewFake()
	dry.Dry = true
	if err := SaveState(dry, path, want); err != nil || len(dry.Files) != 0 {
		t.Errorf("dry run wrote %v (%v)", dry.Files, err)
	}
}
