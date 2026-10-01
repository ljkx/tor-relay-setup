package tui

import (
	"flag"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/plan"
)

// Snapshot tests render whole screens, colours stripped, and compare them
// with testdata/*.golden. After an intended UI change, regenerate with
//
//	go test ./internal/tui -run Golden -update
//
// and review the diff like any other code change.
var updateGolden = flag.Bool("update", false, "rewrite testdata/*.golden")

// timestampRE matches the generation time in a rendered torrc header.
var timestampRE = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC`)

func golden(t *testing.T, name string, a *App) {
	t.Helper()
	var lines []string
	content := timestampRE.ReplaceAllString(strip(a.View().Content), "YYYY-MM-DD hh:mm:ss UTC")
	for _, l := range strings.Split(content, "\n") {
		lines = append(lines, strings.TrimRight(l, " "))
	}
	got := strings.Join(lines, "\n") + "\n"
	path := filepath.Join("testdata", name+".golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got != string(want) {
		t.Errorf("%s changed; run `go test ./internal/tui -run Golden -update` if intended.\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

// liveConsole is a fully loaded dashboard with deterministic data.
func liveConsole(a *App) *console {
	c := newConsole()
	a.screen, a.console = c, c
	c.report, c.loaded = consoleReport(), true
	c.report.Family.IDs = []string{famID("A")}
	c.report.RecentLog = []string{
		"Oct 01 09:12:31 Tor[812]: Self-testing indicates your ORPort 203.0.113.5:9001 is reachable from the outside. Excellent.",
		"Oct 01 10:00:00 Tor[812]: Heartbeat: Tor's uptime is 1 day 0:00 hours, with 1412 circuits open.",
	}
	c.dir = &onionoo.Relay{
		Running: true, Flags: []string{"Fast", "Guard", "Running", "Stable", "Valid"},
		AdvertisedBandwidth: 13_100_000, ConsensusWeight: 41_200, FirstSeen: "2026-03-14 08:00:00",
	}
	c.dirAt = time.Now()
	day := 24 * time.Hour
	first := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	vals := make([]float64, 30)
	for i := range vals {
		vals[i] = 5e6 + 2e6*math.Sin(float64(i)/3)
	}
	c.history = &onionoo.Bandwidth{
		Read:    onionoo.History{First: first, Last: first.Add(29 * day), Interval: day, Values: vals},
		Written: onionoo.History{First: first, Last: first.Add(29 * day), Interval: day, Values: vals},
	}
	t0 := time.Unix(1_000_000, 0)
	for i := range 20 {
		c.record(metrics.Sample{
			At:          t0.Add(time.Duration(i) * 2 * time.Second),
			Read:        uint64(i*i) * 1_000_000,
			Written:     uint64(i*i) * 950_000,
			Connections: 1480,
		}, nil)
	}
	return c
}

func TestGoldenConsoleWide(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 140, 44
	liveConsole(a)
	golden(t, "console-wide", a)
}

func TestGoldenConsoleNarrow(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 80, 70
	liveConsole(a)
	golden(t, "console-narrow", a)
}

func TestGoldenConsoleNeedsAttention(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 44
	c := liveConsole(a)
	c.report.Service.Active = false
	c.report.Warnings = []string{"tor@default is not running", "FamilyId " + famID("A")[:12] + "… has no key in /var/lib/tor/keys"}
	c.report.Family.MissingKeys = []string{famID("A")}
	golden(t, "console-attention", a)
}

func TestGoldenReview(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 60
	a.screen = newReview(a, testSetup(), nil)
	golden(t, "review", a)
}

func TestGoldenApplyFinished(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 100, 30
	ap := syntheticApply(a)
	a.screen = ap
	for i := range ap.steps {
		ap.handle(plan.Event{Kind: plan.StepStarted, Step: i})
		ap.handle(plan.Event{Kind: plan.StepFinished, Step: i, Elapsed: time.Duration(i+1) * 1500 * time.Millisecond})
	}
	ap.started = time.Unix(1_000_000, 0)
	ap.done, ap.ended = true, ap.started.Add(9*time.Second)
	ap.env = &plan.Env{FamilyID: famID("B")}
	ap.finger = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
	ap.reachDone, ap.reach.IPv4 = true, true
	golden(t, "apply-finished", a)
}
