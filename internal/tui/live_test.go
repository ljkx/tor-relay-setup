package tui

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

func TestSparkline(t *testing.T) {
	t.Parallel()
	if got := sparkline(nil, 10); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got := sparkline([]float64{0, 1, 2, 3, 4, 5, 6, 7}, 8); got != "▁▂▃▄▅▆▇█" {
		t.Errorf("ramp = %q", got)
	}
	if got := sparkline([]float64{0, 0}, 8); got != "▁▁" {
		t.Errorf("all zero = %q", got)
	}
	if got := sparkline([]float64{7, math.NaN(), 7}, 8); got != "█ █" {
		t.Errorf("gap = %q", got)
	}
	// 8 values into 4 cells: pairs are averaged.
	if got := sparkline([]float64{0, 0, 7, 7, 0, 0, 7, 7}, 4); got != "▁█▁█" {
		t.Errorf("resampled = %q", got)
	}
	if got := sparkline([]float64{1, 2}, 0); got != "" {
		t.Errorf("zero width = %q", got)
	}
}

func TestHumanUnits(t *testing.T) {
	t.Parallel()
	for in, want := range map[float64]string{
		100:     "800 bit/s",
		5000:    "40 kbit/s",
		1.25e6:  "10.0 Mbit/s",
		2.5e8:   "2.00 Gbit/s",
		0:       "0 bit/s",
		12345.6: "99 kbit/s",
	} {
		if got := humanRate(in); got != want {
			t.Errorf("humanRate(%v) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[float64]string{
		512: "512 B", 2e3: "2.0 kB", 3.5e6: "3.5 MB", 4e9: "4.0 GB", 8.38e12: "8.4 TB",
	} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%v) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[time.Duration]string{
		4 * time.Second: "4s", 150 * time.Second: "2m", 3 * time.Hour: "3h",
	} {
		if got := ago(in); got != want {
			t.Errorf("ago(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestConsoleLiveTraffic(t *testing.T) {
	t.Parallel()
	a := testApp()
	c := newConsole()
	a.screen = c
	c.report, c.loaded = consoleReport(), true

	rows := func() string { return strip(kv(a.theme, c.liveRows(a, 30))) }
	if !strings.Contains(rows(), "measuring") {
		t.Errorf("before samples: %q", rows())
	}

	t0 := time.Unix(1_000_000, 0)
	c.record(metrics.Sample{At: t0, Read: 0, Written: 0, Connections: 5}, nil)
	if len(c.rates) != 0 {
		t.Fatal("one sample is not a rate")
	}
	c.record(metrics.Sample{At: t0.Add(2 * time.Second), Read: 2_500_000, Written: 5_000_000, Connections: 7}, nil)
	got := rows()
	for _, want := range []string{"↓ 10.0 Mbit/s", "↑ 20.0 Mbit/s", "Connections  7 OR", "2s"} {
		if !strings.Contains(got, want) {
			t.Errorf("live rows lack %q:\n%s", want, got)
		}
	}

	// A Tor restart resets the counters: no bogus rate, keep the old one.
	c.record(metrics.Sample{At: t0.Add(4 * time.Second), Read: 10, Written: 10}, nil)
	if len(c.rates) != 1 {
		t.Errorf("counter reset added a rate: %v", c.rates)
	}

	for i := range liveWindow + 10 {
		c.record(metrics.Sample{At: t0.Add(time.Duration(10+i) * time.Second), Read: uint64(i) * 1000, Written: 0}, nil)
	}
	if len(c.rates) != liveWindow {
		t.Errorf("window holds %d rates, want %d", len(c.rates), liveWindow)
	}

	c.record(metrics.Sample{}, errors.New("connection refused"))
	if !strings.Contains(rows(), "MetricsPort not answering") {
		t.Errorf("error: %q", rows())
	}

	c.report.Service.Active = false
	if !strings.Contains(rows(), "Tor is stopped") || c.scrape() != nil {
		t.Errorf("stopped: %q, scrape %v", rows(), c.scrape() != nil)
	}
	c.report.Relay.MetricsPort = ""
	if !strings.Contains(rows(), "enable MetricsPort") || c.scrape() != nil {
		t.Errorf("no MetricsPort: %q", rows())
	}
}

func TestConsoleHistoryRows(t *testing.T) {
	t.Parallel()
	a := testApp()
	c := newConsole()
	if c.historyRows(a, 40) != nil {
		t.Fatal("no history should add no rows")
	}
	first := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	h := func(vals ...float64) onionoo.History {
		return onionoo.History{First: first, Last: first.Add(time.Duration(len(vals)-1) * day), Interval: day, Values: vals}
	}
	c.history = &onionoo.Bandwidth{
		Read:    h(1e6, math.NaN(), 2e6),
		Written: h(1e6, 1e6, 2e6),
	}
	got := strip(kv(a.theme, c.historyRows(a, 40)))
	// in: 3e6 B/s·day = 259.2 GB; out: 4e6 B/s·day = 345.6 GB.
	for _, want := range []string{"3 days", "in 259.2 GB · out 345.6 GB"} {
		if !strings.Contains(got, want) {
			t.Errorf("history rows lack %q:\n%s", want, got)
		}
	}
}

func TestConsoleBackgroundRouting(t *testing.T) {
	t.Parallel()
	a := testApp()
	c := newConsole()
	a.screen = c
	if cmd := c.init(a); cmd == nil || a.console != c || !c.ticking {
		t.Fatalf("init: cmd %v console %v ticking %v", cmd != nil, a.console == c, c.ticking)
	}

	// While another view is open, the console still takes its updates.
	a.screen = newLogView(c)
	rep := consoleReport()
	rep.Relay.Nickname = "Renamed"
	a.Update(reportMsg(rep))
	if c.report.Relay.Nickname != "Renamed" || c.updated.IsZero() {
		t.Errorf("report routed while hidden: %q", c.report.Relay.Nickname)
	}
	a.Update(sampleMsg{sample: metrics.Sample{At: time.Now(), Read: 1}})
	if c.last.Read != 1 {
		t.Error("sample not routed to the hidden console")
	}

	// Hidden: the refresh timer re-arms without re-checking the system.
	if cmd, ok := c.background(a, refreshTickMsg(time.Now())); !ok || cmd == nil {
		t.Error("refresh tick should re-arm")
	}

	// Onionoo is asked again only after directoryEvery.
	c.background(a, directoryMsg{})
	c.dirAt = time.Now()
	if cmd, _ := c.background(a, reportMsg(rep)); cmd != nil {
		t.Error("fresh directory data should not be fetched again")
	}
	c.dirAt = time.Now().Add(-directoryEvery - time.Minute)
	if cmd, _ := c.background(a, reportMsg(rep)); cmd == nil || !c.dirLoading {
		t.Error("stale directory data should be fetched again")
	}
	c.background(a, historyMsg{bw: &onionoo.Bandwidth{}})
	if c.history == nil {
		t.Error("history not stored")
	}
	c.background(a, historyMsg{err: errors.New("x")})
	if c.history == nil {
		t.Error("a failed history fetch should keep the old data")
	}

	if _, ok := c.background(a, tea.KeyPressMsg{Code: 'r'}); ok {
		t.Error("keys are not background messages")
	}

	// The footer shows when the dashboard was last updated.
	a.screen = c
	c.updated = time.Now().Add(-5 * time.Second)
	if keys := strings.Join(c.keys(a), " "); !strings.Contains(keys, "updated 5s ago") {
		t.Errorf("keys = %q", keys)
	}
}

func TestUpdateHint(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ current, latest, want string }{
		{"v3.0.0", "v3.1.0", "v3.1.0"},
		{"v3.1.0", "v3.1.0", ""},
		{"v3.2.0", "v3.1.0", ""},
		{"dev", "v3.1.0", ""}, // development builds never nag
		{"v3.0.0", "", ""},
	} {
		if got := newerRelease(tc.current, tc.latest); got != tc.want {
			t.Errorf("newerRelease(%q, %q) = %q, want %q", tc.current, tc.latest, got, tc.want)
		}
	}
	a := testApp()
	a.opt.Version = "v3.0.0"
	a.screen = newConsole()
	a.Update(updateMsg("v3.1.0"))
	if v := strip(a.View().Content); !strings.Contains(v, "↑ v3.1.0 available · tor-relay-setup self-update") {
		t.Errorf("header lacks the update hint:\n%s", strings.SplitN(v, "\n", 2)[0])
	}
}

func TestTrendSparkline(t *testing.T) {
	t.Parallel()
	// Scaled to its own range: the minimum sits a third of the way up.
	if got := trendSparkline([]float64{100, 103, 106}, 8); got != "▃▆█" {
		t.Errorf("trend = %q", got)
	}
	if got := trendSparkline([]float64{50, 50, 50}, 8); got != "▄▄▄" {
		t.Errorf("flat = %q", got)
	}
	if got := trendSparkline([]float64{math.NaN(), 4}, 8); got != " ▄" {
		t.Errorf("single value with gap = %q", got)
	}
	if got := trendSparkline([]float64{0, 0}, 8); got != "▁▁" {
		t.Errorf("idle = %q", got)
	}
}
