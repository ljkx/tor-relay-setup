package tui

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

// fleetNow is the dashboard's clock in tests.
var fleetNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func fleetFP(c string) string { return strings.Repeat(c, 40) }

// fleetEntry is one inventory relay; instance is set by hand, as a
// multi-instance relay.toml would.
func fleetEntry(i int, address, instance, nick string) fleet.Entry {
	s := config.Default()
	s.Relay.Nickname = nick
	return fleet.Entry{Index: i, Address: address, Instance: instance, Setup: s}
}

// relayJSON is one relay of a fleet-probe document.
type relayJSON struct {
	instance, nick, fp, version string
	active                      bool
	warnings                    []string
	read, written               uint64
	at                          time.Time
}

// hostProbe builds a probe the way it arrives over ssh: as JSON.
func hostProbe(t *testing.T, address string, relays ...relayJSON) fleet.HostProbe {
	t.Helper()
	var doc struct {
		Version string           `json:"version"`
		Relays  []map[string]any `json:"relays"`
	}
	doc.Version = "v3.2.0"
	for _, r := range relays {
		var rep status.Report
		rep.Relay.Configured, rep.Relay.Nickname, rep.Relay.Fingerprint, rep.Relay.ORPort = true, r.nick, r.fp, 9001
		rep.Relay.MetricsPort = "127.0.0.1:9035"
		rep.Service.Unit, rep.Service.Active = "tor@default", r.active
		if r.instance != "" {
			rep.Service.Unit = "tor@" + r.instance
		}
		rep.Tor.Installed, rep.Tor.Version, rep.Tor.Supported = true, r.version, true
		rep.Listener.IPv4, rep.Reachability.IPv4 = r.active, r.active
		rep.Family.IDs = []string{famID("A")}
		rep.Warnings = r.warnings
		raw, _ := json.Marshal(rep)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if r.instance != "" {
			m["instance"] = r.instance
		}
		entry := map[string]any{"report": m, "traffic": nil}
		if !r.at.IsZero() {
			entry["traffic"] = map[string]any{"at": r.at, "read": r.read, "written": r.written, "connections": 1200}
		}
		doc.Relays = append(doc.Relays, entry)
	}
	data, _ := json.Marshal(doc)
	p, err := fleet.ParseProbe(string(data))
	if err != nil {
		t.Fatal(err)
	}
	return fleet.HostProbe{Address: address, State: fleet.HostOK, At: fleetNow, Probe: p}
}

// liveFleet is a fully loaded dashboard: six relays on five servers, one
// unreachable, one with an old tor-relay-setup, live rates, Tor Metrics
// data and a lost Guard flag.
func liveFleet(t *testing.T, a *App) *fleetView {
	t.Helper()
	inv := fleet.Inventory{Path: "fleet.toml", Entries: []fleet.Entry{
		fleetEntry(1, "root@relay1.example.org", "default", "MyRelay1"),
		fleetEntry(2, "admin@relay2.example.org", "default", "MyRelay2"),
		fleetEntry(3, "root@relay3.example.org", "default", "MyRelay3"),
		fleetEntry(4, "root@relay4.example.org", "default", "MyRelay4"),
		fleetEntry(5, "root@relay4.example.org", "second", "MyRelay5"),
		fleetEntry(6, "root@relay5.example.org", "default", "MyRelay6"),
	}}
	v := newFleetView(FleetOptions{Inventory: inv})
	v.now = func() time.Time { return fleetNow }
	a.screen, a.fleet = v, v
	t1 := fleetNow.Add(-10 * time.Second)
	for i, at := range []time.Time{t1, fleetNow} {
		n := uint64(i)
		v.model.Apply(hostProbe(t, "root@relay1.example.org",
			relayJSON{nick: "MyRelay1", fp: fleetFP("1"), version: "0.4.9.3", active: true, at: at, read: n * 125_000_000, written: n * 120_000_000}))
		v.model.Apply(hostProbe(t, "admin@relay2.example.org",
			relayJSON{nick: "MyRelay2", fp: fleetFP("2"), version: "0.4.9.3", active: true, warnings: []string{"Tor could not confirm the ORPort is reachable from outside"}, at: at, read: n * 25_000_000, written: n * 25_000_000}))
		v.model.Apply(hostProbe(t, "root@relay4.example.org",
			relayJSON{nick: "MyRelay4", fp: fleetFP("4"), version: "0.4.8.16", active: true, at: at, read: n * 50_000_000, written: n * 50_000_000},
			relayJSON{instance: "second", nick: "MyRelay5", fp: fleetFP("5"), version: "0.4.9.3", active: false, warnings: []string{"tor@second is not running"}}))
	}
	v.model.Apply(fleet.HostProbe{Address: "root@relay3.example.org", State: fleet.HostUnreachable, Detail: "ssh: connect to host relay3.example.org port 22: Connection timed out", At: fleetNow})
	v.model.Apply(fleet.HostProbe{Address: "root@relay5.example.org", State: fleet.HostTooOld, Detail: "tor-relay-setup too old on this host — run self-update", At: fleetNow})
	v.model.PrevFlags = fleet.FlagCache{Flags: map[string][]string{fleetFP("2"): {"Guard", "Stable", "Fast"}}}
	v.model.SetDirectory(map[string]*onionoo.Relay{
		fleetFP("1"): {Running: true, Flags: []string{"Fast", "Guard", "HSDir", "Running", "Stable", "V2Dir", "Valid"}, ConsensusWeight: 41200,
			ConsensusWeightFraction: 0.000412, GuardProbability: 0.0007, MiddleProbability: 0.0004, AdvertisedBandwidth: 31_250_000, FirstSeen: "2026-03-14 08:00:00"},
		fleetFP("2"): {Running: true, Flags: []string{"Fast", "Running", "Stable", "Valid"}, ConsensusWeight: 9800,
			ConsensusWeightFraction: 0.000098, MiddleProbability: 0.0001, AdvertisedBandwidth: 6_250_000},
		fleetFP("4"): {Running: true, Flags: []string{"Fast", "Running", "Valid"}, ConsensusWeight: 12000,
			ConsensusWeightFraction: 0.00012, MiddleProbability: 0.00015, AdvertisedBandwidth: 12_500_000},
	}, nil, fleetNow.Add(-12*time.Minute))
	day := 24 * time.Hour
	first := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	history := map[string]*onionoo.Bandwidth{}
	for k, fp := range []string{fleetFP("1"), fleetFP("2"), fleetFP("4")} {
		vals := make([]float64, 30)
		for i := range vals {
			vals[i] = float64(k+1) * (5e6 + 2e6*math.Sin(float64(i)/3))
		}
		h := onionoo.History{First: first, Last: first.Add(29 * day), Interval: day, Values: vals}
		history[fp] = &onionoo.Bandwidth{Read: h, Written: h}
	}
	v.model.SetHistory(history)
	v.updated = fleetNow.Add(-4 * time.Second)
	return v
}

func TestGoldenFleetWide(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 40
	liveFleet(t, a)
	golden(t, "fleet-wide", a)
}

func TestGoldenFleetNarrow(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 80, 40
	liveFleet(t, a)
	golden(t, "fleet-narrow", a)
}

func TestGoldenFleetDetail(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 40
	v := liveFleet(t, a)
	v.update(a, tea.KeyPressMsg{Code: tea.KeyDown})
	v.update(a, tea.KeyPressMsg{Code: tea.KeyEnter})
	golden(t, "fleet-detail", a)
}

func press(a *App, v *fleetView, keys ...string) {
	for _, k := range keys {
		var msg tea.KeyPressMsg
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "backspace":
			msg = tea.KeyPressMsg{Code: tea.KeyBackspace}
		case "down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		default:
			r := []rune(k)[0]
			msg = tea.KeyPressMsg{Code: r, Text: k}
		}
		v.update(a, msg)
	}
}

func nicknames(rows []*fleet.Relay) string {
	var n []string
	for _, r := range rows {
		n = append(n, r.Nickname())
	}
	return strings.Join(n, " ")
}

func TestFleetSorting(t *testing.T) {
	t.Parallel()
	a := testApp()
	v := liveFleet(t, a)
	tests := []struct {
		sort, want string
	}{
		{"inventory", "MyRelay1 MyRelay2 MyRelay3 MyRelay4 MyRelay5 MyRelay6"},
		{"host", "MyRelay1 MyRelay2 MyRelay3 MyRelay4 MyRelay5 MyRelay6"},
		{"nickname", "MyRelay1 MyRelay2 MyRelay3 MyRelay4 MyRelay5 MyRelay6"},
		{"status", "MyRelay3 MyRelay5 MyRelay6 MyRelay2 MyRelay1 MyRelay4"},
		{"live", "MyRelay1 MyRelay4 MyRelay2 MyRelay3 MyRelay5 MyRelay6"},
		{"weight", "MyRelay1 MyRelay4 MyRelay2 MyRelay3 MyRelay5 MyRelay6"},
		{"warnings", "MyRelay2 MyRelay5 MyRelay1 MyRelay3 MyRelay4 MyRelay6"},
		{"tor", "MyRelay3 MyRelay6 MyRelay4 MyRelay1 MyRelay2 MyRelay5"},
	}
	for i, tt := range tests {
		if i > 0 {
			press(a, v, "s")
		}
		if fleetSorts[v.sortBy].name != tt.sort {
			t.Fatalf("sort %d is %s, want %s", i, fleetSorts[v.sortBy].name, tt.sort)
		}
		if got := nicknames(v.rows()); got != tt.want {
			t.Errorf("sorted by %s: %s, want %s", tt.sort, got, tt.want)
		}
	}
	press(a, v, "s") // back to inventory order
	press(a, v, "S")
	if got := nicknames(v.rows()); got != "MyRelay6 MyRelay5 MyRelay4 MyRelay3 MyRelay2 MyRelay1" {
		t.Errorf("reversed: %s", got)
	}
	if !strings.Contains(strip(v.view(a)), "sorted by inventory (reversed)") {
		t.Error("the title does not say the order is reversed")
	}
}

func TestFleetFilter(t *testing.T) {
	t.Parallel()
	a := testApp()
	v := liveFleet(t, a)
	press(a, v, "/", "r", "e", "l", "a", "y", "4")
	if !v.filtering || v.filter != "relay4" || nicknames(v.rows()) != "MyRelay4 MyRelay5" {
		t.Fatalf("filter %q (%v): %s", v.filter, v.filtering, nicknames(v.rows()))
	}
	if view := strip(v.view(a)); !strings.Contains(view, "filter: relay4▌") {
		t.Errorf("typing is not shown:\n%s", view)
	}
	press(a, v, "enter")
	view := strip(v.view(a))
	if v.filtering || !strings.Contains(view, `filter "relay4": 2 of 6`) || strings.Contains(view, "MyRelay1") {
		t.Errorf("committed filter:\n%s", view)
	}
	// Flags, states and versions match too; "q" while typing is text.
	press(a, v, "esc", "/", "t", "o", "o", "-", "o", "l", "d", "enter")
	if nicknames(v.rows()) != "MyRelay6" {
		t.Errorf("state filter: %s", nicknames(v.rows()))
	}
	press(a, v, "/", "backspace", "backspace", "backspace", "backspace", "backspace", "backspace", "backspace", "backspace", "H", "S", "D", "i", "r", "enter")
	if nicknames(v.rows()) != "MyRelay1" {
		t.Errorf("flag filter: %s", nicknames(v.rows()))
	}
	press(a, v, "/", "q", "enter")
	if v.filter != "HSDirq" || len(v.rows()) != 0 || !strings.Contains(strip(v.view(a)), `No relay matches "HSDirq" (esc clears the filter).`) {
		t.Errorf("no match: %q\n%s", v.filter, strip(v.view(a)))
	}
	press(a, v, "esc")
	if v.filter != "" || len(v.rows()) != 6 {
		t.Errorf("esc should clear the filter: %q", v.filter)
	}
}

func TestFleetRowsShowUnreachableAndTooOld(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 40
	v := liveFleet(t, a)
	view := strip(v.view(a))
	for _, want := range []string{
		"✗  relay3.example.org", "!  relay5.example.org", "✓  relay1.example.org",
		"root@relay3.example.org: unreachable over ssh",
		"root@relay5.example.org: tor-relay-setup too old on this host — run self-update",
		"MyRelay2 lost Guard since the last dashboard run",
		"tor versions differ: 0.4.9.3 ×3, 0.4.8.16 ×1",
		"Hosts      5 · 1 unreachable · 1 need self-update",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("view lacks %q:\n%s", want, view)
		}
	}
	// The detail of the unreachable relay says why.
	press(a, v, "down", "down", "enter")
	detail := strip(v.view(a))
	if !strings.Contains(detail, "Connection timed out") || !strings.Contains(detail, "no report from this relay") {
		t.Errorf("detail:\n%s", detail)
	}
	press(a, v, "esc")
	if v.detail {
		t.Error("esc should close the detail")
	}
}

func TestFleetNarrowDropsColumns(t *testing.T) {
	t.Parallel()
	v := newFleetView(FleetOptions{})
	titles := func(inner int) string {
		cols, _ := v.fleetColumns(inner)
		var s []string
		for _, c := range cols {
			s = append(s, c.title)
		}
		return strings.TrimSpace(strings.Join(s, " "))
	}
	if got := titles(114); got != "HOST NICKNAME INSTANCE FLAGS TOR LIVE WEIGHT WARN" {
		t.Errorf("wide: %s", got)
	}
	if got := titles(74); got != "HOST NICKNAME LIVE WEIGHT WARN" {
		t.Errorf("80 columns: %s", got)
	}
	if got := titles(50); got != "HOST NICKNAME LIVE WARN" {
		t.Errorf("very narrow: %s", got)
	}
	// The narrowest window shortens the nickname column so the row fits.
	cols, hostW := v.fleetColumns(48)
	total := hostW
	for _, c := range cols {
		if c.title != "HOST" {
			total += c.width
		}
	}
	if total+2*(len(cols)-1) != 48 || cols[2].width != 11 {
		t.Errorf("48 columns: host %d, total %d, nickname %d", hostW, total+2*(len(cols)-1), cols[2].width)
	}
}

func TestFleetBackground(t *testing.T) {
	t.Parallel()
	a := testApp()
	var mu sync.Mutex
	var probed []string
	inv := fleet.Inventory{Entries: []fleet.Entry{fleetEntry(1, "a", "default", "A"), fleetEntry(2, "b", "default", "B")}}
	v := newFleetView(FleetOptions{Inventory: inv, Probe: func(_ context.Context, addr string) fleet.HostProbe {
		mu.Lock()
		probed = append(probed, addr)
		mu.Unlock()
		return fleet.HostProbe{Address: addr, State: fleet.HostUnreachable}
	}})
	a.screen = v
	cmd := v.init(a)
	if a.fleet != v || cmd == nil || len(v.inflight) != 2 {
		t.Fatalf("init: fleet %v, inflight %v", a.fleet, v.inflight)
	}
	// A tick while both probes run starts nothing new.
	if cmd, ok := v.background(a, fleetTickMsg(fleetNow)); !ok || cmd == nil || len(v.inflight) != 2 {
		t.Error("tick")
	}
	v.background(a, fleetProbeMsg(hostProbe(t, "a", relayJSON{nick: "A", fp: fleetFP("A"), version: "0.4.9.3", active: true})))
	if v.inflight["a"] || v.dirDue() {
		t.Errorf("after one host: inflight %v, due %v", v.inflight, v.dirDue())
	}
	cmd, _ = v.background(a, fleetProbeMsg(fleet.HostProbe{Address: "b", State: fleet.HostUnreachable}))
	if cmd == nil || !v.dirLoading {
		t.Error("Tor Metrics should be asked once every host answered")
	}
	// The lookup result is recorded and, without a cache, nothing is saved.
	v.background(a, fleetDirMsg{details: map[string]*onionoo.Relay{fleetFP("A"): {Running: true}}, at: fleetNow})
	if v.dirLoading || v.model.DirAt != fleetNow || v.model.Directory[fleetFP("A")] == nil {
		t.Errorf("directory not recorded: %+v", v.model.Directory)
	}
	// Probes keep arriving while another screen (a task) is open.
	a.screen = newConfirmView(v, "?", nil)
	if _, cmd := a.Update(fleetProbeMsg(fleet.HostProbe{Address: "a", State: fleet.HostTooOld})); cmd == nil && v.model.Host("a").State != fleet.HostTooOld {
		t.Error("background probe not applied")
	}
	if v.model.Host("a").State != fleet.HostTooOld {
		t.Errorf("host a = %+v", v.model.Host("a"))
	}
}

func TestFleetSavesTheFlagCache(t *testing.T) {
	t.Parallel()
	h := host.NewFake()
	h.Files["/cache/fleet.json"] = []byte(`{"flags":{"` + fleetFP("A") + `":["Guard"]}}`)
	v := newFleetView(FleetOptions{Cache: h, CachePath: "/cache/fleet.json"})
	if got := v.model.PrevFlags.Flags[fleetFP("A")]; len(got) != 1 {
		t.Fatalf("cache not loaded: %+v", v.model.PrevFlags)
	}
	cmd, _ := v.background(testApp(), fleetDirMsg{details: map[string]*onionoo.Relay{fleetFP("A"): {Flags: []string{"Stable"}}}, at: fleetNow})
	if cmd == nil {
		t.Fatal("no save")
	}
	cmd()
	if got := fleet.LoadFlagCache(h, "/cache/fleet.json"); len(got.Flags[fleetFP("A")]) != 1 || got.Flags[fleetFP("A")][0] != "Stable" {
		t.Errorf("saved %+v", got)
	}
}

func TestFleetRolloutConfirmation(t *testing.T) {
	t.Parallel()
	a := testApp()
	v := liveFleet(t, a)
	var mu sync.Mutex
	var gotAction string
	var gotNicks []string
	release := make(chan struct{})
	v.opt.Rollout = func(_ context.Context, action string, entries []fleet.Entry, out func(string)) error {
		mu.Lock()
		gotAction = action
		for _, e := range entries {
			gotNicks = append(gotNicks, e.Nickname())
		}
		mu.Unlock()
		out("==> [1/2] restart root@relay4.example.org/MyRelay4")
		<-release
		return nil
	}
	press(a, v, "/", "r", "e", "l", "a", "y", "4", "enter")
	next, _ := v.update(a, tea.KeyPressMsg{Code: 'R', Text: "R"})
	c, ok := next.(*confirmView)
	if !ok {
		t.Fatalf("R opened %T", next)
	}
	a.screen = c
	q := strip(c.view(a))
	for _, want := range []string{`Restart tor on the relays matching "relay4" (2), one relay at a time?`, "1. MyRelay4 (root@relay4.example.org)", "2. MyRelay5 (root@relay4.example.org)"} {
		if !strings.Contains(q, want) {
			t.Errorf("confirmation lacks %q:\n%s", want, q)
		}
	}
	// "n" goes back without running anything.
	if back, _ := c.update(a, tea.KeyPressMsg{Code: 'n', Text: "n"}); back != screen(v) {
		t.Errorf("n returned %T", back)
	}
	next, cmd := c.update(a, tea.KeyPressMsg{Code: 'y', Text: "y"})
	tk, ok := next.(*task)
	if !ok || cmd == nil {
		t.Fatalf("y opened %T", next)
	}
	msg := cmd() // the first output line
	a.screen = tk
	tk.update(a, msg)
	close(release)
	for tk.running {
		tk.update(a, <-tk.events)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotAction != "restart" || strings.Join(gotNicks, " ") != "MyRelay4 MyRelay5" {
		t.Errorf("rollout %s %q", gotAction, gotNicks)
	}
	view := strip(tk.view(a))
	if tk.err != nil || !strings.Contains(view, "Restart tor done on 2 relays.") || !strings.Contains(view, "restart root@relay4.example.org/MyRelay4") {
		t.Errorf("task view:\n%s", view)
	}
	if k := tk.keys(a); k[1] != "back to the fleet" {
		t.Errorf("keys %q", k)
	}
	if back, _ := tk.update(a, tea.KeyPressMsg{Code: tea.KeyEnter}); back != screen(v) {
		t.Errorf("enter returned %T", back)
	}
	// Without a Rollout function nothing is offered.
	v.opt.Rollout = nil
	if next, _ := v.update(a, tea.KeyPressMsg{Code: 'U', Text: "U"}); next != screen(v) {
		t.Errorf("U without rollout opened %T", next)
	}
}

func TestFleetKeysAndHeader(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width = 120
	v := liveFleet(t, a)
	if got := strings.Join(v.keys(a), " "); !strings.Contains(got, "refresh · 4s ago") || !strings.Contains(got, "restart/reload/update") {
		t.Errorf("keys %q", got)
	}
	a.width = 80
	if got := strings.Join(v.keys(a), " "); !strings.Contains(got, "R/O/U roll") {
		t.Errorf("narrow keys %q", got)
	}
	if v.headerRight() != "fleet.toml · 6 relays" {
		t.Errorf("header %q", v.headerRight())
	}
	press(a, v, "enter")
	if got := strings.Join(v.keys(a), " "); got != "↑/↓ next relay esc back" {
		t.Errorf("detail keys %q", got)
	}
	press(a, v, "esc", "/")
	if got := strings.Join(v.keys(a), " "); got != "type filter enter keep esc clear" {
		t.Errorf("filter keys %q", got)
	}
	press(a, v, "esc")
	if _, cmd := v.update(a, tea.KeyPressMsg{Code: 'q', Text: "q"}); cmd == nil {
		t.Error("q should quit")
	}
}
