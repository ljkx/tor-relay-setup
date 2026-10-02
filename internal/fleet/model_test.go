package fleet

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

var (
	famA = strings.Repeat("A", 42) + "a"
	famB = strings.Repeat("B", 42) + "b"
	t0   = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
)

func fp(c string) string { return strings.Repeat(c, 40) }

// relayProbe builds a probe entry; active and ids describe the relay.
func relayProbe(instance, nick, fingerprint, version string, active bool, ids ...string) RelayProbe {
	var r status.Report
	r.Relay.Configured, r.Relay.Nickname, r.Relay.Fingerprint, r.Relay.ORPort = true, nick, fingerprint, 9001
	r.Service.Unit, r.Service.Active = "tor@default", active
	r.Tor.Installed, r.Tor.Version, r.Tor.Supported = true, version, true
	r.Listener.IPv4 = active
	r.Family.IDs = ids
	return RelayProbe{Report: r, instance: instance}
}

func withTraffic(p RelayProbe, at time.Time, read, written uint64) RelayProbe {
	p.Traffic = &Traffic{At: at, Read: read, Written: written, Connections: 7}
	return p
}

func ok(address string, relays ...RelayProbe) HostProbe {
	return HostProbe{Address: address, State: HostOK, At: t0, Probe: Probe{Version: "v3.2.0", Relays: relays}}
}

// testFleet is six inventory relays on five servers, probed once, with one
// relay the inventory does not list.
func testFleet(t *testing.T) *Model {
	t.Helper()
	inv := entries(
		[4]string{"root@a", "default", "One", "x"},
		[4]string{"root@b", "default", "Two", "x"},
		[4]string{"root@c", "default", "Three", "x"},
		[4]string{"root@d", "default", "Four", "x"},
		[4]string{"root@e", "default", "Five", "x"},
		[4]string{"root@a", "second", "Six", "xx"},
	)
	m := NewModel(inv)
	seven := relayProbe("third", "Seven", fp("7"), "0.4.8.16", false)
	seven.Report.Family.LegacyCount = 2
	two := relayProbe(DefaultInstance, "Two", fp("2"), "0.4.9.3", false, famB)
	two.Report.Family.MissingKeys = []string{famB}
	two.Report.Warnings = []string{"tor@default is not running", "no family key installed for FamilyId " + famB, "Tor could not confirm the ORPort is reachable from outside"}
	m.Apply(ok("root@a",
		withTraffic(relayProbe(DefaultInstance, "One", fp("1"), "0.4.9.3", true, famA), t0, 1_000_000, 2_000_000),
		relayProbe("second", "Six", fp("6"), "0.4.9.3", true, famA),
		seven,
	))
	m.Apply(ok("root@b", two))
	m.Apply(HostProbe{Address: "root@c", State: HostUnreachable, Detail: "Connection refused", At: t0})
	m.Apply(HostProbe{Address: "root@d", State: HostTooOld, At: t0})
	m.Apply(HostProbe{Address: "root@e", State: HostMissing, At: t0})
	return m
}

func withDirectory(m *Model) {
	m.PrevFlags = FlagCache{Flags: map[string][]string{fp("1"): {"Guard", "Stable", "Fast"}, fp("2"): {"Fast"}}}
	m.SetDirectory(map[string]*onionoo.Relay{
		fp("1"): {Running: true, Flags: []string{"Fast", "Running", "Valid"}, ConsensusWeight: 100, ConsensusWeightFraction: 0.001,
			GuardProbability: 0.002, MiddleProbability: 0.003, AdvertisedBandwidth: 1000},
		fp("2"): {Running: false, Flags: []string{"Fast"}, ConsensusWeight: 50, ConsensusWeightFraction: 0.0005, ExitProbability: 0.0001, AdvertisedBandwidth: 500},
		fp("7"): {Running: true, Flags: []string{"Running"}, ConsensusWeight: 1, AdvertisedBandwidth: 10},
	}, nil, t0)
}

func TestModelTotals(t *testing.T) {
	m := testFleet(t)
	withDirectory(m)
	// A second probe 10s later gives One a live rate.
	m.Apply(ok("root@a",
		withTraffic(relayProbe(DefaultInstance, "One", fp("1"), "0.4.9.3", true, famA), t0.Add(10*time.Second), 1_010_000, 2_030_000),
		relayProbe("second", "Six", fp("6"), "0.4.9.3", true, famA),
		relayProbe("third", "Seven", fp("7"), "0.4.8.16", false),
	))
	tot := m.Totals()
	want := Totals{
		Relays: 7, Running: 2, Hosts: 5, Unreachable: 1, TooOld: 2, Published: 3,
		ConsensusWeight: 151, WeightFraction: 0.0015, Guard: 0.002, Middle: 0.003, Exit: 0.0001,
		Read: 1000, Written: 3000, Advertised: 1510,
	}
	if math.Abs(tot.WeightFraction-0.0015) < 1e-12 {
		tot.WeightFraction = 0.0015
	}
	if !reflect.DeepEqual(tot, want) {
		t.Errorf("totals\n got %+v\nwant %+v", tot, want)
	}
	if got := m.Fingerprints(); !reflect.DeepEqual(got, []string{fp("1"), fp("2"), fp("6"), fp("7")}) {
		t.Errorf("fingerprints %q", got)
	}
	// The relay the inventory does not list is a row of its own.
	rs := m.Relays()
	if len(rs) != 7 || rs[6].Entry != nil || rs[6].Nickname() != "Seven" || rs[6].Instance != "third" || rs[5].Nickname() != "Six" {
		t.Errorf("relays: %+v", rs)
	}
	// Pending relays fall back to the inventory nickname.
	if rs[2].Nickname() != "Three" || rs[2].Fingerprint() != "" || rs[2].Running() {
		t.Errorf("unreachable relay row: %+v", rs[2])
	}
}

func TestRelayRates(t *testing.T) {
	r := &Relay{}
	r.record(&Traffic{At: t0, Read: 100, Written: 100})
	if r.HasRate {
		t.Fatal("one sample is no rate")
	}
	r.record(&Traffic{At: t0.Add(2 * time.Second), Read: 300, Written: 500})
	if !r.HasRate || r.Rate.Read != 100 || r.Rate.Written != 200 {
		t.Fatalf("rate = %+v", r.Rate)
	}
	// The same sample again (a cached probe) keeps the rate.
	r.record(&Traffic{At: t0.Add(2 * time.Second), Read: 300, Written: 500})
	if !r.HasRate {
		t.Error("an unchanged sample dropped the rate")
	}
	// Tor restarted: counters went backwards.
	r.record(&Traffic{At: t0.Add(4 * time.Second), Read: 10, Written: 10})
	if r.HasRate {
		t.Error("counters went backwards, but a rate is shown")
	}
	r.record(&Traffic{At: t0.Add(6 * time.Second), Read: 20, Written: 30})
	if !r.HasRate || r.Rate.Read != 5 {
		t.Errorf("after the restart: %+v", r.Rate)
	}
	r.record(nil)
	if r.HasRate || !r.last.At.IsZero() {
		t.Error("no traffic clears the rate")
	}
}

func TestSumHistoryAlignsByDate(t *testing.T) {
	day := 24 * time.Hour
	h := func(first time.Time, interval time.Duration, vals ...float64) onionoo.History {
		return onionoo.History{First: first, Last: first.Add(time.Duration(len(vals)-1) * interval), Interval: interval, Values: vals}
	}
	sep1 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	a := &onionoo.Bandwidth{Read: h(sep1, day, 1, 2, 3), Written: h(sep1, day, 1, 1, 1)}
	b := &onionoo.Bandwidth{Read: h(sep1.Add(12*time.Hour), day, 10, math.NaN())} // starts at midnight of Sep 2
	c := &onionoo.Bandwidth{Written: h(sep1.Add(4*day), day, 5)}                  // Sep 5: Sep 4 has no data
	daily, first, in, out := SumHistory([]*onionoo.Bandwidth{a, b, c})
	if !first.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("first day %v", first)
	}
	if len(daily) != 5 || daily[0] != 2 || daily[1] != 13 || daily[2] != 4 || !math.IsNaN(daily[3]) || daily[4] != 5 {
		t.Errorf("daily %v", daily)
	}
	if in != 16*86400 || out != 8*86400 {
		t.Errorf("in %v out %v", in, out)
	}
	if d, _, _, _ := SumHistory(nil); d != nil {
		t.Errorf("no histories: %v", d)
	}
	// Totals use the per-relay histories.
	m := testFleet(t)
	m.SetHistory(map[string]*onionoo.Bandwidth{fp("1"): a, fp("2"): b, "unknown": c})
	if tot := m.Totals(); len(tot.History) != 3 || tot.History[1] != 13 || tot.HistoryIn != 16*86400 {
		t.Errorf("totals history %v in %v", tot.History, tot.HistoryIn)
	}
}

func kinds(items []Item) string {
	var k []string
	for _, it := range items {
		k = append(k, it.Kind)
	}
	return strings.Join(k, " ")
}

func TestAttention(t *testing.T) {
	m := testFleet(t)
	// Before Tor Metrics answered, only local checks run.
	want := "unreachable too-old not-installed not-running family-key relay-warning not-running legacy-myfamily family-drift family-drift version-drift"
	if got := kinds(m.Attention()); got != want {
		t.Errorf("before Tor Metrics:\n got %s\nwant %s", got, want)
	}
	withDirectory(m)
	items := m.Attention()
	want = "unreachable too-old not-installed not-running directory-down family-key relay-warning unpublished not-running legacy-myfamily family-drift family-drift version-drift lost-flags"
	if got := kinds(items); got != want {
		t.Errorf("with Tor Metrics:\n got %s\nwant %s", got, want)
	}
	texts := map[string]string{}
	for _, it := range items {
		texts[it.Kind] += it.Text + "\n"
	}
	for kind, wantText := range map[string]string{
		"unreachable":     "root@c: unreachable over ssh (Connection refused)",
		"too-old":         "root@d: tor-relay-setup too old on this host — run self-update",
		"not-installed":   "root@e: tor-relay-setup is not installed on this host",
		"directory-down":  "Two: Tor Metrics reports it as not running",
		"family-key":      "Two: no family key installed for FamilyId BBBBBBBBBBBB…",
		"unpublished":     "Six (a/second): not in Tor Metrics",
		"legacy-myfamily": "Seven (a/third): legacy MyFamily (2 fingerprints)",
		"family-drift":    "Two: FamilyId set differs from the rest of the fleet\nSeven (a/third): not in the fleet's family (no FamilyId)",
		"version-drift":   "tor versions differ: 0.4.9.3 ×3, 0.4.8.16 ×1",
		"lost-flags":      "One lost Guard, Stable since the last dashboard run",
		"relay-warning":   "Two: Tor could not confirm the ORPort is reachable from outside",
	} {
		if !strings.Contains(texts[kind], wantText) {
			t.Errorf("%s: %q lacks %q", kind, texts[kind], wantText)
		}
	}
	if items[0].Level != Bad || texts["version-drift"] == "" {
		t.Error("levels")
	}
	// A failed Tor Metrics lookup suppresses the directory checks.
	m.SetDirectory(nil, errFake, t0)
	if strings.Contains(kinds(m.Attention()), "unpublished") || strings.Contains(kinds(m.Attention()), "lost-flags") {
		t.Errorf("checks used stale or missing directory data: %s", kinds(m.Attention()))
	}
	if m.Healthy() {
		t.Error("Healthy with problems")
	}
}

var errFake = &host.ExitError{ExitCode: 1}

func TestRelayMissingFromItsHost(t *testing.T) {
	m := testFleet(t)
	// Host a answers without its second relay.
	m.Apply(ok("root@a", relayProbe(DefaultInstance, "One", fp("1"), "0.4.9.3", true, famA)))
	six := m.Relays()[5]
	if !six.Missing || six.Probe != nil || m.RelayState(six) != "missing" {
		t.Errorf("six = %+v", six)
	}
	if !strings.Contains(kinds(m.Attention()), "missing") {
		t.Errorf("attention: %s", kinds(m.Attention()))
	}
	// An unreachable host keeps the last report but shows the host state.
	m.Apply(HostProbe{Address: "root@a", State: HostUnreachable})
	if got := m.RelayState(m.Relays()[0]); got != "unreachable" {
		t.Errorf("state = %s", got)
	}
	healthy := NewModel(entries([4]string{"x", "default", "X", "x"}))
	healthy.Apply(ok("x", relayProbe(DefaultInstance, "X", fp("9"), "0.4.9.3", true)))
	if !healthy.Healthy() || healthy.RelayState(healthy.Relays()[0]) != "running" {
		t.Errorf("healthy fleet: %+v", healthy.Attention())
	}
}

func TestAbbrevFlags(t *testing.T) {
	if got := AbbrevFlags([]string{"Valid", "Running", "Fast", "Guard", "Stable", "HSDir", "V2Dir", "Weird"}); got != "GSFHVRD" {
		t.Errorf("AbbrevFlags = %q", got)
	}
	if AbbrevFlags(nil) != "" {
		t.Error("no flags")
	}
}

func TestFlagCache(t *testing.T) {
	h := host.NewFake()
	inv := entries([4]string{"a", "default", "A", "x"})
	inv.Path = "/home/op/fleet.toml"
	path := CachePath("/home/op/.cache", inv)
	if !strings.HasPrefix(path, "/home/op/.cache/tor-relay-setup/fleet-") || !strings.HasSuffix(path, ".json") {
		t.Errorf("path %q", path)
	}
	other := inv
	other.Path = "/home/op/other.toml"
	if CachePath("/home/op/.cache", other) == path {
		t.Error("two inventories share a cache")
	}
	if c := LoadFlagCache(h, path); c.Flags != nil {
		t.Errorf("missing cache = %+v", c)
	}
	prev := FlagCache{Flags: map[string][]string{fp("1"): {"Guard"}, fp("9"): {"Stable"}}}
	details := map[string]*onionoo.Relay{fp("1"): {Flags: []string{"Fast", "Running", "Stable", "Exit"}}, fp("2"): nil}
	if err := SaveFlagCache(h, path, prev, details, t0); err != nil {
		t.Fatal(err)
	}
	if h.Modes[path] != 0o600 {
		t.Errorf("mode %o", h.Modes[path])
	}
	got := LoadFlagCache(h, path)
	want := map[string][]string{fp("1"): {"Stable", "Fast"}, fp("9"): {"Stable"}}
	if !reflect.DeepEqual(got.Flags, want) || !got.Saved.Equal(t0) {
		t.Errorf("cache = %+v", got)
	}
	// A dry run host writes nothing.
	dry := host.NewFake()
	dry.Dry = true
	if err := SaveFlagCache(dry, path, prev, details, t0); err != nil || len(dry.Files) != 0 {
		t.Errorf("dry run wrote %v (%v)", dry.Files, err)
	}
}

func TestWriteText(t *testing.T) {
	m := testFleet(t)
	withDirectory(m)
	var b bytes.Buffer
	if err := m.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Relays       2 of 7 running on 5 hosts, 1 unreachable, 2 without fleet-probe",
		"Weight       151 (0.150% of the network), 3 of 7 relays published",
		"Selection    guard 0.200% · middle 0.300% · exit 0.010%",
		"HOST  NICKNAME  INSTANCE  STATE",
		"a     One       default   running        FVR    0.4.9.3   100     0",
		"c     Three     default   unreachable    -      -         -       0",
		"a     Seven     third     stopped",
		"Needs attention:\n! root@c: unreachable over ssh (Connection refused)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	m := testFleet(t)
	withDirectory(m)
	var b bytes.Buffer
	if err := m.WriteJSON(&b, t0); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Totals struct {
			Relays          int   `json:"relays"`
			ConsensusWeight int64 `json:"consensus_weight"`
		} `json:"totals"`
		Hosts []struct {
			Address, State string
		} `json:"hosts"`
		Relays []struct {
			Nickname, State, Instance string
			InInventory               bool     `json:"in_inventory"`
			LostFlags                 []string `json:"lost_flags"`
			Report                    *status.Report
		} `json:"relays"`
		Attention []Item `json:"attention"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("%v\n%s", err, b.String())
	}
	if doc.Totals.Relays != 7 || doc.Totals.ConsensusWeight != 151 || len(doc.Hosts) != 5 || doc.Hosts[2].State != "unreachable" {
		t.Errorf("doc = %+v", doc)
	}
	if r := doc.Relays[0]; r.Nickname != "One" || r.State != "running" || !r.InInventory || !reflect.DeepEqual(r.LostFlags, []string{"Guard", "Stable"}) || r.Report == nil {
		t.Errorf("relay 0 = %+v", r)
	}
	if r := doc.Relays[6]; r.InInventory || r.Instance != "third" {
		t.Errorf("relay 6 = %+v", r)
	}
	if len(doc.Attention) != 14 {
		t.Errorf("attention = %d", len(doc.Attention))
	}
}

func TestWritePrometheus(t *testing.T) {
	m := testFleet(t)
	withDirectory(m)
	var b bytes.Buffer
	if err := m.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# TYPE tor_relay_fleet_relays gauge\ntor_relay_fleet_relays 7\n",
		"tor_relay_fleet_relays_running 2\n",
		"tor_relay_fleet_hosts_unreachable 1\n",
		"tor_relay_fleet_hosts_without_probe 2\n",
		"tor_relay_fleet_consensus_weight 151\n",
		"tor_relay_fleet_consensus_weight_fraction 0.0015",
		`tor_relay_fleet_host_up{host="c",state="unreachable"} 0`,
		`tor_relay_fleet_host_up{host="a",state="ok"} 1`,
		`tor_relay_fleet_relay_info{host="a",tor_instance="default",nickname="One",fingerprint="` + fp("1") + `",version="0.4.9.3"} 1`,
		`tor_relay_fleet_relay_service_active{host="b",tor_instance="default",nickname="Two",fingerprint="` + fp("2") + `"} 0`,
		"# TYPE tor_relay_fleet_relay_traffic_bytes_total counter\n",
		`tor_relay_fleet_relay_traffic_bytes_total{host="a",tor_instance="default",nickname="One",fingerprint="` + fp("1") + `",direction="read"} 1e+06`,
		`tor_relay_fleet_relay_consensus_weight{host="a",tor_instance="third",nickname="Seven",fingerprint="` + fp("7") + `"} 1`,
		`tor_relay_fleet_relay_info{host="c",tor_instance="default",nickname="Three",fingerprint="",version=""} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q:\n%s", want, out)
		}
	}
	// Without Tor Metrics data the fleet weight gauges are left out.
	b.Reset()
	if err := testFleet(t).WritePrometheus(&b); err != nil || strings.Contains(b.String(), "consensus_weight") {
		t.Errorf("unknown weights were exported:\n%s", b.String())
	}
}

func TestPercent(t *testing.T) {
	for in, want := range map[float64]string{0: "0%", 0.00001: "0.0010%", 0.0012: "0.120%", 0.05: "5.00%"} {
		if got := Percent(in); got != want {
			t.Errorf("Percent(%v) = %q, want %q", in, got, want)
		}
	}
	if Rate(1.25e6) != "10.0 Mbit/s" || Bytes(2.5e15) != "2.5 PB" || Bytes(12) != "12 B" {
		t.Error("Rate/Bytes")
	}
}
