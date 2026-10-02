package fleet

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/fleet/fleettest"
	"github.com/ljkx/tor-relay-setup/internal/keys"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

const contractPath = "../../docs/monitoring/fleet-metrics.md"

const (
	bridgeRealFP = "9683BB02DA999159D376414EA8D0B4BBBAF95103"
	bridgeHashed = "B2331AC0CA67CCA67C104B892DCCFA531B3DF50A"
	bridgeLine   = "obfs4 203.0.113.9:443 9683BB02DA999159D376414EA8D0B4BBBAF95103 cert=SECRETCERT iat-mode=0"
)

func loadSample(read, written uint64, dropped uint64) *metrics.Sample {
	return &metrics.Sample{At: t0, Read: read, Written: written, Connections: 120, Load: metrics.Load{
		Seen:                true,
		OnionskinsProcessed: metrics.Onionskins{Fast: 10, Ntor: 50_000, NtorV3: 20_000},
		OnionskinsDropped:   metrics.Onionskins{Ntor: dropped},
		OOMBytes:            metrics.OOMBytes{Cell: 4096},
		TCPExhaustion:       1, RateLimitRead: 3, RateLimitWrite: 4, SocketsOpen: 900, SocketsLimit: 65000,
	}}
}

// contractFleet is a fleet with every kind of relay the contract
// describes: a guard (IPv6, family), an exit, a relay with accounting and
// an offline master key, an overloaded relay, an obfs4 bridge, an
// unreachable host and a host whose tor-relay-setup is too old.
func contractFleet(t *testing.T) *Model {
	t.Helper()
	inv := entries(
		[4]string{"root@guard.example.net", "default", "Guard1", "x"},
		[4]string{"root@exit.example.net", "default", "Exit1", "x"},
		[4]string{"root@acct.example.net", "default", "Acct1", "x"},
		[4]string{"root@over.example.net", "default", "Over1", "x"},
		[4]string{"root@bridge.example.net", "default", "Bridge1", "x"},
		[4]string{"root@down.example.net", "default", "Down1", "x"},
		[4]string{"root@old.example.net", "default", "Old1", "x"},
	)
	inv.Entries[4].Setup.Relay.Mode = "bridge"
	m := NewModel(inv)

	guard := relayProbe(DefaultInstance, "Guard1", fp("1"), "0.4.9.3", true, famA)
	guard.Report.Relay.IPv6, guard.Report.Listener.IPv6, guard.Report.Reachability.IPv4 = true, true, true
	guard.Sample = loadSample(1_000_000, 2_000_000, 0)
	guard.Traffic = &Traffic{At: t0, Read: 1_000_000, Written: 2_000_000, Connections: 120}
	guard.Report.Keys = &keys.State{MasterOnDisk: true, Identity: "g", CertExpires: t0.Add(3 * 24 * time.Hour)} // tor renews it

	exit := relayProbe(DefaultInstance, "Exit1", fp("2"), "0.4.9.3", true, famA)
	exit.Report.Relay.Exit = true
	exit.Traffic = &Traffic{At: t0, Read: 5_000, Written: 6_000, Connections: 3} // an older host: traffic only

	acct := relayProbe(DefaultInstance, "Acct1", fp("3"), "0.4.9.3", true, famA)
	acct.Accounting = &metrics.Accounting{Enabled: true, Rule: "max", Max: 1 << 40, Used: 1 << 39, Projected: 1 << 40,
		PeriodStart: t0.Add(-15 * 24 * time.Hour), PeriodEnd: t0.Add(15 * 24 * time.Hour)}
	acct.Report.Keys = &keys.State{Offline: true, Identity: "x", CertExpires: t0.Add(5 * 24 * time.Hour)}

	over := relayProbe(DefaultInstance, "Over1", fp("4"), "0.4.8.16", true, famB)
	over.Sample = loadSample(10, 20, 2_000)

	bridge := relayProbe(DefaultInstance, "Bridge1", bridgeRealFP, "0.4.9.3", true)
	bridge.Report.Relay.Bridge = true
	bridge.Report.Bridge = &status.Bridge{Transport: "obfs4", Listening: true, HashedFingerprint: bridgeHashed, Line: bridgeLine, Port: 443}

	m.Apply(okAt("root@guard.example.net", guard))
	m.Apply(okAt("root@exit.example.net", exit))
	m.Apply(okAt("root@acct.example.net", acct))
	m.Apply(okAt("root@over.example.net", over))
	m.Apply(okAt("root@bridge.example.net", bridge))
	m.Apply(HostProbe{Address: "root@down.example.net", State: HostUnreachable, Detail: "Connection timed out", At: t0, Duration: 10 * time.Second})
	m.Apply(HostProbe{Address: "root@old.example.net", State: HostTooOld, At: t0, Duration: time.Second})
	m.EndRound(t0.Add(-3*time.Second), t0)

	m.SetDirectoryResult(DirectoryResult{At: t0, Details: map[string]*onionoo.Relay{
		fp("1"): {Running: true, Flags: []string{"Fast", "Guard", "HSDir", "Running", "Stable", "V2Dir", "Valid", "NoEdConsensus"},
			ConsensusWeight: 9000, ConsensusWeightFraction: 0.0001, GuardProbability: 0.0002, MiddleProbability: 0.0001,
			AdvertisedBandwidth: 30_000_000, ObservedBandwidth: 28_000_000, FirstSeen: "2025-01-02 03:04:05", LastRestarted: "2026-09-30 10:00:00",
			Country: "de", AS: "AS24940", ASName: "Hetzner Online GmbH"},
		fp("2"): {Running: true, Flags: []string{"Exit", "Fast", "Guard", "Running", "Valid"}, ConsensusWeight: 5000, ExitProbability: 0.0003,
			AdvertisedBandwidth: 10_000_000, ObservedBandwidth: 9_000_000, Country: "nl", AS: "AS60781", ASName: "LeaseWeb Netherlands B.V."},
		fp("3"): {Running: true, Flags: []string{"Fast", "Running", "Valid"}, ConsensusWeight: 100},
		fp("4"): {Running: true, Flags: []string{"Fast", "Running", "Valid", "BadExit", "MiddleOnly", "StaleDesc", "Authority"}, ConsensusWeight: 10,
			OverloadGeneral: t0.Add(-5 * time.Hour)},
	}, Bridges: map[string]*onionoo.Bridge{
		bridgeHashed: {Running: true, Flags: []string{"Running", "Valid"}, FirstSeen: "2026-09-01 10:00:00", AdvertisedBandwidth: 1_000_000},
	}})
	return m
}

func okAt(address string, relays ...RelayProbe) HostProbe {
	hp := ok(address, relays...)
	hp.Duration = 2 * time.Second
	return hp
}

func promText(t *testing.T, m *Model, opt PrometheusOptions) string {
	t.Helper()
	if opt.Now.IsZero() {
		opt.Now = t0
	}
	var b bytes.Buffer
	if err := m.WritePrometheus(&b, opt); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestPrometheusMatchesTheContract(t *testing.T) {
	c, err := fleettest.LoadContract(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) < 50 {
		t.Fatalf("contract parsed to only %d names", len(c))
	}
	out := promText(t, contractFleet(t), PrometheusOptions{})
	e, problems := c.Check(out, true)
	for _, p := range problems {
		t.Error(p)
	}
	if t.Failed() {
		t.Log(out)
	}
	for _, secret := range []string{bridgeRealFP, "SECRETCERT", "203.0.113.9"} {
		if strings.Contains(out, secret) {
			t.Errorf("the output contains %q", secret)
		}
	}

	one := func(name string, labels map[string]string, want float64) {
		t.Helper()
		got := e.Find(fleettest.Prefix+name, labels)
		if len(got) != 1 || got[0].Value != want {
			t.Errorf("%s%v = %+v, want one sample of %v", name, labels, got, want)
		}
	}
	none := func(name string, labels map[string]string) {
		t.Helper()
		if got := e.Find(fleettest.Prefix+name, labels); len(got) != 0 {
			t.Errorf("%s%v should be left out: %+v", name, labels, got)
		}
	}
	one("relays", nil, 7)
	one("relays_running", nil, 5)
	one("hosts", nil, 7)
	one("hosts_up", nil, 5)
	one("hosts_unreachable", nil, 1)
	one("hosts_without_probe", nil, 1)
	one("consensus_weight", nil, 14110)
	one("advertised_bandwidth_bytes", nil, 41_000_000) // bridges count
	one("observed_bandwidth_bytes", nil, 37_000_000)
	one("traffic_bytes_total", map[string]string{"direction": "read"}, 1_005_010)
	one("traffic_bytes_total", map[string]string{"direction": "written"}, 2_006_020)
	one("or_connections", nil, 243)
	one("probe_duration_seconds", nil, 3)
	one("last_probe_timestamp_seconds", nil, float64(t0.Unix()))
	one("directory_last_update_timestamp_seconds", nil, float64(t0.Unix()))

	one("host_up", map[string]string{"host": "down.example.net", "state": "unreachable"}, 1)
	one("host_up", map[string]string{"host": "down.example.net", "state": "ok"}, 0)
	one("host_up", map[string]string{"host": "old.example.net", "state": "no_probe"}, 1)
	one("host_tool_info", map[string]string{"host": "guard.example.net", "version": "v3.2.0"}, 1)
	none("host_tool_info", map[string]string{"host": "old.example.net"})
	none("host_last_success_timestamp_seconds", map[string]string{"host": "down.example.net"})
	one("host_probe_duration_seconds", map[string]string{"host": "down.example.net"}, 10)

	guard := map[string]string{"nickname": "Guard1", "role": "guard", "fingerprint": fp("1")}
	one("relay_info", map[string]string{"nickname": "Guard1", "country": "de", "as": "AS24940", "as_name": "Hetzner Online GmbH", "version": "0.4.9.3", "transport": ""}, 1)
	one("relay_listener", map[string]string{"nickname": "Guard1", "family": "ipv6"}, 1)
	one("relay_reachable", map[string]string{"nickname": "Guard1", "family": "ipv4"}, 1)
	one("relay_flag", map[string]string{"nickname": "Guard1", "flag": "HSDir"}, 1)
	none("relay_flag", map[string]string{"flag": "NoEdConsensus"})
	one("relay_first_seen_timestamp_seconds", guard, float64(time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC).Unix()))
	one("relay_traffic_bytes_total", map[string]string{"nickname": "Guard1", "direction": "written"}, 2_000_000)
	one("relay_onionskins_total", map[string]string{"nickname": "Guard1", "type": "ntor_v3", "action": "processed"}, 20_000)
	one("relay_family_consistent", guard, 1)
	one("relay_overloaded", guard, 0)

	one("relay_service_active", map[string]string{"nickname": "Exit1", "role": "exit"}, 1) // Exit and Guard flags: exit
	one("relay_traffic_bytes_total", map[string]string{"nickname": "Exit1", "direction": "read"}, 5_000)
	none("relay_onionskins_total", map[string]string{"nickname": "Exit1"}) // no load counters from an old host

	one("relay_accounting_used_bytes", map[string]string{"nickname": "Acct1"}, 1<<39)
	one("relay_signing_cert_expiry_timestamp_seconds", map[string]string{"nickname": "Acct1"}, float64(t0.Add(5*24*time.Hour).Unix()))
	one("relay_master_key_offline", map[string]string{"nickname": "Acct1"}, 1)
	one("relay_master_key_offline", map[string]string{"nickname": "Guard1"}, 0)
	none("relay_accounting_max_bytes", map[string]string{"nickname": "Guard1"})

	over := map[string]string{"nickname": "Over1", "role": "middle"}
	one("relay_overloaded", over, 1)
	one("relay_overload_general_timestamp_seconds", over, float64(t0.Add(-5*time.Hour).Unix()))
	one("relay_onionskins_total", map[string]string{"nickname": "Over1", "type": "ntor", "action": "dropped"}, 2_000)
	one("relay_family_consistent", over, 0)

	bridge := map[string]string{"nickname": "Bridge1", "role": "bridge", "fingerprint": bridgeHashed}
	one("relay_info", map[string]string{"nickname": "Bridge1", "transport": "obfs4"}, 1)
	one("relay_bridge_transport_listening", map[string]string{"nickname": "Bridge1", "transport": "obfs4"}, 1)
	one("relay_published", bridge, 1)
	one("relay_advertised_bandwidth_bytes", bridge, 1_000_000)
	none("relay_family_ids", bridge)
	none("relay_consensus_weight", bridge)

	down := map[string]string{"nickname": "Down1", "host": "down.example.net", "fingerprint": "", "role": "middle"}
	one("relay_info", down, 1)
	none("relay_service_active", down)
	none("relay_published", down)
}

func TestPrometheusPrivacyMode(t *testing.T) {
	c, err := fleettest.LoadContract(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	out := promText(t, contractFleet(t), PrometheusOptions{Privacy: true})
	e, problems := c.Check(out, false)
	for _, p := range problems {
		t.Error(p)
	}
	for _, name := range []string{"relay_traffic_bytes_total", "relay_or_connections"} {
		if _, ok := e.Types[fleettest.Prefix+name]; ok {
			t.Errorf("privacy mode exports %s", name)
		}
	}
	for _, name := range []string{"traffic_bytes_total", "or_connections", "relay_onionskins_total", "relay_info"} {
		if _, ok := e.Types[fleettest.Prefix+name]; !ok {
			t.Errorf("privacy mode lacks %s", name)
		}
	}
	for name := range c {
		if _, ok := e.Types[name]; !ok && name != fleettest.Prefix+"relay_traffic_bytes_total" && name != fleettest.Prefix+"relay_or_connections" {
			t.Errorf("privacy mode lacks %s", name)
		}
	}
}

func TestPrometheusLeavesUnknownValuesOut(t *testing.T) {
	m := NewModel(entries([4]string{"root@a", "default", "A", "x"}))
	out := promText(t, m, PrometheusOptions{})
	for _, absent := range []string{"consensus_weight", "or_connections", "probe_duration_seconds", "directory_last_update", "host_up", "relay_service_active", "relay_published"} {
		if strings.Contains(out, MetricPrefix+absent) {
			t.Errorf("%s exported before anything is known:\n%s", absent, out)
		}
	}
	for _, present := range []string{"tor_relay_fleet_relays 1\n", `tor_relay_fleet_traffic_bytes_total{direction="read"} 0`, `tor_relay_fleet_relay_info{host="a",tor_instance="default",nickname="A",fingerprint="",role="middle",version="",country="",as="",as_name="",transport=""} 1`} {
		if !strings.Contains(out, present) {
			t.Errorf("lacks %q:\n%s", present, out)
		}
	}
}

func TestFleetTrafficCounterOnlyGrows(t *testing.T) {
	m := NewModel(entries([4]string{"a", "default", "A", "x"}, [4]string{"b", "default", "B", "x"}, [4]string{"c", "default", "C", "x"}))
	probe := func(addr, nick string, read uint64) HostProbe {
		p := relayProbe(DefaultInstance, nick, "", "0.4.9.3", true)
		p.Sample = &metrics.Sample{At: t0, Read: read, Written: read}
		return ok(addr, p)
	}
	read := func() float64 { return m.Totals().TrafficRead }
	// First round: every relay adds its counters. c is unreachable.
	m.Apply(probe("a", "A", 1000))
	m.Apply(probe("b", "B", 500))
	m.Apply(HostProbe{Address: "c", State: HostUnreachable})
	m.EndRound(t0, t0)
	if read() != 1500 {
		t.Fatalf("after round 1: %v", read())
	}
	m.Apply(probe("a", "A", 1100))                           // +100
	m.Apply(probe("b", "B", 50))                             // tor restarted: +50
	m.Apply(probe("c", "C", 1_000_000))                      // first seen later: +0
	m.Apply(HostProbe{Address: "a", State: HostUnreachable}) // no change
	if read() != 1650 {
		t.Fatalf("after round 2: %v", read())
	}
	m.Apply(probe("a", "A", 1200)) // back: +100 since it was last counted
	m.Apply(probe("c", "C", 1_000_010))
	if read() != 1760 {
		t.Fatalf("after round 3: %v", read())
	}
}
