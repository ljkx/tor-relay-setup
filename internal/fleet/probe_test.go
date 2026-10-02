package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
)

const probeTorrc = `Nickname ProbeRelay
ContactInfo "ops@example.org"
ORPort 9001
MetricsPort 127.0.0.1:9035
`

// relayHost is a fake relay: tor installed, the unit active or not.
func relayHost(torrc string, active bool) *host.Fake {
	f := host.NewFake()
	f.Files["/etc/tor/torrc"] = []byte(torrc)
	f.Files["/var/lib/tor/fingerprint"] = []byte("ProbeRelay ABCDEF0123456789ABCDEF0123456789ABCDEF01\n")
	f.Files["/proc/net/tcp"] = []byte("  sl  local_address rem_address   st\n   0: 00000000:2329 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1\n")
	f.Handler = func(c host.Command) (host.Result, error) {
		switch {
		case c.Name == "tor":
			return host.Result{Output: "Tor version 0.4.9.3.\n"}, nil
		case c.Name == "systemctl" && !active:
			return host.Result{ExitCode: 3}, &host.ExitError{ExitCode: 3}
		}
		return host.Result{}, nil
	}
	return f
}

func TestProbeLocalJSONShape(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var scraped string
	scrape := func(_ context.Context, addr string) (metrics.Sample, error) {
		scraped = addr
		return metrics.Sample{At: at, Read: 1000, Written: 2000, Connections: 42}, nil
	}
	h := relayHost(probeTorrc, true)
	p := ProbeLocal(context.Background(), h, "v9.9.9", scrape)
	for _, c := range h.Commands {
		if c.Mutates {
			t.Errorf("the probe ran a mutating command: %s", c)
		}
	}
	if scraped != "127.0.0.1:9035" {
		t.Errorf("scraped %q", scraped)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if keysOf(doc) != "relays version" || doc["version"] != "v9.9.9" {
		t.Errorf("top level: %s", data)
	}
	relays := doc["relays"].([]any)
	if len(relays) != 1 {
		t.Fatalf("relays: %s", data)
	}
	r := relays[0].(map[string]any)
	if keysOf(r) != "report sample traffic" {
		t.Errorf("relay keys: %s", keysOf(r))
	}
	if sample := r["sample"].(map[string]any); sample["connections"] != 42.0 || sample["load"] == nil {
		t.Errorf("sample: %v", sample)
	}
	traffic := r["traffic"].(map[string]any)
	if keysOf(traffic) != "at connections read written" || traffic["at"] != "2026-10-01T12:00:00Z" || traffic["read"] != 1000.0 || traffic["connections"] != 42.0 {
		t.Errorf("traffic: %v", traffic)
	}
	report := r["report"].(map[string]any)
	if report["relay"].(map[string]any)["nickname"] != "ProbeRelay" || report["service"].(map[string]any)["active"] != true {
		t.Errorf("report: %v", report)
	}
	if _, ok := report["directory"]; ok {
		t.Error("fleet-probe must not ask Tor Metrics")
	}

	// The document reads back, with the default instance.
	back, err := ParseProbe("sudo: unable to resolve host relay1\n" + string(data) + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if back.Version != "v9.9.9" || back.Relays[0].Instance() != DefaultInstance || back.Relays[0].Report.Relay.Fingerprint != "ABCDEF0123456789ABCDEF0123456789ABCDEF01" {
		t.Errorf("parsed back: %+v", back)
	}
	if !reflect.DeepEqual(*back.Relays[0].Traffic, *p.Relays[0].Traffic) {
		t.Errorf("traffic: %+v", back.Relays[0].Traffic)
	}
}

func keysOf(m map[string]any) string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	sort.Strings(k)
	return strings.Join(k, " ")
}

func TestProbeTrafficIsNullWithoutAnAnsweringMetricsPort(t *testing.T) {
	failing := func(context.Context, string) (metrics.Sample, error) { return metrics.Sample{}, errors.New("refused") }
	called := false
	counting := func(context.Context, string) (metrics.Sample, error) {
		called = true
		return metrics.Sample{}, nil
	}
	tests := []struct {
		name   string
		h      *host.Fake
		scrape Scraper
	}{
		{"not answering", relayHost(probeTorrc, true), failing},
		{"no MetricsPort", relayHost(strings.Replace(probeTorrc, "MetricsPort 127.0.0.1:9035\n", "", 1), true), counting},
		{"tor stopped", relayHost(probeTorrc, false), counting},
	}
	for _, tt := range tests {
		p := ProbeLocal(context.Background(), tt.h, "v1", tt.scrape)
		if p.Relays[0].Traffic != nil {
			t.Errorf("%s: traffic = %+v", tt.name, p.Relays[0].Traffic)
		}
		data, _ := json.Marshal(p)
		if !strings.Contains(string(data), `"traffic":null`) {
			t.Errorf("%s: %s", tt.name, data)
		}
	}
	if called {
		t.Error("scraped without a MetricsPort or with tor stopped")
	}
}

func TestParseProbe(t *testing.T) {
	good := `{"version":"v3.2.0","relays":[{"report":{"instance":"second","relay":{"nickname":"Two"}},"traffic":null}]}`
	p, err := ParseProbe("Warning: Permanently added 'x' to the list of known hosts.\n" + good + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if r := p.Relays[0]; r.Instance() != "second" || r.Report.Relay.Nickname != "Two" || r.Traffic != nil {
		t.Errorf("relay = %+v", r)
	}
	for _, bad := range []string{"", "no json here\n", "{not json}\n", `{"relays":[]}`} {
		if _, err := ParseProbe(bad); err == nil {
			t.Errorf("ParseProbe(%q) accepted", bad)
		}
	}
	// A relay without a report is tolerated.
	if p, err := ParseProbe(`{"version":"v1","relays":[{"report":null,"traffic":null}]}`); err != nil || p.Relays[0].Instance() != DefaultInstance {
		t.Errorf("null report: %+v, %v", p, err)
	}
}

func TestParseProbeFromAnOlderHost(t *testing.T) {
	// v3.2.0's document: report and traffic only.
	old := `{"version":"v3.2.0","relays":[{"report":{"collected_at":"2026-10-01T12:00:00Z","instance":"default","tor":{"installed":true,"version":"0.4.9.3","supported":true},` +
		`"service":{"unit":"tor@default","active":true},"relay":{"configured":true,"nickname":"Old","fingerprint":"` + fp("1") + `","or_port":9001},` +
		`"listener":{"ipv4":true,"ipv6":false},"family":{"legacy_myfamily":0}},"traffic":{"at":"2026-10-01T12:00:00Z","read":10,"written":20,"connections":3}}]}`
	p, err := ParseProbe(old)
	if err != nil {
		t.Fatal(err)
	}
	r := p.Relays[0]
	if r.Sample != nil || r.Accounting != nil || r.Report.Keys != nil || r.Report.Bridge != nil {
		t.Errorf("fields an old host cannot send: %+v", r)
	}
	s := r.MetricsSample()
	if s == nil || s.Read != 10 || s.Written != 20 || s.Connections != 3 || s.Load.Seen {
		t.Errorf("sample from traffic = %+v", s)
	}
	if (RelayProbe{}).MetricsSample() != nil {
		t.Error("no traffic, no sample")
	}
}

func TestProbeCarriesAccountingKeysAndBridgeButNoBridgeLine(t *testing.T) {
	torrc := "Nickname ProbeBridge\nORPort 9001\nBridgeRelay 1\nServerTransportPlugin obfs4 exec /usr/bin/lyrebird\nServerTransportListenAddr obfs4 0.0.0.0:443\n" +
		"ExtORPort auto\nAccountingMax 100 GBytes\nAccountingStart month 1 00:00\n"
	h := relayHost(torrc, true)
	h.Files["/usr/bin/lyrebird"] = []byte("binary")
	h.Files["/var/lib/tor/bridgelines"] = []byte("Bridge obfs4 203.0.113.9:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=SECRETCERT iat-mode=0\n")
	h.Files["/var/lib/tor/state"] = []byte("AccountingBytesReadInInterval 1000\nAccountingBytesWrittenInInterval 2000\nAccountingIntervalStart 2026-10-01 00:00:00\nLastWritten 2099-10-01 00:00:00\n")
	p := ProbeLocal(context.Background(), h, "v9", nil)
	r := p.Relays[0]
	if r.Accounting == nil || !r.Accounting.Enabled || r.Accounting.Max != 100<<30 {
		t.Errorf("accounting = %+v (%s)", r.Accounting, r.AccountingError)
	}
	if r.Report.Bridge == nil || r.Report.Bridge.HashedFingerprint == "" || r.Report.Keys == nil {
		t.Fatalf("bridge %+v keys %+v", r.Report.Bridge, r.Report.Keys)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SECRETCERT") || strings.Contains(string(data), "203.0.113.9") {
		t.Errorf("the bridge line is in the probe document: %s", data)
	}
	if !strings.Contains(string(data), `"accounting":{"enabled":true`) || !strings.Contains(string(data), `"hashed_fingerprint"`) {
		t.Errorf("document: %s", data)
	}
}
