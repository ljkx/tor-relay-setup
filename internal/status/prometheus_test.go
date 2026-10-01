package status

import (
	"errors"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

const promHead = `# HELP tor_relay_setup_up 1 when tor-relay-setup collected this report.
# TYPE tor_relay_setup_up gauge
tor_relay_setup_up 1
# HELP tor_relay_setup_info Relay identity and tor version; the value is always 1.
# TYPE tor_relay_setup_info gauge
`

const promBody = `# HELP tor_relay_setup_relay_configured 1 when /etc/tor/torrc configures an ORPort.
# TYPE tor_relay_setup_relay_configured gauge
tor_relay_setup_relay_configured 1
# HELP tor_relay_setup_tor_installed 1 when the tor binary runs.
# TYPE tor_relay_setup_tor_installed gauge
tor_relay_setup_tor_installed 1
# HELP tor_relay_setup_tor_supported 1 when the installed tor version is accepted by the network.
# TYPE tor_relay_setup_tor_supported gauge
tor_relay_setup_tor_supported 1
# HELP tor_relay_setup_service_active 1 when the tor systemd unit is active.
# TYPE tor_relay_setup_service_active gauge
tor_relay_setup_service_active 1
# HELP tor_relay_setup_listener 1 when something listens on the ORPort, per address family.
# TYPE tor_relay_setup_listener gauge
tor_relay_setup_listener{family="ipv4"} 1
tor_relay_setup_listener{family="ipv6"} 0
# HELP tor_relay_setup_reachable 1 when Tor's self-test confirmed the ORPort is reachable from outside in the last 24 hours.
# TYPE tor_relay_setup_reachable gauge
tor_relay_setup_reachable{family="ipv4"} 1
tor_relay_setup_reachable{family="ipv6"} 0
# HELP tor_relay_setup_reachability_failed 1 when Tor reported that its ORPort self-test failed.
# TYPE tor_relay_setup_reachability_failed gauge
tor_relay_setup_reachability_failed 0
# HELP tor_relay_setup_family_ids Number of FamilyId lines in torrc.
# TYPE tor_relay_setup_family_ids gauge
tor_relay_setup_family_ids 2
# HELP tor_relay_setup_family_keys_missing Number of configured FamilyIds without an installed secret family key.
# TYPE tor_relay_setup_family_keys_missing gauge
tor_relay_setup_family_keys_missing 1
# HELP tor_relay_setup_legacy_myfamily_fingerprints Number of fingerprints in legacy MyFamily lines.
# TYPE tor_relay_setup_legacy_myfamily_fingerprints gauge
tor_relay_setup_legacy_myfamily_fingerprints 3
# HELP tor_relay_setup_warnings Number of problems that need attention (status exits 1 when this is not 0).
# TYPE tor_relay_setup_warnings gauge
tor_relay_setup_warnings 1
`

func promReport() Report {
	var r Report
	r.Tor.Installed, r.Tor.Supported, r.Tor.Version = true, true, "0.4.9.3"
	r.Service.Active = true
	r.Relay.Configured, r.Relay.Nickname = true, "MyRelay"
	r.Listener.IPv4 = true
	r.Reachability.IPv4 = true
	r.Family.IDs = []string{"a", "b"}
	r.Family.MissingKeys = []string{"b"}
	r.Family.LegacyCount = 3
	r.Warnings = []string{"no family key installed for FamilyId b"}
	return r
}

func prom(t *testing.T, r Report) string {
	t.Helper()
	var b strings.Builder
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestWritePrometheusWithoutFingerprint(t *testing.T) {
	got := prom(t, promReport())
	want := promHead + `tor_relay_setup_info{version="0.4.9.3",nickname="MyRelay",fingerprint=""} 1
` + promBody
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWritePrometheusWithDirectory(t *testing.T) {
	r := promReport()
	r.Relay.Fingerprint = strings.Repeat("A", 40)
	r.Directory = &onionoo.Relay{Running: true, ConsensusWeight: 1234, AdvertisedBandwidth: 5_000_000}
	got := prom(t, r)
	want := promHead + `tor_relay_setup_info{version="0.4.9.3",nickname="MyRelay",fingerprint="` + r.Relay.Fingerprint + `"} 1
` + promBody + `# HELP tor_relay_setup_directory_published 1 when Tor Metrics lists the relay.
# TYPE tor_relay_setup_directory_published gauge
tor_relay_setup_directory_published 1
# HELP tor_relay_setup_directory_running 1 when Tor Metrics reports the relay as running.
# TYPE tor_relay_setup_directory_running gauge
tor_relay_setup_directory_running 1
# HELP tor_relay_setup_consensus_weight Consensus weight reported by Tor Metrics.
# TYPE tor_relay_setup_consensus_weight gauge
tor_relay_setup_consensus_weight 1234
# HELP tor_relay_setup_advertised_bandwidth_bytes Advertised bandwidth in bytes per second, reported by Tor Metrics.
# TYPE tor_relay_setup_advertised_bandwidth_bytes gauge
tor_relay_setup_advertised_bandwidth_bytes 5000000
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if prom(t, r) != got {
		t.Error("output is not deterministic")
	}
}

func TestWritePrometheusDirectoryStates(t *testing.T) {
	r := promReport()
	r.Relay.Fingerprint = strings.Repeat("A", 40)
	// Tor Metrics answered without the relay: not published, nothing else.
	got := prom(t, r)
	if !strings.Contains(got, "\ntor_relay_setup_directory_published 0\n") || strings.Contains(got, "directory_running") || strings.Contains(got, "consensus_weight") {
		t.Errorf("unpublished relay:\n%s", got)
	}
	// The lookup failed: unknown, so no directory metrics at all.
	r.DirectoryError = "timeout"
	if got := prom(t, r); strings.Contains(got, "directory_") {
		t.Errorf("failed lookup exported directory metrics:\n%s", got)
	}
}

func TestWritePrometheusEscapesLabels(t *testing.T) {
	r := promReport()
	r.Relay.Nickname = "a\"b\\c\nd"
	got := prom(t, r)
	if !strings.Contains(got, `nickname="a\"b\\c\nd"`) {
		t.Errorf("label not escaped:\n%s", got)
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if line == "" {
			t.Errorf("empty line in output:\n%s", got)
		}
	}
	if escapeHelp("a\\b\nc") != `a\\b\nc` {
		t.Error("escapeHelp")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWritePrometheusReportsWriteErrors(t *testing.T) {
	if err := promReport().WritePrometheus(failWriter{}); err == nil {
		t.Error("write error was swallowed")
	}
}
