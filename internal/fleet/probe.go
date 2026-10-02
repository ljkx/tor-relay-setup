package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

// Probe is the document `tor-relay-setup fleet-probe` prints: the tool's
// version and one entry per relay on the host.
type Probe struct {
	Version string       `json:"version"`
	Relays  []RelayProbe `json:"relays"`
}

// RelayProbe is one relay's health report and, when its MetricsPort
// answered, one traffic sample.
type RelayProbe struct {
	Report  status.Report `json:"report"`
	Traffic *Traffic      `json:"traffic"`

	// instance is the report's "instance" field (multi-instance hosts);
	// older binaries leave it out, which means DefaultInstance.
	instance string
}

// Instance names the relay on its host.
func (p RelayProbe) Instance() string {
	if p.instance == "" {
		return DefaultInstance
	}
	return p.instance
}

// UnmarshalJSON decodes a relay entry and picks report.instance out of the
// report without depending on status.Report having that field.
func (p *RelayProbe) UnmarshalJSON(data []byte) error {
	type plain RelayProbe
	var raw struct {
		plain
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*p = RelayProbe(raw.plain)
	if len(raw.Report) == 0 || string(raw.Report) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw.Report, &p.Report); err != nil {
		return err
	}
	var id struct {
		Instance string `json:"instance"`
	}
	_ = json.Unmarshal(raw.Report, &id)
	p.instance = id.Instance
	return nil
}

// Traffic is one MetricsPort scrape.
type Traffic struct {
	At          time.Time `json:"at"`
	Read        uint64    `json:"read"`
	Written     uint64    `json:"written"`
	Connections int       `json:"connections"`
}

// Sample converts the traffic to a metrics sample.
func (t Traffic) Sample() metrics.Sample {
	return metrics.Sample{At: t.At, Read: t.Read, Written: t.Written, Connections: t.Connections}
}

// Scraper reads a MetricsPort; metrics.Scrape in production.
type Scraper func(ctx context.Context, metricsPort string) (metrics.Sample, error)

// metricsTimeout keeps a silent MetricsPort from slowing the probe down.
const metricsTimeout = time.Second

// ProbeLocal collects the probe document for this machine. It only reads:
// the status report without Tor Metrics (the dashboard asks Tor Metrics
// for the whole fleet at once) and one MetricsPort scrape per relay.
func ProbeLocal(ctx context.Context, h host.Host, version string, scrape Scraper) Probe {
	return Probe{Version: version, Relays: probeRelays(ctx, h, scrape)}
}

// probeRelays returns one probe per relay on this host: every discovered
// tor instance, or the default instance on a host not set up yet.
func probeRelays(ctx context.Context, h host.Host, scrape Scraper) []RelayProbe {
	insts, _ := relay.Discover(h)
	if len(insts) == 0 {
		insts = []relay.Instance{relay.DefaultInstance()}
	}
	out := make([]RelayProbe, 0, len(insts))
	for _, inst := range insts {
		r := status.Collect(ctx, h, status.Options{Instance: inst})
		out = append(out, RelayProbe{Report: r, Traffic: probeTraffic(ctx, r, scrape), instance: r.Instance})
	}
	return out
}

// probeTraffic scrapes the relay's MetricsPort, or returns nil when it has
// none, Tor is stopped, or it does not answer.
func probeTraffic(ctx context.Context, r status.Report, scrape Scraper) *Traffic {
	if r.Relay.MetricsPort == "" || !r.Service.Active || scrape == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, metricsTimeout)
	defer cancel()
	s, err := scrape(ctx, r.Relay.MetricsPort)
	if err != nil {
		return nil
	}
	return &Traffic{At: s.At.UTC(), Read: s.Read, Written: s.Written, Connections: s.Connections}
}

// ParseProbe finds the probe document in fleet-probe's output. The JSON is
// one line; anything else (sudo or ssh notices) is skipped.
func ParseProbe(output string) (Probe, error) {
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var p Probe
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			return Probe{}, err
		}
		if p.Version == "" {
			return Probe{}, errors.New("the probe document has no version")
		}
		return p, nil
	}
	return Probe{}, errors.New("no probe document in the output")
}
