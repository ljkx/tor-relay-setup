package serve

import (
	"context"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// liveSource probes over ssh and asks the real Tor Metrics.
type liveSource struct {
	probe func(ctx context.Context, address string) fleet.HostProbe
	dir   onionoo.Client
}

// NewLiveSource is the production Source: probe is remote.Fleet.Probe.
func NewLiveSource(probe func(ctx context.Context, address string) fleet.HostProbe, dir onionoo.Client) Source {
	return liveSource{probe: probe, dir: dir}
}

func (s liveSource) Probe(ctx context.Context, address string) fleet.HostProbe {
	return s.probe(ctx, address)
}

func (s liveSource) Directory(ctx context.Context, relays, bridges []string) fleet.DirectoryResult {
	return fleet.FetchDirectory(ctx, s.dir, relays, bridges, true)
}
