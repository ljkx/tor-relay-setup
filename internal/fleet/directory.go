package fleet

import (
	"context"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// DirectoryResult is one bulk Tor Metrics lookup of the fleet.
type DirectoryResult struct {
	Details map[string]*onionoo.Relay     // by fingerprint
	Bridges map[string]*onionoo.Bridge    // by hashed fingerprint
	History map[string]*onionoo.Bandwidth // by fingerprint; nil when not asked for or failed
	Err     error
	At      time.Time
}

// FetchDirectory asks Tor Metrics about the fleet in bulk: relay details
// by fingerprint, bridge details by hashed fingerprint only, and with
// history the relays' traffic history. A failed details lookup fails the
// result; a failed history lookup only leaves History nil.
func FetchDirectory(ctx context.Context, c onionoo.Client, relays, bridges []string, history bool) (res DirectoryResult) {
	defer func() { res.At = time.Now() }()
	if len(relays) > 0 {
		if res.Details, res.Err = c.DetailsBulk(ctx, relays); res.Err != nil {
			return res
		}
	}
	if len(bridges) > 0 {
		if res.Bridges, res.Err = c.BridgeDetailsBulk(ctx, bridges); res.Err != nil {
			return res
		}
	}
	if history && len(relays) > 0 {
		if bw, err := c.BandwidthBulk(ctx, relays); err == nil {
			res.History = bw
		}
	}
	return res
}
