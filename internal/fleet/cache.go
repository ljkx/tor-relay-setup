package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// FlagCache remembers each relay's tracked flags between dashboard runs,
// so a lost Guard or Stable flag shows up the next time.
type FlagCache struct {
	Saved time.Time           `json:"saved"`
	Flags map[string][]string `json:"flags"` // fingerprint → tracked flags
}

// CachePath is the flag cache of one inventory under the user's cache
// directory: tor-relay-setup/fleet-<hash>.json, the hash taken over the
// inventory's absolute path (or its addresses for a one-off list).
func CachePath(cacheDir string, inv Inventory) string {
	key := inv.Path
	if abs, err := filepath.Abs(inv.Path); err == nil && inv.Path != "" {
		key = abs
	}
	if inv.Path == "" {
		key = strings.Join(inv.Addresses(), "\n")
	}
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(cacheDir, "tor-relay-setup", "fleet-"+hex.EncodeToString(sum[:8])+".json")
}

// LoadFlagCache reads the cache; a missing or unreadable cache is empty.
func LoadFlagCache(h host.Host, path string) FlagCache {
	var c FlagCache
	if data, err := h.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &c)
	}
	return c
}

// SaveFlagCache writes the tracked flags of the published relays (mode
// 0600). Relays missing from details keep their previous entry, so a
// relay that drops out of Tor Metrics for a while is still compared later.
func SaveFlagCache(h host.Host, path string, prev FlagCache, details map[string]*onionoo.Relay, now time.Time) error {
	c := FlagCache{Saved: now.UTC(), Flags: map[string][]string{}}
	for fp, flags := range prev.Flags {
		c.Flags[fp] = flags
	}
	for fp, d := range details {
		if d == nil {
			continue
		}
		var tracked []string
		for _, f := range trackedFlags {
			if slices.Contains(d.Flags, f) {
				tracked = append(tracked, f)
			}
		}
		c.Flags[fp] = tracked
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := h.MkdirAll(filepath.Dir(path), 0o700, ""); err != nil {
		return err
	}
	_, err = h.WriteFile(path, append(data, '\n'), host.FileOptions{Mode: 0o600})
	return err
}
