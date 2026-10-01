package update

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
)

// CacheFile is the name of the update-check cache inside the state
// directory.
const CacheFile = "update-check.json"

type cacheEntry struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest"`
}

// CheckCached returns the latest release tag, asking GitHub at most once
// per maxAge. The answer is kept in <stateDir>/update-check.json (mode
// 0600) as {"checked_at": ..., "latest": ...}; reading or writing the cache
// is best effort, so an unwritable state directory only costs an API call.
//
// When the lookup fails, CheckCached returns the stale cached tag (if any)
// together with the error, so callers such as the TUI header can keep
// showing a hint offline. Compare the result with UpdateAvailable:
//
//	latest, _ := update.CheckCached(ctx, "/var/lib/tor-relay-setup", 24*time.Hour)
//	if latest != "" && update.UpdateAvailable(version, latest) { ... }
func CheckCached(ctx context.Context, stateDir string, maxAge time.Duration) (latest string, err error) {
	return New("", io.Discard, false).CheckCached(ctx, stateDir, maxAge)
}

// CheckCached is the package-level CheckCached against u's API and clock.
func (u *Updater) CheckCached(ctx context.Context, stateDir string, maxAge time.Duration) (string, error) {
	p := filepath.Join(stateDir, CacheFile)
	now := u.Now()
	var cached cacheEntry
	if data, err := os.ReadFile(p); err == nil && json.Unmarshal(data, &cached) == nil && stableTag.MatchString(cached.Latest) {
		if age := now.Sub(cached.CheckedAt); age >= 0 && age < maxAge {
			return cached.Latest, nil
		}
	} else {
		cached = cacheEntry{}
	}
	latest, err := u.Latest(ctx)
	if err != nil {
		return cached.Latest, err
	}
	writeCache(p, cacheEntry{CheckedAt: now.UTC(), Latest: latest})
	return latest, nil
}

// writeCache replaces the cache file atomically, ignoring errors.
func writeCache(p string, e cacheEntry) {
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, "."+CacheFile+".tmp-*")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(append(data, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		return
	}
	// CreateTemp already uses mode 0600.
	_ = os.Rename(tmp.Name(), p)
}
