package onionoo

import (
	"context"
	"crypto/sha1" //nolint:gosec // Onionoo identifies bridges by SHA-1 of the fingerprint; not a security use.
	"encoding/hex"
	"net/url"
	"strings"
	"time"
)

// HashFingerprint returns the hashed fingerprint Onionoo and the bridge
// authority use for a bridge: SHA-1 over the 20 bytes of the fingerprint
// (not its hex text), as 40 upper-case hex digits. tor writes the same
// value to DataDirectory/hashed-fingerprint. Onionoo asks clients to send
// only hashed fingerprints so a bridge's real fingerprint never appears in
// a URL (metrics.torproject.org/onionoo.html, parameter "lookup").
func HashFingerprint(fingerprint string) (string, error) {
	fp, err := NormalizeFingerprint(fingerprint)
	if err != nil {
		return "", err
	}
	raw, _ := hex.DecodeString(fp)
	sum := sha1.Sum(raw) //nolint:gosec // see the import comment
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// Bridge is the subset of an Onionoo bridge details document the console
// shows. Addresses are sanitized by Onionoo and not included.
type Bridge struct {
	Nickname            string   `json:"nickname"`
	HashedFingerprint   string   `json:"hashed_fingerprint"`
	Running             bool     `json:"running"`
	Flags               []string `json:"flags,omitempty"`
	FirstSeen           string   `json:"first_seen,omitempty"`
	LastSeen            string   `json:"last_seen,omitempty"`
	LastRestarted       string   `json:"last_restarted,omitempty"`
	AdvertisedBandwidth int64    `json:"advertised_bandwidth,omitempty"`
	Platform            string   `json:"platform,omitempty"`
	Version             string   `json:"version,omitempty"`
	VersionStatus       string   `json:"version_status,omitempty"`
	RecommendedVersion  *bool    `json:"recommended_version,omitempty"`
	// Transports lists the pluggable transports the bridge offers.
	Transports []string `json:"transports,omitempty"`
	// Distributor is the BridgeDB distributor the bridge is assigned to;
	// empty while it is not assigned (new bridges show none for about a day).
	Distributor string `json:"bridgedb_distributor,omitempty"`
	// Blocklist names countries where the bridge is not handed out because
	// it is believed to be blocked there.
	Blocklist []string `json:"blocklist,omitempty"`
	// OverloadGeneralMS is Onionoo's overload_general_timestamp in
	// milliseconds since the epoch; 0 when unset. See OverloadGeneral.
	OverloadGeneralMS int64 `json:"overload_general_timestamp,omitempty"`
}

// OverloadGeneral is the hour of the bridge's last overload-general event,
// or the zero time.
func (b *Bridge) OverloadGeneral() time.Time {
	if b == nil || b.OverloadGeneralMS <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(b.OverloadGeneralMS).UTC()
}

// Overloaded reports whether Relay Search shows the bridge as overloaded.
func (b *Bridge) Overloaded(now time.Time) bool {
	o := b.OverloadGeneral()
	return !o.IsZero() && now.Sub(o) < OverloadWindow
}

// BridgeDetailsBulk looks up many bridges by their hashed fingerprints
// (never the real ones, which must not appear in a URL), BulkChunk per
// request, and returns the published ones by hashed fingerprint.
func (c Client) BridgeDetailsBulk(ctx context.Context, hashed []string) (map[string]*Bridge, error) {
	groups, err := chunks(hashed)
	if err != nil {
		return nil, err
	}
	out := map[string]*Bridge{}
	for _, g := range groups {
		var doc struct {
			Bridges []Bridge `json:"bridges"`
		}
		if err := c.get(ctx, "/details", url.Values{"lookup": {strings.Join(g, ",")}, "type": {"bridge"}}, &doc); err != nil {
			return nil, err
		}
		for i := range doc.Bridges {
			if h, err := NormalizeFingerprint(doc.Bridges[i].HashedFingerprint); err == nil {
				out[h] = &doc.Bridges[i]
			}
		}
	}
	return out, nil
}

// BridgeDetails returns the published details of the bridge with this
// fingerprint, or (nil, nil) when Onionoo does not list it (about three
// hours after the first start). Only the hashed fingerprint is sent.
func (c Client) BridgeDetails(ctx context.Context, fingerprint string) (*Bridge, error) {
	hashed, err := HashFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Bridges []Bridge `json:"bridges"`
	}
	if err := c.get(ctx, "/details", url.Values{"lookup": {hashed}, "type": {"bridge"}}, &doc); err != nil {
		return nil, err
	}
	if len(doc.Bridges) == 0 {
		return nil, nil
	}
	return &doc.Bridges[0], nil
}
