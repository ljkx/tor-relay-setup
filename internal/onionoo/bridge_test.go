package onionoo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The fingerprint pair tor 0.4.9.13 wrote for a test bridge: fingerprint
// and hashed-fingerprint in its DataDirectory, and the start-up notice
// "Your Tor bridge's hashed identity key fingerprint is ...".
const (
	bridgeFP     = "9683BB02DA999159D376414EA8D0B4BBBAF95103"
	bridgeHashed = "B2331AC0CA67CCA67C104B892DCCFA531B3DF50A"
)

func TestHashFingerprintMatchesTor(t *testing.T) {
	t.Parallel()
	for _, in := range []string{bridgeFP, "$" + strings.ToLower(bridgeFP), "9683 BB02 DA99 9159 D376 414E A8D0 B4BB BAF9 5103"} {
		got, err := HashFingerprint(in)
		if err != nil || got != bridgeHashed {
			t.Errorf("HashFingerprint(%q) = %q, %v; want %s", in, got, err, bridgeHashed)
		}
	}
	if _, err := HashFingerprint("nope"); err == nil {
		t.Error("invalid fingerprint accepted")
	}
}

func TestBridgeDetails(t *testing.T) {
	t.Parallel()
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		if r.URL.Query().Get("lookup") != bridgeHashed {
			_, _ = w.Write([]byte(`{"version":"8.0","relays":[],"bridges":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"version":"8.0","relays":[],"bridges":[{"nickname":"brtest","hashed_fingerprint":"` + bridgeHashed + `",
			"or_addresses":["10.143.1.2:9443"],"running":true,"flags":["Running","Stable","Valid"],
			"first_seen":"2026-09-01 10:00:00","last_seen":"2026-10-02 12:00:00","advertised_bandwidth":1250000,
			"version":"0.4.9.13","version_status":"recommended","recommended_version":true,
			"transports":["obfs4"],"bridgedb_distributor":"moat","blocklist":["ru"]}]}`))
	}))
	defer srv.Close()
	c := Client{Base: srv.URL}
	b, err := c.BridgeDetails(context.Background(), bridgeFP)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(query, bridgeFP) {
		t.Errorf("the real bridge fingerprint was sent: %s", query)
	}
	if b == nil || !b.Running || b.Distributor != "moat" || len(b.Transports) != 1 || b.Transports[0] != "obfs4" ||
		len(b.Blocklist) != 1 || b.VersionStatus != "recommended" || b.RecommendedVersion == nil || !*b.RecommendedVersion {
		t.Errorf("BridgeDetails = %+v", b)
	}

	unknown, err := c.BridgeDetails(context.Background(), strings.Repeat("A", 40))
	if err != nil || unknown != nil {
		t.Errorf("unlisted bridge = %+v, %v", unknown, err)
	}
	if _, err := c.BridgeDetails(context.Background(), "bad"); err == nil {
		t.Error("bad fingerprint accepted")
	}
}
