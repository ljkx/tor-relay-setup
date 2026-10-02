package keys

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// TestRenewWithRealTor runs the whole offline-key cycle against a real tor:
//
//	TRS_REAL_TOR=/usr/bin/tor go test ./internal/keys -run RealTor -v
//
// tor --keygen makes a master key, Renew makes a new signing key from it the
// way `keys renew --master` does, and InstallSigning accepts it for a relay
// key directory holding only the public key. Recorded run: tor 0.4.9.13.
func TestRenewWithRealTor(t *testing.T) {
	bin := os.Getenv("TRS_REAL_TOR")
	if bin == "" {
		t.Skip("set TRS_REAL_TOR to a tor binary")
	}
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	master := t.TempDir()
	empty := filepath.Join(master, "empty.torrc")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "--defaults-torrc", empty, "-f", empty, "--keygen", "--no-passphrase",
		"--DataDirectory", master, "--SigningKeyLifetime", "2 days").CombinedOutput(); err != nil {
		t.Fatalf("tor --keygen: %v\n%s", err, out)
	}
	h := host.NewLocal()
	secret, cert, err := Renew(context.Background(), h, filepath.Join(master, "keys"), "30 days")
	if err != nil {
		t.Fatal(err)
	}
	relayKeys := t.TempDir()
	pub, err := os.ReadFile(filepath.Join(master, "keys", MasterPublic))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(relayKeys, MasterPublic), pub, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := InstallSigning(h, relayKeys, "", secret, cert, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(c.Expires); left < 29*24*time.Hour || left > 31*24*time.Hour {
		t.Errorf("renewed certificate expires %s, want about 30 days from now", c.Expires)
	}
	// tor itself agrees on the expiry.
	out, err := exec.Command(bin, "--defaults-torrc", empty, "-f", empty, "--DataDirectory", filepath.Dir(relayKeys),
		"--KeyDirectory", relayKeys, "--key-expiration", "sign", "--format", "timestamp").CombinedOutput()
	if err != nil {
		t.Fatalf("tor --key-expiration: %v\n%s", err, out)
	}
	if want := strconv.FormatInt(c.Expires.Unix(), 10); !strings.Contains(string(out), want) {
		t.Errorf("tor --key-expiration says %s, parsed %s", out, want)
	}
}
