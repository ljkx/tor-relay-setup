package relay

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderWithRealTor feeds every new torrc variant to a real tor binary:
//
//	TRS_REAL_TOR=/usr/bin/tor go test ./internal/relay -run RealTor -v
//
// It is skipped otherwise (CI runs tor in internal/integration). Recorded
// run: tor 0.4.9.13 accepted all variants below.
func TestRenderWithRealTor(t *testing.T) {
	bin := os.Getenv("TRS_REAL_TOR")
	if bin == "" {
		t.Skip("set TRS_REAL_TOR to a tor binary")
	}
	reduced := baseConfig()
	reduced.Mode, reduced.ExitPolicy = ModeExit, PolicyReduced
	web := reduced
	web.ExitPolicy, web.IPv6Exit, web.IPv6Address = PolicyWeb, true, "2001:db8::5"
	custom := reduced
	custom.ExitPolicy = PolicyCustom
	custom.ExitPolicyLines = []string{"accept *4:443", "accept [2001:db8::]/32:80-81", "reject private:*", "reject 18.0.0.0/8:*", "accept6 *6:22", "reject *:*"}
	notice := reduced
	notice.ExitNotice = filepath.Join(t.TempDir(), "tor-exit-notice.html")
	if err := os.WriteFile(notice.ExitNotice, RenderExitNotice("MyRelay01", "email:ops[]example.org"), 0o644); err != nil {
		t.Fatal(err)
	}
	offline := baseConfig()
	offline.OfflineMasterKey = true
	obfs4 := obfs4Config()
	obfs4.IPv6Address = "2001:db8::5"
	for name, c := range map[string]Config{
		"reduced": reduced, "web": web, "custom": custom, "notice": notice, "offline": offline,
		"obfs4": obfs4, "webtunnel": webTunnelConfig(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			torrc := filepath.Join(dir, "torrc")
			data := append(c.Render("trs", testNow), []byte("DataDirectory "+filepath.Join(dir, "data")+"\n")...)
			if err := os.WriteFile(torrc, data, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(bin, "-f", torrc, "--verify-config").CombinedOutput()
			if err != nil || !strings.Contains(string(out), "Configuration was valid") {
				t.Fatalf("tor rejected %s: %v\n%s\n%s", name, err, out, data)
			}
			for _, line := range strings.Split(string(out), "\n") {
				// "ORPort N superseded by ORPort [v6]:N" is tor's normal notice
				// for the dual-stack layout every relay of this tool uses.
				if strings.Contains(line, "[warn]") && !strings.Contains(line, "running Tor as root") && !strings.Contains(line, "superseded by ORPort [") {
					t.Errorf("tor warned: %s", line)
				}
			}
		})
	}
}
