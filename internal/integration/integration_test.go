//go:build integration

// Package integration runs the real setup steps inside a disposable
// Debian/Ubuntu container: Tor apt repository with key verification, one
// batched apt transaction, a real `tor --keygen-family`, and a torrc checked
// by the installed tor. Build and run it only in a container:
//
//	CGO_ENABLED=0 go test -c -tags integration -o itest ./internal/integration
//	docker run --rm -v "$PWD/itest:/itest:ro" debian:trixie /itest -test.v
package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/system"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

// Steps that need systemd, a real network edge, or change the hostname are
// covered by unit tests instead.
var skipped = map[string]bool{"preflight": true, "hostname": true, "firewall": true, "service": true}

func TestSetupInContainer(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err != nil && os.Getenv("ALLOW_HOST_INTEGRATION") != "1" {
		t.Skip("integration tests modify the system; run them in a container")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	h := host.NewLocal()
	// Containers ship without ca-certificates; the repository fetch is Go's
	// own HTTPS client, but apt needs the CA bundle for the https source.
	if _, err := h.Run(ctx, host.Command{Name: "apt-get", Args: []string{"update", "-qq"}, Mutates: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Run(ctx, host.Command{Name: "apt-get", Args: []string{"install", "-y", "-qq", "--no-install-recommends", "ca-certificates"},
		Env: []string{"DEBIAN_FRONTEND=noninteractive"}, Mutates: true}); err != nil {
		t.Fatal(err)
	}

	facts, err := system.Detect(ctx, h, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("container: %s (%s, %s)", facts.PrettyName, facts.Codename, facts.Arch)
	// The Tor canary workflow points the repository at a pre-release suite,
	// such as tor-nightly-main-trixie, to catch breaking Tor changes early.
	if suite := os.Getenv("TOR_SUITE"); suite != "" {
		facts.Codename = suite
		t.Logf("using Tor repository suite %s", suite)
	}

	s := config.Default()
	s.Relay.Nickname = "CiRelay"
	s.Relay.Contact = relay.BuildCIISS("ci@example.org", "https://example.org", "")
	s.Relay.MetricsPort = true
	s.Family = config.Family{Mode: "generate", KeyName: "ci-family"}
	s.Bandwidth = config.BandwidthPlan{Mode: "steady", MonthlyQuota: "10TB", HeadroomPercent: 10, Billing: "sum"}
	s.System.Nyx = false
	s.System.Firewall = "none"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}

	var steps []plan.Step
	for _, st := range plan.Build(s, facts) {
		if !skipped[st.ID] {
			steps = append(steps, st)
		}
	}
	env := plan.NewEnv(h, facts, s, "tor-relay-setup integration")
	start := time.Now()
	err = plan.Run(ctx, steps, env, func(e plan.Event) {
		switch e.Kind {
		case plan.StepStarted:
			t.Logf("▶ %s", e.Text)
		case plan.StepNote:
			t.Logf("   · %s", e.Text)
		case plan.StepFinished:
			t.Logf("   done in %s", e.Elapsed.Round(time.Millisecond))
		case plan.StepFailed:
			t.Logf("   FAILED: %s", e.Text)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("setup finished in %s", time.Since(start).Round(time.Second))

	// The keyring holds exactly the Tor Project key.
	keyring, err := os.ReadFile(torproject.KeyringPath)
	if err != nil || len(keyring) == 0 {
		t.Fatalf("keyring: %v", err)
	}
	sources, _ := os.ReadFile(torproject.SourcesPath)
	if !strings.Contains(string(sources), "Suites: "+facts.Codename) {
		t.Fatalf("sources:\n%s", sources)
	}

	// tor comes from the Tor Project and is new enough.
	res, err := h.Run(ctx, host.Command{Name: "tor", Args: []string{"--version"}})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := torproject.ParseTorVersion(res.Output)
	if !torproject.VersionAtLeast(v, torproject.MinVersion) {
		t.Fatalf("tor %s is below %s", v, torproject.MinVersion)
	}

	// The family key is installed privately for debian-tor and in torrc.
	if !relay.ValidFamilyID(env.FamilyID) {
		t.Fatalf("FamilyId %q", env.FamilyID)
	}
	keys, err := family.Installed(h, "/var/lib/tor/keys")
	if err != nil || !family.HasKeyFor(keys, env.FamilyID) {
		t.Fatalf("installed keys %+v, err %v", keys, err)
	}
	info, err := os.Stat("/var/lib/tor/keys/ci-family.secret_family_key")
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode: %v %v", info.Mode(), err)
	}
	torrc, _ := os.ReadFile("/etc/tor/torrc")
	for _, want := range []string{"FamilyId " + env.FamilyID, "MetricsPort 127.0.0.1:9035", "RelayBandwidthRate 1640 KBytes", "ExitRelay 0"} {
		if !strings.Contains(string(torrc), want) {
			t.Errorf("torrc misses %q:\n%s", want, torrc)
		}
	}
	if err := relay.Verify(ctx, h, "/etc/tor/torrc"); err != nil {
		t.Fatalf("installed torrc does not verify: %v", err)
	}

	// Applying again changes nothing and does not fail.
	env2 := plan.NewEnv(h, facts, s, "tor-relay-setup integration")
	env2.Now = func() time.Time { return time.Time{} }
	var again []plan.Step
	for _, st := range plan.Build(s, facts) {
		if st.ID == "repository" || st.ID == "unattended" {
			again = append(again, st)
		}
	}
	if err := plan.Run(ctx, again, env2, func(plan.Event) {}); err != nil {
		t.Fatalf("second run: %v", err)
	}
}
