package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/status"
	"github.com/ljkx/tor-relay-setup/internal/tui"
)

func TestFleetUsageErrors(t *testing.T) {
	clearRoot(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"--host with fleet", []string{"fleet", "--host", "a"}, "--host is only used with apply"},
		{"--inventory with status", []string{"status", "--inventory", "f.toml"}, "--inventory is only used with apply and fleet"},
		{"--inventory and --host", []string{"apply", "--inventory", "f.toml", "--host", "a"}, "use either --inventory or --host"},
		{"--inventory and --config", []string{"apply", "--inventory", "f.toml", "--config", "c.toml"}, "--config is not used with --inventory"},
		{"--parallel without fleet", []string{"apply", "--config", "c.toml", "--parallel", "2"}, "--parallel needs apply --inventory or --host"},
		{"--parallel too high", []string{"apply", "--inventory", "f.toml", "--parallel", "99"}, "--parallel must be 1–64"},
		{"--only with status", []string{"status", "--only", "a"}, "--only needs"},
		{"--keep-going with the dashboard", []string{"fleet", "--keep-going"}, "--keep-going needs"},
		{"unknown fleet command", []string{"fleet", "frob"}, `unknown fleet command "frob"`},
		{"tor without a verb", []string{"tor"}, "tor needs restart, reload, or update"},
		{"tor with an unknown verb", []string{"tor", "stop"}, "tor needs restart, reload, or update"},
		{"extra argument after a subcommand", []string{"fleet", "status", "extra"}, `unexpected argument "extra"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tt.args...)
			if code != 2 || !strings.Contains(errOut, tt.want) || out != "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want 2 and %q", code, out, errOut, tt.want)
			}
		})
	}
}

func TestHelpListsFleetCommands(t *testing.T) {
	clearRoot(t)
	_, out, _ := runCLI(t, "--help")
	for _, want := range []string{
		"tor-relay-setup apply --inventory FILE [--parallel N] [--only HOST[,HOST]] [--keep-going]",
		"tor-relay-setup fleet [--inventory FILE]",
		"tor-relay-setup fleet status [--format text|json|prometheus]",
		"tor-relay-setup fleet restart|reload|update-tor",
		"tor-relay-setup tor restart|reload|update [--yes]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

func TestFleetProbeCommand(t *testing.T) {
	stubPath(t)
	torrc := strings.Replace(fixtureTorrc, "FAMILY", famA, 1)
	t.Setenv("TOR_RELAY_SETUP_ROOT", fixtureRoot(t, torrc))
	code, out, errOut := runCLI(t, "fleet-probe", "--dry-run")
	if code != 0 || strings.Count(out, "\n") != 1 {
		t.Fatalf("exit %d, stderr %q, want one line:\n%s", code, errOut, out)
	}
	p, err := fleet.ParseProbe(out)
	if err != nil {
		t.Fatal(err)
	}
	r := p.Relays[0]
	if p.Version == "" || r.Report.Relay.Nickname != "FixtureRelay" || !r.Report.Service.Active || r.Traffic != nil || r.Instance() != "default" {
		t.Errorf("probe = %+v", p)
	}
	if !strings.Contains(out, `"traffic":null`) {
		t.Errorf("no MetricsPort means traffic null: %s", out)
	}

	// With a MetricsPort the probe scrapes it once.
	orig := scrape
	t.Cleanup(func() { scrape = orig })
	scrape = func(_ context.Context, addr string) (metrics.Sample, error) {
		if addr != "127.0.0.1:9035" {
			return metrics.Sample{}, errors.New("wrong address " + addr)
		}
		return metrics.Sample{Read: 5, Written: 6, Connections: 7}, nil
	}
	t.Setenv("TOR_RELAY_SETUP_ROOT", fixtureRoot(t, torrc+"MetricsPort 127.0.0.1:9035\n"))
	_, out, _ = runCLI(t, "fleet-probe", "--dry-run")
	if p, err := fleet.ParseProbe(out); err != nil || p.Relays[0].Traffic == nil || p.Relays[0].Traffic.Connections != 7 {
		t.Errorf("traffic: %v %s", err, out)
	}
}

// writeInventory writes relay.toml and fleet.toml for three relays.
func writeInventory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"relay.toml": "[relay]\nnickname = \"Base\"\ncontact = \"ops@example.org\"\n[bandwidth]\nmonthly_quota = \"10TB\"\n",
		"fleet.toml": "config = \"relay.toml\"\nnickname = \"Fleet{n}\"\n[[host]]\naddress = \"root@relay-1\"\n[[host]]\naddress = \"relay-2\"\n[[host]]\naddress = \"relay-3\"\nrelay = { or_port = 443 }\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "fleet.toml")
}

func TestApplyInventory(t *testing.T) {
	clearRoot(t)
	fake := fakeFleet(t)
	inv := writeInventory(t)
	code, out, errOut := runCLI(t, "apply", "--inventory", inv, "--dry-run", "--parallel", "2", "--only", "relay-2,Fleet3")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q\n%s", code, errOut, out)
	}
	for _, want := range []string{"==> [1/2] relay-2", "==> [2/2] relay-3", "relay-2  Fleet2  ok", "relay-3  Fleet3  ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if fake.Ran("relay-1") {
		t.Errorf("--only ran on relay-1:\n%s", strings.Join(fake.CommandLines(), "\n"))
	}

	// Validation happens before connecting.
	fake.Commands = nil
	for _, args := range [][]string{
		{"apply", "--inventory", inv, "--only", "relay-9"},
		{"apply", "--inventory", filepath.Join(t.TempDir(), "absent.toml")},
	} {
		if code, _, errOut := runCLI(t, args...); code != 1 || !strings.HasPrefix(errOut, "error: ") {
			t.Errorf("%q: exit %d, stderr %q", args, code, errOut)
		}
	}
	if len(fake.Commands) != 0 {
		t.Errorf("connected despite an invalid inventory: %q", fake.CommandLines())
	}

	// --only also narrows a --host list.
	cfg := filepath.Join(filepath.Dir(inv), "relay.toml")
	code, out, _ = runCLI(t, "apply", "--dry-run", "--config", cfg, "--host", "relay-1", "--host", "relay-2", "--only", "relay-2")
	if code != 0 || strings.Contains(out, "==> [1/2]") || !strings.Contains(out, "==> [1/1] relay-2") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// fleetHosts answers fleet-probe and `tor VERB` over the fake ssh: relay-2
// is unreachable unless healthy is set.
func fleetHosts(t *testing.T, fake *host.Fake, healthy bool) *[]string {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	fake.Handler = func(c host.Command) (host.Result, error) {
		dest, script := c.Args[len(c.Args)-2], c.Args[len(c.Args)-1]
		mu.Lock()
		defer mu.Unlock()
		if c.Name != "ssh" || slices.Contains(c.Args, "-O") {
			return host.Result{}, nil // ssh -O exit closing a shared connection
		}
		if dest == "relay-2" && !healthy {
			calls = append(calls, dest+" unreachable")
			return host.Result{ExitCode: 255, Output: "ssh: connect to host relay-2 port 22: No route to host\n"}, &host.ExitError{ExitCode: 255}
		}
		_, args, _ := strings.Cut(script, `exec $s "$b" `)
		calls = append(calls, dest+" "+strings.TrimSuffix(args, "'"))
		if strings.Contains(script, "fleet-probe") {
			var r status.Report
			r.Relay.Configured, r.Relay.Nickname, r.Relay.ORPort = true, "Fleet"+dest[len(dest)-1:], 9001
			r.Relay.Fingerprint = strings.Repeat(dest[len(dest)-1:], 40)
			r.Service.Unit, r.Service.Active, r.Listener.IPv4 = "tor@default", true, true
			r.Tor.Installed, r.Tor.Version, r.Tor.Supported = true, "0.4.9.3", true
			data, _ := json.Marshal(fleet.Probe{Version: "v3.2.0", Relays: []fleet.RelayProbe{{Report: r}}})
			return host.Result{Output: string(data) + "\n"}, nil
		}
		return host.Result{Output: "Tor restarted.\n"}, nil
	}
	return &calls
}

// fakeOnionoo serves Tor Metrics details for every fingerprint asked for.
func fakeOnionoo(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var relays []string
		for _, fp := range strings.Split(r.URL.Query().Get("lookup"), ",") {
			if r.URL.Path == "/details" {
				relays = append(relays, `{"fingerprint":"`+fp+`","running":true,"flags":["Fast","Running","Valid"],"consensus_weight":10,"consensus_weight_fraction":0.0001}`)
			}
		}
		_, _ = w.Write([]byte(`{"relays":[` + strings.Join(relays, ",") + `]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("TOR_RELAY_SETUP_ONIONOO_URL", srv.URL)
}

func useCacheDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := cacheDir
	t.Cleanup(func() { cacheDir = orig })
	cacheDir = func() (string, error) { return dir, nil }
	return dir
}

func TestFleetStatus(t *testing.T) {
	clearRoot(t)
	fakeOnionoo(t)
	cache := useCacheDir(t)
	fake := fakeFleet(t)
	fleetHosts(t, fake, false)
	inv := writeInventory(t)

	code, out, errOut := runCLI(t, "fleet", "status", "--dry-run", "--inventory", inv, "--format", "prometheus")
	if code != 0 {
		t.Errorf("prometheus: exit %d, stderr %q", code, errOut)
	}
	for _, want := range []string{
		"tor_relay_fleet_relays 3\n",
		"tor_relay_fleet_relays_running 2\n",
		"tor_relay_fleet_hosts_unreachable 1\n",
		"tor_relay_fleet_consensus_weight 20\n",
		`tor_relay_fleet_relay_service_active{host="relay-1",tor_instance="default",nickname="Fleet1",fingerprint="` + strings.Repeat("1", 40) + `",role="middle"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q:\n%s", want, out)
		}
	}

	code, out, _ = runCLI(t, "fleet", "--dry-run", "--plain", "--inventory", inv)
	if code != 1 || !strings.Contains(out, "Relays       2 of 3 running on 3 hosts, 1 unreachable") || !strings.Contains(out, "! relay-2: unreachable over ssh (ssh: connect to host relay-2 port 22: No route to host)") {
		t.Errorf("text: exit %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "fleet", "status", "--dry-run", "--json", "--inventory", inv)
	var doc struct {
		Totals struct{ Relays, Running int }
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 1 || doc.Totals.Relays != 3 || doc.Totals.Running != 2 {
		t.Errorf("json: exit %d, %v\n%s", code, err, out)
	}
	// fleet status reads the dashboard's flag cache but never writes it.
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Errorf("fleet status wrote %v", entries)
	}

	// A healthy fleet exits 0.
	fleetHosts(t, fake, true)
	if code, out, _ := runCLI(t, "fleet", "status", "--dry-run", "--inventory", inv); code != 0 {
		t.Errorf("healthy: exit %d\n%s", code, out)
	}
	// The default inventory is ./fleet.toml.
	t.Chdir(t.TempDir())
	if code, _, errOut := runCLI(t, "fleet", "status", "--dry-run"); code != 1 || !strings.Contains(errOut, "fleet.toml") {
		t.Errorf("no inventory: exit %d, %q", code, errOut)
	}
}

func TestFleetRollout(t *testing.T) {
	clearRoot(t)
	useCacheDir(t)
	fake := fakeFleet(t)
	calls := fleetHosts(t, fake, true)
	inv := writeInventory(t)

	code, _, errOut := runCLI(t, "fleet", "restart", "--inventory", inv)
	if code != 2 || !strings.Contains(errOut, "add --yes") || len(*calls) != 0 {
		t.Errorf("without --yes: exit %d, %q, calls %q", code, errOut, *calls)
	}
	code, out, errOut := runCLI(t, "fleet", "reload", "--inventory", inv, "--yes", "--only", "relay-1,relay-3")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q\n%s", code, errOut, out)
	}
	want := "root@relay-1 tor reload --yes --plain|root@relay-1 fleet-probe|relay-3 tor reload --yes --plain|relay-3 fleet-probe"
	if got := strings.Join(*calls, "|"); got != want {
		t.Errorf("calls:\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(out, "==> [2/2] reload relay-3") || !strings.Contains(out, "[relay-3] running and listening") {
		t.Errorf("output:\n%s", out)
	}

	// A dry run needs no confirmation and does not wait.
	*calls = nil
	if code, _, errOut := runCLI(t, "fleet", "update-tor", "--dry-run", "--inventory", inv, "--only", "relay-2"); code != 0 || strings.Join(*calls, "|") != "relay-2 tor update --yes --plain --dry-run" {
		t.Errorf("dry run: exit %d, %q, calls %q", code, errOut, *calls)
	}

	// A terminal is asked first.
	orig := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = orig })
	stdinIsTerminal = func(io.Reader) bool { return true }
	*calls = nil
	var stdout, stderr strings.Builder
	code = run([]string{"fleet", "restart", "--inventory", inv}, strings.NewReader("n\n"), &stdout, &stderr)
	if code != 130 || len(*calls) != 0 || !strings.Contains(stdout.String(), "  3. Fleet3 (relay-3)") {
		t.Errorf("declined: exit %d, calls %q\n%s", code, *calls, stdout.String())
	}
}

func TestFleetDashboardWiring(t *testing.T) {
	clearRoot(t)
	cache := useCacheDir(t)
	fake := fakeFleet(t)
	calls := fleetHosts(t, fake, true)
	inv := writeInventory(t)
	origUI, origInteractive := runFleetUI, isInteractive
	t.Cleanup(func() { runFleetUI, isInteractive = origUI, origInteractive })
	isInteractive = func() bool { return true }
	var got tui.FleetOptions
	runFleetUI = func(opt tui.FleetOptions) error {
		got = opt
		return nil
	}
	if code, _, errOut := runCLI(t, "fleet", "--inventory", inv); code != 0 {
		t.Fatalf("exit %d, %q", code, errOut)
	}
	if len(got.Inventory.Entries) != 3 || got.Probe == nil || got.Rollout == nil || got.Cache == nil || !strings.HasPrefix(got.CachePath, filepath.Join(cache, "tor-relay-setup", "fleet-")) {
		t.Fatalf("options = %+v", got)
	}
	if hp := got.Probe(context.Background(), "relay-2"); hp.State != fleet.HostOK {
		t.Errorf("probe = %+v", hp)
	}
	var lines []string
	err := got.Rollout(context.Background(), "restart", got.Inventory.Entries[:1], func(s string) { lines = append(lines, s) })
	if err != nil || !strings.Contains(strings.Join(lines, "\n"), "[root@relay-1] running and listening") {
		t.Errorf("rollout: %v\n%s", err, strings.Join(lines, "\n"))
	}
	if !strings.Contains(strings.Join(*calls, "|"), "root@relay-1 tor restart --yes --plain") {
		t.Errorf("calls %q", *calls)
	}
	// --format asks for plain output even on a terminal.
	fakeOnionoo(t)
	got = tui.FleetOptions{}
	if code, out, _ := runCLI(t, "fleet", "--dry-run", "--inventory", inv, "--format", "json"); code != 0 || got.Probe != nil || !strings.Contains(out, `"totals"`) {
		t.Errorf("--format on a terminal: exit %d\n%s", code, out)
	}
}

func TestTorCommand(t *testing.T) {
	newHost := func() *host.Fake {
		f := host.NewFake()
		f.Paths["tor"] = true
		return f
	}
	var out strings.Builder
	f := newHost()
	if err := torCmd(f, "restart", torOptions{Yes: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if !f.Ran("systemctl restart tor@default") || !strings.Contains(out.String(), "Tor restarted.") {
		t.Errorf("commands %q\n%s", f.CommandLines(), out.String())
	}
	f = newHost()
	if err := torCmd(f, "reload", torOptions{Out: &out}); err == nil || !strings.Contains(err.Error(), "tor reload needs --yes") || len(f.Commands) != 0 {
		t.Errorf("no terminal, no --yes: %v", err)
	}
	if err := torCmd(f, "update", torOptions{Terminal: true, In: strings.NewReader("n\n"), Out: &out}); !errors.Is(err, tui.ErrAborted) || len(f.Commands) != 0 {
		t.Errorf("declined: %v", err)
	}
	out.Reset()
	if err := torCmd(f, "reload", torOptions{Terminal: true, In: strings.NewReader("y\n"), Out: &out}); err != nil || !f.Ran("systemctl reload tor@default") {
		t.Errorf("confirmed: %v %q", err, f.CommandLines())
	}
	if !strings.Contains(out.String(), "Reload tor@default (re-read torrc)? [y/N] ") {
		t.Errorf("question: %q", out.String())
	}
}

func TestTorCommandDryRun(t *testing.T) {
	stubPath(t)
	t.Setenv("TOR_RELAY_SETUP_ROOT", fixtureRoot(t, strings.Replace(fixtureTorrc, "FAMILY", famA, 1)))
	code, out, errOut := runCLI(t, "tor", "reload", "--dry-run")
	if code != 0 || !strings.Contains(out, "would run: systemctl reload tor@default") || !strings.Contains(out, "Tor re-read its configuration.") {
		t.Errorf("exit %d, stderr %q\n%s", code, errOut, out)
	}
	if os.Geteuid() != 0 {
		clearRoot(t)
		if code, _, errOut := runCLI(t, "tor", "restart", "--yes"); code != 1 || !strings.Contains(errOut, "must run as root") {
			t.Errorf("non-root: exit %d, %q", code, errOut)
		}
	}
}

func TestLineWriter(t *testing.T) {
	var got []string
	w := &lineWriter{out: func(s string) { got = append(got, s) }}
	_, _ = io.WriteString(w, "one\ntw")
	_, _ = io.WriteString(w, "o\n\nthree")
	w.Flush()
	if strings.Join(got, "|") != "one|two|three" {
		t.Errorf("lines = %q", got)
	}
}
