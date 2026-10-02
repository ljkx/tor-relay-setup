package plan

import (
	"context"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
)

const debianUnit = "[Service]\nExecStart=/usr/bin/tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc --RunAsDaemon 0\nLimitNOFILE=65536\n"

func runTuning(t *testing.T, f *host.Fake, s config.Setup) []string {
	t.Helper()
	env := NewEnv(f, testFacts(), s, "p")
	var rec safeRecorder
	if err := tuningStep(s).Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
		t.Fatalf("tuning step: %v", err)
	}
	return rec.notes()
}

func TestTuningSysctl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		portRange string // /proc content; "" = unreadable
		conntrack string // /proc content; "" = module not loaded
		wantRange string
		wantCT    string // "" = no conntrack line
		wantRule  bool
	}{
		{name: "kernel defaults", portRange: "32768\t60999\n", conntrack: "65536\n",
			wantRange: "net.ipv4.ip_local_port_range = 15000 64000", wantCT: "-net.netfilter.nf_conntrack_max = 262144", wantRule: true},
		{name: "no conntrack loaded", portRange: "32768\t60999\n",
			wantRange: "net.ipv4.ip_local_port_range = 15000 64000"},
		{name: "wider operator settings are kept", portRange: "1024 65000\n", conntrack: "1048576\n",
			wantRange: "net.ipv4.ip_local_port_range = 1024 65000", wantCT: "-net.netfilter.nf_conntrack_max = 1048576", wantRule: true},
		{name: "unreadable proc uses the recommendation",
			wantRange: "net.ipv4.ip_local_port_range = 15000 64000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := host.NewFake()
			if tt.portRange != "" {
				f.Files[portRangeProc] = []byte(tt.portRange)
			}
			if tt.conntrack != "" {
				f.Files[conntrackMaxProc] = []byte(tt.conntrack)
			}
			f.Files["/usr/lib/systemd/system/tor@default.service"] = []byte(debianUnit)
			s := testSetup()
			s.System.Tuning = true
			runTuning(t, f, s)

			conf := string(f.Files[TuningSysctlPath])
			if !strings.Contains(conf, tt.wantRange+"\n") {
				t.Errorf("sysctl file lacks %q:\n%s", tt.wantRange, conf)
			}
			if tt.wantCT != "" && !strings.Contains(conf, tt.wantCT+"\n") {
				t.Errorf("sysctl file lacks %q:\n%s", tt.wantCT, conf)
			}
			if tt.wantCT == "" && strings.Contains(conf, "nf_conntrack_max") {
				t.Errorf("conntrack set without the module:\n%s", conf)
			}
			if !strings.Contains(conf, "relay-bridge-overloaded") {
				t.Error("the port range has no reason comment")
			}
			_, rule := f.Files[TuningUdevRule]
			if rule != tt.wantRule {
				t.Errorf("udev rule written = %v, want %v", rule, tt.wantRule)
			}
			if f.Modes[TuningSysctlPath] != 0o644 {
				t.Errorf("mode = %v", f.Modes[TuningSysctlPath])
			}
			if !f.Ran("sysctl -e -p " + TuningSysctlPath) {
				t.Errorf("commands = %q", f.CommandLines())
			}
			// Debian's unit already allows 65536 files: no drop-in.
			if f.Ran("daemon-reload") || len(f.Dirs) != 0 {
				t.Errorf("LimitNOFILE drop-in written for a unit that needs none: %q", f.CommandLines())
			}
		})
	}
}

func TestTuningIsIdempotent(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	f.Files[portRangeProc] = []byte("32768 60999\n")
	f.Files[conntrackMaxProc] = []byte("65536\n")
	s := testSetup()
	s.System.Tuning = true
	runTuning(t, f, s)
	first := string(f.Files[TuningSysctlPath])
	// The kernel now runs the tuned values.
	f.Files[portRangeProc] = []byte("15000 64000\n")
	f.Files[conntrackMaxProc] = []byte("262144\n")
	runTuning(t, f, s)
	if got := string(f.Files[TuningSysctlPath]); got != first {
		t.Errorf("second run rewrote the file:\n%s\nwant\n%s", got, first)
	}
	if _, ok := f.Files[TuningSysctlPath+".bak.test"]; ok {
		t.Error("an unchanged file was backed up")
	}
	// nf_conntrack unloaded (e.g. firewall off at the moment): the earlier
	// value stays so it applies when the module loads again.
	delete(f.Files, conntrackMaxProc)
	runTuning(t, f, s)
	if got := string(f.Files[TuningSysctlPath]); got != first {
		t.Errorf("conntrack line lost while the module was unloaded:\n%s", got)
	}
}

func TestTuningDryRun(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	f.Dry = true
	f.Handler = func(c host.Command) (host.Result, error) {
		if c.Mutates {
			t.Errorf("mutating command ran in a dry run: %s", c)
		}
		return host.Result{}, nil
	}
	s := testSetup()
	s.System.Tuning = true
	notes := runTuning(t, f, s)
	if len(f.Files) != 0 || len(f.Dirs) != 0 {
		t.Errorf("dry run wrote %v", keys(f.Files))
	}
	if !f.Ran("sysctl -e -p") {
		t.Error("the sysctl command is not shown in the dry run")
	}
	if !containsSubstring(notes, "LimitNOFILE is checked once tor's tor@default.service is installed") {
		t.Errorf("notes = %q", notes)
	}
}

func TestTuningNoFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		instance string
		unitPath string
		unit     string
		dropIn   string // "" = none expected
		wantNote string
	}{
		{name: "Debian default", unitPath: "/usr/lib/systemd/system/tor@default.service", unit: debianUnit,
			wantNote: "tor@default.service already allows 65536 open files"},
		{name: "low limit", unitPath: "/lib/systemd/system/tor@default.service", unit: "[Service]\nLimitNOFILE=4096\n",
			dropIn: "/etc/systemd/system/tor@default.service.d/60-tor-relay-setup.conf", wantNote: "LimitNOFILE 65536 for tor@default.service"},
		{name: "no limit set", unitPath: "/usr/lib/systemd/system/tor@default.service", unit: "[Service]\n",
			dropIn: "/etc/systemd/system/tor@default.service.d/60-tor-relay-setup.conf", wantNote: "LimitNOFILE 65536"},
		{name: "soft:hard form", unitPath: "/usr/lib/systemd/system/tor@default.service", unit: "[Service]\nLimitNOFILE=1024:524288\n",
			dropIn: "/etc/systemd/system/tor@default.service.d/60-tor-relay-setup.conf", wantNote: "LimitNOFILE 65536"},
		{name: "infinity", unitPath: "/usr/lib/systemd/system/tor@default.service", unit: "[Service]\nLimitNOFILE=infinity\n",
			wantNote: "already allows"},
		{name: "named instance reads the template", instance: "relay2", unitPath: "/usr/lib/systemd/system/tor@.service", unit: "[Service]\nLimitNOFILE=8192\n",
			dropIn: "/etc/systemd/system/tor@.service.d/60-tor-relay-setup.conf", wantNote: "LimitNOFILE 65536 for tor@.service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := host.NewFake()
			f.Files[tt.unitPath] = []byte(tt.unit)
			s := testSetup()
			s.System.Tuning, s.Relay.Instance = true, tt.instance
			notes := runTuning(t, f, s)
			if !containsSubstring(notes, tt.wantNote) {
				t.Errorf("notes %q lack %q", notes, tt.wantNote)
			}
			if tt.dropIn == "" {
				if f.Ran("daemon-reload") {
					t.Error("daemon-reload without a drop-in")
				}
				return
			}
			if got := string(f.Files[tt.dropIn]); !strings.Contains(got, "[Service]\nLimitNOFILE=65536\n") {
				t.Errorf("drop-in %s = %q", tt.dropIn, got)
			}
			if !f.Ran("systemctl daemon-reload") {
				t.Errorf("commands = %q", f.CommandLines())
			}
			// Re-running keeps the drop-in and does not reload again.
			f.Commands = nil
			runTuning(t, f, s)
			if f.Ran("daemon-reload") {
				t.Error("an unchanged drop-in triggered daemon-reload")
			}
		})
	}
}

func TestTuningWarnsAboutORPortInRange(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	s := testSetup()
	s.System.Tuning, s.Relay.ORPort = true, 50000
	if notes := runTuning(t, f, s); !containsSubstring(notes, "ORPort 50000 lies in the ephemeral port range") {
		t.Errorf("notes = %q", notes)
	}
}

func TestSuggestTuning(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		bw   config.BandwidthPlan
		want bool
	}{
		{"no limit", config.BandwidthPlan{Mode: "none"}, true},
		{"accounting runs at full speed", config.BandwidthPlan{Mode: "accounting", MonthlyQuota: "10TB", Billing: "sum"}, true},
		{"manual 50", config.BandwidthPlan{Mode: "manual", RateMbit: 50}, false},
		{"manual 200", config.BandwidthPlan{Mode: "manual", RateMbit: 200}, true},
		{"steady 10TB is ~33 Mbit/s", config.BandwidthPlan{Mode: "steady", MonthlyQuota: "10TB", HeadroomPercent: 10, Billing: "sum"}, false},
		{"steady 100TB", config.BandwidthPlan{Mode: "steady", MonthlyQuota: "100TB", HeadroomPercent: 10, Billing: "out"}, true},
	}
	for _, tt := range tests {
		s := testSetup()
		s.Bandwidth = tt.bw
		if got := SuggestTuning(s); got != tt.want {
			mbit, ok := ExpectedMbit(s)
			t.Errorf("%s: SuggestTuning = %v (%.1f Mbit/s, %v), want %v", tt.name, got, mbit, ok, tt.want)
		}
	}
}
