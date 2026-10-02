package plan

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// The optional tuning step (system.tuning) for relays above ~100 Mbit/s. It
// only applies what Tor's own documentation asks busy relays for, and only
// ever widens the running kernel's limits:
//
//   - net.ipv4.ip_local_port_range 15000 64000: Tor's overload guide answers
//     "TCP port exhaustion" with exactly this range
//     (https://support.torproject.org/relay-operators/relay-bridge-overloaded/).
//   - net.netfilter.nf_conntrack_max 262144, only when nf_conntrack is loaded
//     (UFW and stateful nftables load it): a full table silently drops new
//     relay connections. 262144 is the kernel's own default on 64-bit hosts
//     with more than 4 GiB RAM; entries cost memory only while in use.
//   - LimitNOFILE 65536 for the tor unit, only when the installed unit allows
//     fewer: Tor's doc/TUNING asks Linux relays to raise the open-file limit,
//     and Debian's tor@default.service and tor@.service already set 65536,
//     so on current packages nothing is written.
//
// Nothing that weakens security (syncookies, rp_filter, ...) is touched.
const (
	// TuningSysctlPath is the sysctl drop-in the tuning step writes.
	TuningSysctlPath = "/etc/sysctl.d/60-tor-relay.conf"
	// TuningUdevRule re-applies net.netfilter settings when nf_conntrack
	// loads after boot-time sysctl (the systemd sysctl.d(5) pattern).
	TuningUdevRule = "/etc/udev/rules.d/60-tor-relay-conntrack.rules"

	portRangeProc    = "/proc/sys/net/ipv4/ip_local_port_range"
	conntrackMaxProc = "/proc/sys/net/netfilter/nf_conntrack_max"

	tunedPortLow   = 15000
	tunedPortHigh  = 64000
	tunedConntrack = 262144
	tunedNoFile    = 65536

	noFileDropIn = "60-tor-relay-setup.conf"
)

// unitDirs are searched in systemd's order for the tor unit file.
var unitDirs = []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

// Tuning holds the values the tuning step writes.
type Tuning struct {
	PortLow, PortHigh int
	Conntrack         int // 0 leaves nf_conntrack_max alone
}

// TuningFor computes the sysctl values for this host: the recommended
// values widened by whatever the kernel (or a previous run) already uses,
// so a re-run writes the same file and nothing is ever lowered.
func TuningFor(h host.Host) Tuning {
	t := Tuning{PortLow: tunedPortLow, PortHigh: tunedPortHigh}
	if data, err := h.ReadFile(portRangeProc); err == nil {
		if f := strings.Fields(string(data)); len(f) == 2 {
			lo, err1 := strconv.Atoi(f[0])
			hi, err2 := strconv.Atoi(f[1])
			if err1 == nil && err2 == nil && lo > 0 && hi > lo {
				t.PortLow, t.PortHigh = min(lo, tunedPortLow), max(hi, tunedPortHigh)
			}
		}
	}
	if data, err := h.ReadFile(conntrackMaxProc); err == nil {
		cur, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		t.Conntrack = max(cur, tunedConntrack)
	} else if old, err := h.ReadFile(TuningSysctlPath); err == nil {
		// nf_conntrack is not loaded right now; keep what an earlier run
		// wrote so the setting still applies when the firewall loads it.
		t.Conntrack = sysctlValue(old, "net.netfilter.nf_conntrack_max")
	}
	return t
}

// sysctlValue returns an integer setting from a sysctl.d file, or 0.
func sysctlValue(data []byte, key string) int {
	for line := range strings.Lines(string(data)) {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimPrefix(strings.TrimSpace(k), "-") == key {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// Render returns the sysctl.d file, each value with its reason.
func (t Tuning) Render() []byte {
	var b strings.Builder
	b.WriteString("# Managed by tor-relay-setup (system.tuning): kernel settings for a busy Tor relay.\n")
	b.WriteString("# Values only ever widen the kernel's own settings. To undo, delete this file\n")
	b.WriteString("# and reboot.\n\n")
	b.WriteString("# Busy relays open many outbound connections and can run out of ephemeral\n")
	b.WriteString("# ports (Tor reports \"TCP port exhaustion\"). Tor's overload guide suggests\n")
	b.WriteString("# 15000-64000: https://support.torproject.org/relay-operators/relay-bridge-overloaded/\n")
	fmt.Fprintf(&b, "net.ipv4.ip_local_port_range = %d %d\n", t.PortLow, t.PortHigh)
	if t.Conntrack > 0 {
		b.WriteString("\n# The firewall tracks every relay connection, and a full conntrack table\n")
		b.WriteString("# silently drops new ones. 262144 is the kernel's default on 64-bit hosts with\n")
		b.WriteString("# more than 4 GiB RAM; entries use memory only while connections exist. The\n")
		b.WriteString("# leading \"-\" tolerates nf_conntrack loading after boot-time sysctl;\n")
		b.WriteString("# " + TuningUdevRule + " applies it when the module loads.\n")
		fmt.Fprintf(&b, "-net.netfilter.nf_conntrack_max = %d\n", t.Conntrack)
	}
	return []byte(b.String())
}

// conntrackRule is the udev rule from systemd's sysctl.d(5) example for
// settings of modules that load after systemd-sysctl.service.
const conntrackRule = `# Managed by tor-relay-setup (system.tuning): apply net.netfilter sysctl
# settings once nf_conntrack loads, which is usually after boot-time sysctl.
ACTION=="add", SUBSYSTEM=="module", KERNEL=="nf_conntrack", RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/netfilter"
`

// noFileUnit is the unit file whose LimitNOFILE applies to inst, and the
// drop-in directory the tuning step would use.
func noFileUnit(inst relay.Instance) (unitFile, dropInDir string) {
	unit := "tor@default.service"
	if !inst.IsDefault() {
		unit = "tor@.service" // the template every named instance runs from
	}
	return unit, "/etc/systemd/system/" + unit + ".d"
}

// unitNoFile returns the soft LimitNOFILE the unit file sets (math.MaxInt
// for infinity, 0 when it sets none) and whether the unit file was found.
func unitNoFile(h host.Host, unit string) (int, bool) {
	for _, dir := range unitDirs {
		data, err := h.ReadFile(dir + "/" + unit)
		if err != nil {
			continue
		}
		limit := 0
		for line := range strings.Lines(string(data)) {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok || strings.TrimSpace(k) != "LimitNOFILE" {
				continue
			}
			soft, _, _ := strings.Cut(strings.TrimSpace(v), ":")
			if soft == "infinity" {
				limit = math.MaxInt
			} else {
				limit, _ = strconv.Atoi(soft)
			}
		}
		return limit, true
	}
	return 0, false
}

func tuningStep(s config.Setup) Step {
	inst := s.Instance()
	unit, dropInDir := noFileUnit(inst)
	return Step{
		ID:    "tuning",
		Title: "Tune the kernel for a busy relay",
		Changes: []string{
			fmt.Sprintf("Write %s (ephemeral ports %d-%d; nf_conntrack_max %d if conntrack is loaded) and apply it with sysctl",
				TuningSysctlPath, tunedPortLow, tunedPortHigh, tunedConntrack),
			fmt.Sprintf("Raise LimitNOFILE to %d with %s/%s, only if %s allows fewer open files", tunedNoFile, dropInDir, noFileDropIn, unit),
		},
		Weight: 1,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			h := e.Host
			t := TuningFor(h)
			ch, err := h.WriteFile(TuningSysctlPath, t.Render(), host.FileOptions{Mode: 0o644, Backup: true})
			if err != nil {
				return err
			}
			if ch.BackupOf != "" {
				r.Note(Info, "Previous "+TuningSysctlPath+" saved as "+ch.BackupOf)
			}
			if t.Conntrack > 0 {
				if _, err := h.WriteFile(TuningUdevRule, []byte(conntrackRule), host.FileOptions{Mode: 0o644, Backup: true}); err != nil {
					return err
				}
			}
			// -e skips nf_conntrack_max while the module is not loaded.
			if _, err := h.Run(ctx, host.Command{Name: "sysctl", Args: []string{"-e", "-p", TuningSysctlPath}, Mutates: true}); err != nil {
				return err
			}
			r.Note(Success, fmt.Sprintf("Ephemeral ports %d-%d", t.PortLow, t.PortHigh))
			if t.Conntrack > 0 {
				r.Note(Success, fmt.Sprintf("nf_conntrack_max %d", t.Conntrack))
			}
			if p := e.Setup.Relay.ORPort; p >= t.PortLow && p <= t.PortHigh {
				r.Note(Warn, fmt.Sprintf("ORPort %d lies in the ephemeral port range; reserve it with net.ipv4.ip_local_reserved_ports so outgoing connections never take it", p))
			}
			return tuneNoFile(ctx, e, r, unit, dropInDir)
		},
	}
}

// tuneNoFile adds a LimitNOFILE drop-in when the tor unit allows fewer than
// tunedNoFile open files, and keeps an earlier drop-in up to date.
func tuneNoFile(ctx context.Context, e *Env, r Reporter, unit, dropInDir string) error {
	h := e.Host
	dropIn := dropInDir + "/" + noFileDropIn
	_, statErr := h.Stat(dropIn)
	haveDropIn := statErr == nil
	limit, found := unitNoFile(h, unit)
	switch {
	case !haveDropIn && !found:
		r.Note(Info, "LimitNOFILE is checked once tor's "+unit+" is installed")
		return nil
	case !haveDropIn && limit >= tunedNoFile:
		r.Note(Success, fmt.Sprintf("%s already allows %d open files", unit, limit))
		return nil
	}
	data := fmt.Sprintf("# Managed by tor-relay-setup (system.tuning). Tor's doc/TUNING asks busy Linux\n# relays to raise the open-file limit; Debian's tor units use %d.\n[Service]\nLimitNOFILE=%d\n", tunedNoFile, tunedNoFile)
	if err := h.MkdirAll(dropInDir, 0o755, ""); err != nil {
		return err
	}
	ch, err := h.WriteFile(dropIn, []byte(data), host.FileOptions{Mode: 0o644, Backup: true})
	if err != nil || ch.Unchanged {
		return err
	}
	if _, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"daemon-reload"}, Mutates: true}); err != nil {
		return err
	}
	r.Note(Success, fmt.Sprintf("LimitNOFILE %d for %s (applies at the next restart)", tunedNoFile, unit))
	return nil
}

// ExpectedMbit estimates the relay's sustained rate from its bandwidth
// plan; ok is false when nothing limits it (the server's link decides).
func ExpectedMbit(s config.Setup) (mbit float64, ok bool) {
	bw, err := s.Bandwidth.Resolve()
	if err != nil {
		return 0, false
	}
	switch {
	case bw.RateKBytes > 0:
		return relay.MbitFromKBytes(bw.RateKBytes), true
	case bw.RateMbit > 0:
		return float64(bw.RateMbit), true
	}
	return 0, false
}

// TuningThresholdMbit is the expected rate from which the wizard offers
// tuning; slower relays do not reach the limits it raises.
const TuningThresholdMbit = 100

// SuggestTuning reports whether the wizard should offer the tuning step.
func SuggestTuning(s config.Setup) bool {
	mbit, ok := ExpectedMbit(s)
	return !ok || mbit >= TuningThresholdMbit
}
