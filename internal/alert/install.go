package alert

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// systemd unit names and paths written by Install.
const (
	UnitName    = "tor-relay-setup-alert"
	ServicePath = "/etc/systemd/system/" + UnitName + ".service"
	TimerPath   = "/etc/systemd/system/" + UnitName + ".timer"
)

// Interval bounds for --every.
const (
	DefaultEvery = 5 * time.Minute
	minEvery     = time.Minute
	maxEvery     = 24 * time.Hour
)

// InstallOptions configures the systemd units.
type InstallOptions struct {
	Executable string        // absolute path of tor-relay-setup
	ConfigPath string        // default DefaultConfigPath
	Every      time.Duration // default DefaultEvery
}

// Units renders the service and timer.
//
// The service is a root oneshot: it reads torrc, tor's state file and the
// family key directory (owned by debian-tor, mode 0700), asks systemd and
// the journal about tor, runs tor --version, apt-cache and the configured
// notifiers (sendmail, a command), and talks to Tor Metrics and the
// notification services. The hardening below keeps all of that working:
// it removes what the job never needs (write access to /usr, /boot and
// /etc, devices, kernel and cgroup tunables, new namespaces, exotic
// sockets) without restricting capabilities, because the root user needs
// CAP_DAC_READ_SEARCH for debian-tor's files and an MTA's sendmail may
// need to change user.
func Units(opt InstallOptions) (service, timer []byte, err error) {
	if opt.ConfigPath == "" {
		opt.ConfigPath = DefaultConfigPath
	}
	if opt.Every == 0 {
		opt.Every = DefaultEvery
	}
	if opt.Every < minEvery || opt.Every > maxEvery {
		return nil, nil, fmt.Errorf("--every must be between %s and %s", minEvery, maxEvery)
	}
	for _, p := range []string{opt.Executable, opt.ConfigPath} {
		if !filepath.IsAbs(p) || !unitSafe(p) {
			return nil, nil, fmt.Errorf("%q must be an absolute path of letters, digits and ._+-/ only, to be used in a systemd unit", p)
		}
	}
	secs := strconv.Itoa(int(opt.Every.Seconds()))
	service = []byte(`# Written by tor-relay-setup alert install; remove with: tor-relay-setup alert uninstall
[Unit]
Description=tor-relay-setup relay alerts
Documentation=https://github.com/ljkx/tor-relay-setup/blob/main/docs/monitoring/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=` + opt.Executable + ` alert run --config ` + opt.ConfigPath + `
# A hung notifier or lookup must not block the next run.
TimeoutStartSec=3min
# Monitoring yields to the relay.
Nice=10
# /usr, /boot and /etc are read-only; /var stays writable for the alert
# state (/var/lib/tor-relay-setup) and an MTA's mail spool (sendmail).
ProtectSystem=full
# Home directories are visible but read-only (a command notifier may live there).
ProtectHome=read-only
# Private /tmp and /var/tmp.
PrivateTmp=yes
# No physical devices; tor --version, journalctl and HTTP need none.
PrivateDevices=yes
# The job never changes kernel settings, modules, logs, cgroups, the clock or the host name.
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
# systemctl and journalctl use unix sockets; notifications and Tor Metrics use IP.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
# Not set: MemoryDenyWriteExecute (breaks JIT runtimes a command notifier may
# use), CapabilityBoundingSet and NoNewPrivileges (reading debian-tor's files
# needs root's capabilities; sendmail may switch to the MTA user).
`)
	timer = []byte(`# Written by tor-relay-setup alert install; remove with: tor-relay-setup alert uninstall
[Unit]
Description=Run tor-relay-setup relay alerts every ` + opt.Every.String() + `

[Timer]
OnBootSec=2min
OnUnitActiveSec=` + secs + `s
# Spread runs a little so a fleet does not query Tor Metrics in lockstep.
RandomizedDelaySec=30s
AccuracySec=30s

[Install]
WantedBy=timers.target
`)
	return service, timer, nil
}

// unitSafe accepts paths that need no quoting in ExecStart.
func unitSafe(p string) bool {
	for _, r := range p {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '/' && r != '.' && r != '_' && r != '-' && r != '+' {
			return false
		}
	}
	return true
}

// Install writes the units, reloads systemd and enables the timer, all
// through h, so a dry-run host only reports the changes. Progress, and in
// a dry run the full unit files, go to out.
func Install(ctx context.Context, h host.Host, opt InstallOptions, out io.Writer) error {
	service, timer, err := Units(opt)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		data []byte
	}{{ServicePath, service}, {TimerPath, timer}} {
		ch, err := h.WriteFile(f.path, f.data, host.FileOptions{Mode: 0o644})
		if err != nil {
			return err
		}
		switch {
		case h.DryRun():
			fmt.Fprintf(out, "would write %s:\n%s\n", f.path, f.data)
		case ch.Unchanged:
			fmt.Fprintln(out, "unchanged", f.path)
		default:
			fmt.Fprintln(out, "wrote", f.path)
		}
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", UnitName + ".timer"}} {
		if err := systemctl(ctx, h, out, args...); err != nil {
			return err
		}
	}
	if !h.DryRun() {
		fmt.Fprintf(out, "Alerts run every %s. Check with: systemctl list-timers %s.timer; journalctl -u %s\n", everyOr(opt.Every), UnitName, UnitName)
	}
	return nil
}

// Uninstall disables the timer and removes both units. Missing units are
// not an error.
func Uninstall(ctx context.Context, h host.Host, out io.Writer) error {
	present := false
	for _, p := range []string{TimerPath, ServicePath} {
		if _, err := h.Stat(p); err == nil {
			present = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if !present {
		fmt.Fprintln(out, "The alert timer is not installed.")
		return nil
	}
	// The timer may already be stopped or unknown to systemd; removal goes on.
	_ = systemctl(ctx, h, out, "disable", "--now", UnitName+".timer")
	for _, p := range []string{TimerPath, ServicePath} {
		if _, err := h.Stat(p); err != nil {
			continue
		}
		if err := h.Remove(p); err != nil {
			return err
		}
		if h.DryRun() {
			fmt.Fprintln(out, "would remove", p)
		} else {
			fmt.Fprintln(out, "removed", p)
		}
	}
	return systemctl(ctx, h, out, "daemon-reload")
}

func systemctl(ctx context.Context, h host.Host, out io.Writer, args ...string) error {
	c := host.Command{Name: "systemctl", Args: args, Mutates: true}
	if h.DryRun() {
		fmt.Fprintln(out, "would run", c.String())
	}
	_, err := h.Run(ctx, c)
	return err
}

func everyOr(d time.Duration) time.Duration {
	if d == 0 {
		return DefaultEvery
	}
	return d
}
