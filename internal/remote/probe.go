package remote

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
)

// probeTimeout bounds one fleet-probe call, connection included.
const probeTimeout = 20 * time.Second

// installedScript runs the installed tor-relay-setup with the given
// arguments: through passwordless sudo when the user is not root and sudo
// allows it, unprivileged otherwise (reads that need root then come back
// empty). It prints TRS-NOBINARY and exits 127 when the tool is missing.
func installedScript(args string, needRoot bool) string {
	s := `b=$(command -v tor-relay-setup 2>/dev/null) || b=/usr/local/bin/tor-relay-setup
if [ ! -x "$b" ]; then echo TRS-NOBINARY; exit 127; fi
s=
if [ "$(id -u)" != 0 ]; then
  if sudo -n true >/dev/null 2>&1; then s='sudo -n'; `
	if needRoot {
		s += `else echo TRS-NOSUDO; exit 126; `
	}
	return s + `fi
fi
exec $s "$b" ` + args
}

// Probe runs `tor-relay-setup fleet-probe` on dest over ssh and classifies
// the outcome: unreachable, tool missing or too old, or the probe document.
func (f *Fleet) Probe(ctx context.Context, dest string) fleet.HostProbe {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	hp := fleet.HostProbe{Address: dest}
	start := time.Now()
	res, err := f.Host.Run(ctx, f.ssh(dest, installedScript("fleet-probe", false), false))
	hp.At = time.Now()
	hp.Duration = hp.At.Sub(start)
	if err != nil {
		hp.State, hp.Detail = classify(res.Output, err)
		return hp
	}
	p, perr := fleet.ParseProbe(res.Output)
	if perr != nil {
		hp.State, hp.Detail = fleet.HostFailed, perr.Error()
		return hp
	}
	hp.State, hp.Probe = fleet.HostOK, p
	return hp
}

// classify turns a failed remote call into a host state and a short reason.
func classify(output string, err error) (fleet.HostState, string) {
	var exit *host.ExitError
	if !errors.As(err, &exit) {
		if errors.Is(err, context.DeadlineExceeded) {
			return fleet.HostUnreachable, "timed out"
		}
		return fleet.HostFailed, err.Error()
	}
	switch {
	case exit.ExitCode == 255:
		return fleet.HostUnreachable, lastLine(output)
	case strings.Contains(output, "TRS-NOBINARY"):
		return fleet.HostMissing, "tor-relay-setup is not installed"
	case strings.Contains(output, "TRS-NOSUDO"):
		return fleet.HostFailed, "the remote user is not root and sudo asks for a password"
	case exit.ExitCode == 2 && strings.Contains(output, "unknown command"):
		return fleet.HostTooOld, "tor-relay-setup too old on this host — run self-update"
	}
	if l := lastLine(output); l != "" {
		return fleet.HostFailed, l
	}
	return fleet.HostFailed, commandError("fleet-probe", err).Error()
}

// lastLine is the last non-empty output line, for short error details.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// ProbeAll probes every address, at most n at once, and returns the probes
// in address order.
func (f *Fleet) ProbeAll(ctx context.Context, addresses []string, n int) []fleet.HostProbe {
	out := make([]fleet.HostProbe, len(addresses))
	idx := make([]int, len(addresses))
	for i := range idx {
		idx[i] = i
	}
	var mu sync.Mutex
	runServers(idx, n, func(i int) {
		hp := f.Probe(ctx, addresses[i])
		mu.Lock()
		out[i] = hp
		mu.Unlock()
	})
	return out
}
