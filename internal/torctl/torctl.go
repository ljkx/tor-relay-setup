// Package torctl holds the Tor service operations shared by the console
// and the non-interactive `tor-relay-setup tor restart|reload|update`
// command (which `fleet restart|reload|update-tor` runs on every host):
// restart and verify, verified reload, and a Tor package upgrade.
package torctl

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/apt"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/service"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

// Ops runs the operations on one tor instance.
type Ops struct {
	Host     host.Host
	Instance relay.Instance // the default instance when zero
	// ActiveTimeout bounds the wait for the unit after a restart; 15s when
	// zero. Poll is the interval between checks, 500ms when zero.
	ActiveTimeout time.Duration
	Poll          time.Duration
}

func (o Ops) tor() service.Tor {
	return service.Tor{Host: o.Host, Unit: o.Instance.OrDefault().Unit}
}

// Restart restarts tor, waits until the unit is active again and reports
// family-key warnings tor logged since. It returns a one-line summary.
func (o Ops) Restart(ctx context.Context, out func(string), progress func(float64, string)) (string, error) {
	tor := o.tor()
	since := time.Now()
	progress(10, "restarting")
	if err := tor.Restart(ctx); err != nil {
		return "", err
	}
	if o.Host.DryRun() {
		return "Dry run: Tor was not restarted.", nil
	}
	progress(50, "waiting for the service")
	timeout, poll := o.ActiveTimeout, o.Poll
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for !tor.Active(ctx) {
		if time.Now().After(deadline) {
			return "", errors.New(tor.Unit + " did not come back; check the log")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(poll):
		}
	}
	if w, _ := tor.FamilyWarnings(ctx, since); len(w) > 0 {
		for _, line := range w {
			out(line)
		}
	}
	return "Tor restarted. Reachability is re-tested in the background; refresh the console in a minute.", nil
}

// Reload verifies torrc with tor and asks tor to re-read it.
func (o Ops) Reload(ctx context.Context, out func(string), progress func(float64, string)) (string, error) {
	progress(20, "tor --verify-config")
	inst := o.Instance.OrDefault()
	if err := relay.VerifyInstance(ctx, o.Host, inst, inst.TorrcPath); err != nil && !errors.Is(err, relay.ErrTorMissing) {
		return "", fmt.Errorf("torrc is invalid, not reloading: %w", err)
	}
	progress(60, "reloading")
	if err := o.tor().Reload(ctx); err != nil {
		return "", err
	}
	return "Tor re-read its configuration.", nil
}

// Update refreshes apt and upgrades tor from deb.torproject.org; apt's
// package scripts restart the service.
func (o Ops) Update(ctx context.Context, out func(string), progress func(float64, string)) (string, error) {
	h := o.Host
	c := apt.Client{Host: h}
	if err := c.Update(ctx, func(p apt.Progress) { progress(p.Percent*0.3, p.Detail) }, out); err != nil {
		return "", err
	}
	policy, err := c.Policy(ctx, "tor")
	if err != nil {
		return "", err
	}
	if !h.DryRun() && !torproject.CandidateFromTorProject(policy) {
		return "", errors.New("the tor candidate does not come from deb.torproject.org; use Reconfigure to repair the repository")
	}
	if err := c.Install(ctx, []string{"tor", "deb.torproject.org-keyring"}, func(p apt.Progress) {
		progress(30+p.Percent*0.7, p.Detail)
	}, out); err != nil {
		return "", err
	}
	res, err := h.Run(ctx, host.Command{Name: "tor", Args: []string{"--version"}})
	if err != nil {
		return "Updated.", nil
	}
	v, _ := torproject.ParseTorVersion(res.Output)
	return "tor " + v + " is installed.", nil
}
