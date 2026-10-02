package remote

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
)

// Action is a rolling fleet operation.
type Action string

// Rolling actions.
const (
	Restart   Action = "restart"
	Reload    Action = "reload"
	UpdateTor Action = "update-tor"
)

// ParseAction accepts the `fleet` subcommand names of rolling actions.
func ParseAction(s string) (Action, bool) {
	switch a := Action(s); a {
	case Restart, Reload, UpdateTor:
		return a, true
	}
	return "", false
}

// verb is the `tor-relay-setup tor VERB` that performs the action on a host.
func (a Action) verb() string {
	if a == UpdateTor {
		return "update"
	}
	return string(a)
}

// Default health wait after each relay.
const (
	defaultRolloutTimeout = 2 * time.Minute
	defaultRolloutPoll    = 5 * time.Second
)

// RolloutOptions describes a rolling restart, reload or Tor update.
type RolloutOptions struct {
	Action    Action
	Entries   []fleet.Entry
	DryRun    bool // run the command with --dry-run and do not wait
	KeepGoing bool // continue after a relay fails
	// Timeout bounds the wait for each relay to be running and listening
	// again (2 minutes when zero); Poll is the probe interval (5s).
	Timeout time.Duration
	Poll    time.Duration
}

// Rollout performs the action on one relay at a time: it runs
// `tor-relay-setup tor VERB --yes` on the host with sudo, then waits until
// fleet-probe shows that relay's service active and listening. A failure
// stops the rollout unless KeepGoing is set.
func (f *Fleet) Rollout(ctx context.Context, opt RolloutOptions) ([]HostResult, error) {
	if len(opt.Entries) == 0 {
		return nil, errors.New("no relays selected")
	}
	if opt.Timeout <= 0 {
		opt.Timeout = defaultRolloutTimeout
	}
	if opt.Poll <= 0 {
		opt.Poll = defaultRolloutPoll
	}
	perServer := map[string]int{}
	for _, e := range opt.Entries {
		perServer[strings.ToLower(e.Address)]++
	}
	results := make([]HostResult, len(opt.Entries))
	var stop error
	for i, e := range opt.Entries {
		t := target{Entry: e, pos: i, label: e.Address}
		if perServer[strings.ToLower(e.Address)] > 1 {
			t.label = e.Address + "/" + e.Nickname()
		}
		results[i] = HostResult{Host: e.Address, Relay: relayName(t), Outcome: Skipped}
		if stop == nil && ctx.Err() != nil {
			stop = ctx.Err()
		}
		if stop != nil {
			results[i].Err = stop
			continue
		}
		f.say("\n==> [%d/%d] %s %s\n", i+1, len(opt.Entries), opt.Action, t.label)
		if err := f.rolloutOne(ctx, t, opt); err != nil {
			results[i].Outcome, results[i].Err = Failed, err
			f.say("[%s] FAILED: %v\n", t.label, err)
			if !opt.KeepGoing {
				stop = errors.New("rollout stopped after an earlier failure (--keep-going continues)")
			}
			continue
		}
		results[i].Outcome = OK
	}
	f.summary(results)
	var failed, skipped int
	for _, res := range results {
		switch res.Outcome {
		case Failed:
			failed++
		case Skipped:
			skipped++
		}
	}
	if failed+skipped > 0 {
		return results, fmt.Errorf("%d of %d relays failed, %d skipped", failed, len(results), skipped)
	}
	return results, nil
}

// rolloutOne acts on one relay and waits for it.
func (f *Fleet) rolloutOne(ctx context.Context, t target, opt RolloutOptions) error {
	args := "tor " + opt.Action.verb() + " --yes --plain"
	if t.Instance != fleet.DefaultInstance {
		args += " --instance " + ShellQuote(t.Instance)
	}
	if opt.DryRun {
		args += " --dry-run"
	}
	res, err := f.Host.Stream(ctx, f.ssh(t.Address, installedScript(args, !opt.DryRun), !opt.DryRun), f.printer(t.label))
	if err != nil {
		state, detail := classify(res.Output, err)
		switch state {
		case fleet.HostUnreachable:
			return fmt.Errorf("ssh could not connect or authenticate (%s)", detail)
		case fleet.HostTooOld:
			return fmt.Errorf("tor-relay-setup too old on this host for `tor %s` — run self-update", opt.Action.verb())
		}
		return fmt.Errorf("tor %s failed: %s", opt.Action.verb(), detail)
	}
	if opt.DryRun {
		return nil
	}
	f.say("[%s] waiting until the relay is running and listening\n", t.label)
	if err := f.waitHealthy(ctx, t.Entry, opt.Timeout, opt.Poll); err != nil {
		return err
	}
	f.say("[%s] running and listening\n", t.label)
	return nil
}

// waitHealthy probes the relay's host until the relay's service is active
// and something listens on its ORPort, or the timeout passes.
func (f *Fleet) waitHealthy(parent context.Context, e fleet.Entry, timeout, poll time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var last string
	for {
		hp := f.Probe(ctx, e.Address)
		if hp.State == fleet.HostOK {
			last = "the relay is missing from the probe"
			for _, rp := range hp.Probe.Relays {
				if rp.Instance() != e.Instance {
					continue
				}
				rep := rp.Report
				switch {
				case rep.Service.Active && (rep.Listener.IPv4 || rep.Listener.IPv6):
					return nil
				case !rep.Service.Active:
					last = rep.Service.Unit + " is not active"
				default:
					last = "nothing listens on ORPort " + strconv.Itoa(rep.Relay.ORPort)
				}
			}
		} else {
			last = string(hp.State)
			if hp.Detail != "" {
				last += ": " + hp.Detail
			}
		}
		select {
		case <-ctx.Done():
			if parent.Err() != nil {
				return parent.Err()
			}
			return fmt.Errorf("not running and listening after %s (%s)", timeout, last)
		case <-time.After(poll):
		}
	}
}
