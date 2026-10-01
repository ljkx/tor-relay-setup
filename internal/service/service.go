// Package service controls the tor systemd unit and reads its journal:
// start/stop/restart, the ORPort reachability self-test and family-key
// warnings Tor logs after a restart.
package service

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// DefaultUnit is the Debian tor instance unit.
const DefaultUnit = "tor@default"

// defaultPoll is WaitReachable's poll interval when none is given.
const defaultPoll = 5 * time.Second

// journalTime is the --since format journalctl accepts (local time).
const journalTime = "2006-01-02 15:04:05"

// Tor manages one tor systemd unit through a host.
type Tor struct {
	Host host.Host
	Unit string // DefaultUnit when empty
}

func (t Tor) unit() string {
	if t.Unit == "" {
		return DefaultUnit
	}
	return t.Unit
}

func (t Tor) systemctl(ctx context.Context, verb string) error {
	_, err := t.Host.Run(ctx, host.Command{Name: "systemctl", Args: []string{verb, t.unit()}, Mutates: true})
	return err
}

// Active reports whether the unit is active (read-only).
func (t Tor) Active(ctx context.Context) bool {
	_, err := t.Host.Run(ctx, host.Command{Name: "systemctl", Args: []string{"is-active", "--quiet", t.unit()}})
	return err == nil
}

// Enable enables the unit at boot.
func (t Tor) Enable(ctx context.Context) error { return t.systemctl(ctx, "enable") }

// Disable disables the unit at boot.
func (t Tor) Disable(ctx context.Context) error { return t.systemctl(ctx, "disable") }

// Start starts the unit.
func (t Tor) Start(ctx context.Context) error { return t.systemctl(ctx, "start") }

// Stop stops the unit.
func (t Tor) Stop(ctx context.Context) error { return t.systemctl(ctx, "stop") }

// Restart restarts the unit.
func (t Tor) Restart(ctx context.Context) error { return t.systemctl(ctx, "restart") }

// Reload asks tor to re-read its configuration (SIGHUP via systemd).
func (t Tor) Reload(ctx context.Context) error { return t.systemctl(ctx, "reload") }

// Journal returns the unit's journal in short-iso format. since (any
// journalctl --since value), lines (-n) and priority (-p) are omitted when
// empty or non-positive.
func (t Tor) Journal(ctx context.Context, since string, lines int, priority string) (string, error) {
	args := []string{"-u", t.unit(), "--no-pager", "-o", "short-iso"}
	if since != "" {
		args = append(args, "--since", since)
	}
	if lines > 0 {
		args = append(args, "-n", strconv.Itoa(lines))
	}
	if priority != "" {
		args = append(args, "-p", priority)
	}
	res, err := t.Host.Run(ctx, host.Command{Name: "journalctl", Args: args})
	return res.Output, err
}

// Follow streams new journal lines (after the last 50) to onLine until ctx
// is cancelled; cancellation is not an error.
func (t Tor) Follow(ctx context.Context, onLine func(string)) error {
	c := host.Command{Name: "journalctl", Args: []string{"-u", t.unit(), "-f", "-n", "50", "-o", "short-iso"}}
	_, err := t.Host.Stream(ctx, c, onLine)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// SelfTest is the ORPort reachability verdict found in Tor's log.
type SelfTest struct {
	IPv4   bool // an IPv4 (or legacy address-less) success notice was seen
	IPv6   bool // an IPv6 ([addr]:port) success notice was seen
	Failed bool // Tor reported it could not confirm reachability
}

var (
	// Tor 0.4.5+ names the address; older releases do not.
	selfTestOK = regexp.MustCompile(`Self-testing indicates your ORPort (\S+ )?is reachable from the outside\. Excellent\.`)
	// Current wording lives in src/feature/relay/relay_periodic.c; the older
	// "(addr:port) has not managed to confirm that its ORPort is reachable"
	// wording is kept for old relays.
	selfTestFailed = regexp.MustCompile(`Your server (\([^)]*\) )?has not managed to confirm (reachability for its ORPort|that its ORPort is reachable)`)
)

// ParseSelfTest scans Tor log text for ORPort self-test results.
func ParseSelfTest(log string) SelfTest {
	var st SelfTest
	for _, m := range selfTestOK.FindAllStringSubmatch(log, -1) {
		if strings.HasPrefix(m[1], "[") {
			st.IPv6 = true
		} else {
			st.IPv4 = true
		}
	}
	st.Failed = selfTestFailed.MatchString(log)
	return st
}

// done reports whether st settles WaitReachable: IPv4 success (plus IPv6
// when wanted), or a failure notice.
func (st SelfTest) done(wantIPv6 bool) bool {
	return (st.IPv4 && (st.IPv6 || !wantIPv6)) || st.Failed
}

// WaitReachable polls the journal since the given time until Tor reports
// ORPort reachability over IPv4 (and IPv6 when wantIPv6), or a failure
// notice appears; both return a nil error and the caller inspects the
// SelfTest. When ctx ends first it returns the last SelfTest and ctx.Err().
// A journalctl error is returned immediately. poll defaults to 5s.
func (t Tor) WaitReachable(ctx context.Context, since time.Time, poll time.Duration, wantIPv6 bool) (SelfTest, error) {
	if poll <= 0 {
		poll = defaultPoll
	}
	sinceArg := since.Local().Format(journalTime)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	var st SelfTest
	for {
		log, err := t.Journal(ctx, sinceArg, 0, "")
		if err != nil {
			if ctx.Err() != nil {
				return st, ctx.Err()
			}
			return st, err
		}
		st = ParseSelfTest(log)
		if st.done(wantIPv6) {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-ticker.C:
		}
	}
}

// maxFamilyWarnings caps FamilyWarnings, like the installer's `head -n 5`.
const maxFamilyWarnings = 5

// FamilyWarnings returns up to five warning-or-worse journal lines since
// the given time that mention "family" (case-insensitive), e.g. a missing or
// unreadable family key after a restart.
func (t Tor) FamilyWarnings(ctx context.Context, since time.Time) ([]string, error) {
	log, err := t.Journal(ctx, since.Local().Format(journalTime), 0, "warning")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(strings.ToLower(line), "family") {
			out = append(out, strings.TrimSpace(line))
			if len(out) == maxFamilyWarnings {
				break
			}
		}
	}
	return out, nil
}
