package alert

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/apt"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

// GatherOptions configures Gather.
type GatherOptions struct {
	Instance     relay.Instance   // the tor instance; zero is the default one
	TorrcPath    string           // default: the instance's torrc
	Unit         string           // tor systemd unit; default: the instance's unit
	Onionoo      onionoo.Client   // Tor Metrics
	HTTP         *http.Client     // MetricsPort scrape; nil uses metrics' default
	CheckUpdates bool             // ask apt-cache policy about the tor package
	Now          func() time.Time // default time.Now
}

// Gather observes the relay: the status report with the Tor Metrics entry,
// a MetricsPort scrape, the accounting assessment and optionally apt's
// view of the tor package. Every probe is read-only; failures are recorded
// in the Input instead of stopping the run.
func Gather(ctx context.Context, h host.Host, opt GatherOptions) Input {
	inst := opt.Instance.OrDefault()
	if opt.TorrcPath == "" {
		opt.TorrcPath = inst.TorrcPath
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	in := Input{Report: status.Collect(ctx, h, status.Options{Instance: inst, TorrcPath: opt.TorrcPath, Unit: opt.Unit})}
	r := &in.Report
	if r.Relay.Fingerprint != "" {
		dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		d, err := status.Directory(dctx, opt.Onionoo, r.Relay.Fingerprint)
		cancel()
		r.Directory = d
		if err != nil {
			r.DirectoryError = err.Error()
		}
	}
	var doc *relay.Document
	if data, err := h.ReadFile(opt.TorrcPath); err == nil {
		doc = relay.ParseDocument(data)
	}
	if r.Relay.MetricsPort != "" {
		s, err := metrics.Scrape(ctx, opt.HTTP, r.Relay.MetricsPort)
		if err != nil {
			in.SampleErr = err.Error()
		} else {
			in.Sample = &s
		}
	}
	if doc != nil {
		in.Accounting, in.AccountingErr = AccountingFor(h, doc, now())
	}
	if opt.CheckUpdates {
		actx, cancel := context.WithTimeout(ctx, 30*time.Second)
		out, err := apt.Client{Host: h}.Policy(actx, "tor")
		cancel()
		if err != nil {
			in.UpdateErr = err.Error()
		} else {
			in.TorInstalled, in.TorCandidate = policyField(out, "Installed:"), apt.ParseCandidate(out)
		}
	}
	in.Now = now()
	return in
}

// Identify reads only the relay's nickname and fingerprint, for a test
// message that should not wait for Tor Metrics.
func Identify(h host.Host, torrcPath string) Input {
	if torrcPath == "" {
		torrcPath = "/etc/tor/torrc"
	}
	in := Input{Now: time.Now()}
	data, err := h.ReadFile(torrcPath)
	if err != nil {
		return in
	}
	doc := relay.ParseDocument(data)
	in.Report.Relay.Nickname, _ = doc.Get("Nickname")
	if fp, err := h.ReadFile(strings.TrimRight(doc.DataDirectory(), "/") + "/fingerprint"); err == nil {
		if f := strings.Fields(string(fp)); len(f) > 0 {
			in.Report.Relay.Fingerprint = strings.ToUpper(f[len(f)-1])
		}
	}
	return in
}

// AccountingFor assesses AccountingMax from torrc and tor's state file. It
// returns nil (and no error) when accounting is not configured.
func AccountingFor(h host.Host, doc *relay.Document, now time.Time) (*metrics.Accounting, string) {
	maxValue, ok := doc.Get("AccountingMax")
	if !ok {
		return nil, ""
	}
	rule, _ := doc.Get("AccountingRule")
	start, _ := doc.Get("AccountingStart")
	cfg, err := metrics.ParseAccountingConfig(maxValue, rule, start)
	if err != nil {
		return nil, err.Error()
	}
	var u metrics.AccountingUsage
	data, err := h.ReadFile(strings.TrimRight(doc.DataDirectory(), "/") + "/state")
	if err == nil {
		u, err = metrics.ParseState(data)
	}
	if err != nil {
		// A relay that never ran with accounting has no counters yet.
		if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no accounting data") {
			return nil, err.Error()
		}
		u = metrics.AccountingUsage{}
	}
	a := metrics.AssessAccounting(cfg, u, now.Local())
	return &a, ""
}

// policyField returns the version after key ("Installed:") in apt-cache
// policy output.
func policyField(out, key string) string {
	for line := range strings.Lines(out) {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == key {
			return f[1]
		}
	}
	return ""
}

// Runner performs one alert run.
type Runner struct {
	Host      host.Host
	Config    Config
	Notifiers []Notifier
	StatePath string    // default DefaultStatePath; use one file per tor instance
	Out       io.Writer // progress and, in a dry run, the messages
	// Instance names the tor instance in messages ("default" or the Debian
	// instance name); empty leaves it out.
	Instance string
	// DryRun prints what would be sent and leaves the state file alone.
	DryRun bool
}

// Run evaluates in against the saved state, sends the notifications and
// saves the new state. It fails when a notifier failed; when every
// notifier failed, the open problems are kept as they were, so the next
// run sends them again.
func (r Runner) Run(ctx context.Context, in Input) error {
	path := r.StatePath
	if path == "" {
		path = DefaultStatePath
	}
	prev, err := LoadState(r.Host, path)
	if err != nil {
		fmt.Fprintln(r.Out, "warning:", err)
	}
	ev := Evaluate(in, prev.Observed, r.Config)
	notes, next := Plan(prev, ev, in.Now, r.Config)

	open := len(next.Active)
	if len(notes) == 0 {
		fmt.Fprintf(r.Out, "Nothing to send (%d open problem(s)).\n", open)
		if r.DryRun {
			return nil
		}
		return SaveState(r.Host, path, next)
	}
	m := r.message(in, notes)
	if r.DryRun {
		fmt.Fprintf(r.Out, "Dry run: would send to %d notifier(s), state not updated.\nSubject: %s\n\n%s", len(r.Notifiers), m.Subject(), m.Text())
		for _, n := range r.Notifiers {
			fmt.Fprintln(r.Out, "  ->", n.Name())
		}
		return nil
	}
	failed := r.send(ctx, m)
	if failed == len(r.Notifiers) {
		next.Active = prev.Active
	}
	if err := SaveState(r.Host, path, next); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d notifiers failed", failed, len(r.Notifiers))
	}
	return nil
}

// Test sends a test message to every notifier.
func (r Runner) Test(ctx context.Context, in Input) error {
	m := r.message(in, []Notification{{
		Alert: Alert{ID: "test", Severity: Info, Title: "test notification",
			Body: "tor-relay-setup alerts reach you through this notifier."},
		Status: StatusTest,
	}})
	m.Test = true
	if r.DryRun {
		fmt.Fprintf(r.Out, "Dry run: would send a test notification to %d notifier(s).\nSubject: %s\n\n%s", len(r.Notifiers), m.Subject(), m.Text())
		for _, n := range r.Notifiers {
			fmt.Fprintln(r.Out, "  ->", n.Name())
		}
		return nil
	}
	if failed := r.send(ctx, m); failed > 0 {
		return fmt.Errorf("%d of %d notifiers failed", failed, len(r.Notifiers))
	}
	return nil
}

// send delivers m to every notifier and returns how many failed.
func (r Runner) send(ctx context.Context, m Message) int {
	failed := 0
	for _, n := range r.Notifiers {
		if err := n.Send(ctx, m); err != nil {
			failed++
			fmt.Fprintln(r.Out, "failed:", err)
			continue
		}
		fmt.Fprintf(r.Out, "sent %d alert(s) to %s\n", len(m.Alerts), n.Name())
	}
	return failed
}

func (r Runner) message(in Input, notes []Notification) Message {
	host, _ := os.Hostname()
	m := Message{
		Relay:       r.Config.Name,
		Nickname:    in.Report.Relay.Nickname,
		Fingerprint: in.Report.Relay.Fingerprint,
		Host:        host,
		Instance:    r.Instance,
		Time:        in.Now.UTC(),
		Alerts:      notes,
	}
	if m.Relay == "" {
		m.Relay = m.Nickname
	}
	if m.Relay == "" {
		m.Relay = m.Host
	}
	return m
}
