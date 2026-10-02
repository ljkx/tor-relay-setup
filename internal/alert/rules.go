package alert

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/status"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

// Input is everything one run observed.
type Input struct {
	Now time.Time
	// Report is status.Collect's report, with Directory/DirectoryError
	// filled in by status.Directory when the fingerprint is known.
	Report status.Report

	// Sample is the MetricsPort scrape; nil without a MetricsPort or when
	// the scrape failed (SampleErr says why).
	Sample    *metrics.Sample
	SampleErr string

	// Accounting is set when torrc has AccountingMax; AccountingErr when
	// the limit or tor's state file could not be read.
	Accounting    *metrics.Accounting
	AccountingErr string

	// TorInstalled and TorCandidate are apt-cache policy's versions of the
	// tor package (CheckUpdates only); UpdateErr when the lookup failed.
	TorInstalled, TorCandidate string
	UpdateErr                  string
}

// Evaluation is the outcome of Evaluate.
type Evaluation struct {
	Alerts []Alert
	// Unknown lists alert ID prefixes whose condition could not be checked
	// this run (Tor Metrics or the MetricsPort did not answer). Plan keeps
	// their previous state instead of reporting them resolved.
	Unknown []string
	// Observed is what the next run compares against.
	Observed Observed
}

// Observed is the part of State that records observations rather than
// notifications.
type Observed struct {
	Sample    *metrics.Sample         `json:"sample,omitempty"`
	Flags     []string                `json:"flags,omitempty"`
	Published bool                    `json:"published,omitempty"`
	Overload  map[string]OverloadMark `json:"overload,omitempty"`
}

// OverloadMark remembers the last time an overload signal fired.
type OverloadMark struct {
	At       time.Time `json:"at"`
	Severity Severity  `json:"severity"`
	Summary  string    `json:"summary"`
}

// Alert ID prefixes for the unknown-state bookkeeping.
const (
	prefixDirectory  = "directory-"
	prefixFlag       = "flag-lost-"
	prefixOverload   = "overload-"
	prefixAccounting = "accounting-"
	idUpdate         = "tor-update"
)

// Evaluate turns observations into the alerts firing now. prev supplies
// the earlier observations: the MetricsPort baseline for overload deltas,
// the flags the relay held, whether Tor Metrics ever listed it, and recent
// overload marks.
func Evaluate(in Input, prev Observed, cfg Config) Evaluation {
	var ev Evaluation
	r := in.Report
	add := func(a Alert) { ev.Alerts = append(ev.Alerts, a) }
	unit := r.Service.Unit
	if !r.Relay.Configured {
		// Nothing else applies; keep every earlier observation.
		add(Alert{ID: "relay-not-configured", Severity: Critical, Title: "no relay is configured in /etc/tor/torrc",
			Body: "torrc has no ORPort, so this server does not run a relay. Set it up again with: sudo tor-relay-setup"})
		ev.Unknown = []string{prefixDirectory, prefixFlag, prefixOverload, prefixAccounting, idUpdate}
		ev.Observed = prev
		return ev
	}

	// Local health, the same checks as `status`.
	switch {
	case !r.Tor.Installed:
		add(Alert{ID: "tor-missing", Severity: Critical, Title: "tor is not installed",
			Body: "The tor binary does not run, so the relay is offline. Reinstall it: sudo tor-relay-setup apply --config <relay.toml>, or apt install tor."})
	case r.Tor.Version != "" && !r.Tor.Supported:
		add(Alert{ID: "tor-unsupported", Severity: Critical, Title: "tor " + r.Tor.Version + " is no longer supported",
			Body: "Tor " + r.Tor.Version + " is older than " + torproject.MinVersion + "; directory authorities reject relays running it. Upgrade tor from the Tor Project repository (apt update && apt install tor)."})
	}
	if !r.Service.Active {
		add(Alert{ID: "service-inactive", Severity: Critical, Title: unit + " is not running",
			Body: "The tor service is not active, so the relay is offline. Look at: systemctl status " + unit + "; journalctl -u " + unit + " -n 50"})
	} else if !r.Listener.IPv4 && !r.Listener.IPv6 && r.Relay.ORPort > 0 {
		add(Alert{ID: "orport-not-listening", Severity: Critical, Title: fmt.Sprintf("nothing listens on ORPort %d", r.Relay.ORPort),
			Body: "tor runs but has not opened its ORPort; it may still be starting, or it failed to bind. Check: journalctl -u " + unit + " -n 50"})
	}
	if r.Reachability.Failed && !r.Reachability.IPv4 {
		add(Alert{ID: "orport-unreachable", Severity: Critical, Title: "the ORPort is not reachable from outside",
			Body: fmt.Sprintf("Tor's self-test could not confirm that ORPort %d is reachable from the internet, so the relay will not be published. Check the firewall (and any provider firewall) allows inbound TCP %d, and that the address in torrc is the public one.", r.Relay.ORPort, r.Relay.ORPort)})
	}
	if len(r.Family.MissingKeys) > 0 {
		add(Alert{ID: "family-key-missing", Severity: Warning, Title: "family key missing",
			Body: "torrc declares FamilyId " + strings.Join(r.Family.MissingKeys, ", ") + " but no matching secret family key is installed in " + r.Family.KeyDirectory + ". Copy the family's NAME.secret_family_key there (owned by debian-tor, mode 0600) and restart tor."})
	}

	if w := status.BridgeWarnings(r); len(w) > 0 {
		add(Alert{ID: "bridge-transport", Severity: Critical, Title: "the bridge's transport needs attention",
			Body: strings.Join(w, ". ") + "."})
	}
	if r.Keys != nil {
		if w := r.Keys.Warnings(in.Now, 0); len(w) > 0 {
			sev := Warning
			if !r.Keys.CertExpires.IsZero() && !r.Keys.CertExpires.After(in.Now) {
				sev = Critical // tor stops with an expired signing certificate
			}
			add(Alert{ID: "signing-key", Severity: sev, Title: "the relay's identity keys need attention",
				Body: strings.Join(w, ". ") + "."})
		}
	}

	evalDirectory(&ev, in, prev, cfg)
	evalOverload(&ev, in, prev, cfg)
	evalAccounting(&ev, in, cfg)

	if in.SampleErr != "" && r.Relay.MetricsPort != "" && r.Service.Active {
		add(Alert{ID: "metricsport-down", Severity: Info, Title: "the MetricsPort does not answer",
			Body: "tor runs but its MetricsPort (" + r.Relay.MetricsPort + ") could not be read, so overload signals are not checked: " + in.SampleErr})
	}
	if cfg.CheckUpdates {
		switch {
		case in.UpdateErr != "":
			ev.Unknown = append(ev.Unknown, idUpdate)
		case in.TorCandidate != "" && in.TorCandidate != "(none)" && in.TorInstalled != "" && in.TorInstalled != "(none)" && in.TorCandidate != in.TorInstalled:
			add(Alert{ID: idUpdate, Severity: Info, Title: "tor " + in.TorCandidate + " is available",
				Body: "The installed tor package is " + in.TorInstalled + ". unattended-upgrades installs it if enabled; otherwise run: apt install tor"})
		}
	}
	return ev
}

// evalDirectory checks what Tor Metrics says: running, listed, flags and
// Relay Search's overload mark.
func evalDirectory(ev *Evaluation, in Input, prev Observed, cfg Config) {
	r := in.Report
	ev.Observed.Published = prev.Published
	ev.Observed.Flags = prev.Flags
	if r.Relay.Fingerprint == "" || r.DirectoryError != "" {
		ev.Unknown = append(ev.Unknown, prefixDirectory)
		return
	}
	d := r.Directory
	if d == nil {
		if prev.Published {
			ev.Alerts = append(ev.Alerts, Alert{ID: "directory-missing", Severity: Critical, Title: "the relay dropped out of the consensus",
				Body: "Tor Metrics listed this relay before but no longer does, so clients cannot use it. Check that tor runs, that the ORPort is reachable, and tor's log for directory authority errors."})
		}
		return
	}
	ev.Observed.Published = true
	if !d.Running {
		ev.Alerts = append(ev.Alerts, Alert{ID: "directory-not-running", Severity: Critical, Title: "Tor Metrics does not see the relay running",
			Body: "The directory authorities did not find the relay reachable in the latest consensus (Tor Metrics lags by an hour or two). Check that tor runs and the ORPort is reachable from outside."})
	}
	if d.Overloaded(in.Now) {
		ev.Alerts = append(ev.Alerts, Alert{ID: "directory-overloaded", Severity: Warning, Title: "Relay Search shows the relay as overloaded",
			Body: "Tor reported overload-general at " + d.OverloadGeneral.UTC().Format("2006-01-02 15:04 UTC") + "; Relay Search shows it for 72 hours after the last event. The overload alerts (with a MetricsPort) or tor's log say which limit was hit; see https://support.torproject.org/relays/performance/overloaded/"})
	}
	var held []string
	for _, f := range cfg.WatchFlags {
		if slices.Contains(d.Flags, f) {
			held = append(held, f)
		} else if slices.Contains(prev.Flags, f) {
			ev.Alerts = append(ev.Alerts, Alert{ID: prefixFlag + f, Severity: Warning, Event: true, Title: "the relay lost the " + f + " flag",
				Body: "The relay had the " + f + " flag at the last check and the latest consensus no longer gives it. " + flagHint(f)})
		}
	}
	ev.Observed.Flags = held
}

func flagHint(flag string) string {
	switch flag {
	case "Guard":
		return "Guard needs about 8 days of stable uptime and enough bandwidth; a restart or outage resets the clock."
	case "Stable":
		return "Stable depends on mean time between failures; restarts and outages lower it."
	case "Fast":
		return "Fast needs at least 100 KB/s measured bandwidth (or the top 7/8 of relays); check bandwidth limits and accounting."
	case "HSDir":
		return "HSDir needs the Stable flag and about 96 hours of uptime."
	}
	return ""
}

// evalOverload compares the MetricsPort sample with the previous one.
// An overload alert stays open for OverloadHold after its signal last
// fired.
func evalOverload(ev *Evaluation, in Input, prev Observed, cfg Config) {
	marks := map[string]OverloadMark{}
	for sig, m := range prev.Overload {
		if in.Now.Sub(m.At) < cfg.OverloadHold.Duration {
			marks[sig] = m
		}
	}
	if in.Sample == nil {
		ev.Observed.Sample = prev.Sample
		ev.Observed.Overload = nilIfEmpty(marks)
		if in.Report.Relay.MetricsPort != "" {
			ev.Unknown = append(ev.Unknown, prefixOverload)
		}
		return
	}
	ev.Observed.Sample = in.Sample
	var base metrics.Sample
	if prev.Sample != nil {
		base = *prev.Sample
	}
	o := metrics.AssessOverload(base, *in.Sample)
	findings := map[string]metrics.Finding{}
	for _, f := range o.Findings {
		// Within the hold period the severity only goes up, so a quieter
		// window does not silently downgrade an open alert.
		sev := max(overloadSeverity(f), marks[string(f.Signal)].Severity)
		findings[string(f.Signal)] = f
		marks[string(f.Signal)] = OverloadMark{At: in.Now, Severity: sev, Summary: f.Summary}
	}
	for _, sig := range metrics.Signals {
		m, ok := marks[string(sig)]
		if !ok {
			continue
		}
		body := m.Summary
		if _, now := findings[string(sig)]; !now {
			body += fmt.Sprintf(" (last seen %s)", m.At.UTC().Format("2006-01-02 15:04 UTC"))
		}
		explanation, remedy := sig.Describe()
		body += ".\n" + explanation + "\nRemedy: " + remedy
		ev.Alerts = append(ev.Alerts, Alert{ID: prefixOverload + string(sig), Severity: m.Severity, Title: overloadTitle(sig), Body: body})
	}
	ev.Observed.Overload = nilIfEmpty(marks)
}

// overloadSeverity: what makes Relay Search (or tor's fd accounting) flag
// the relay is a warning; early signs and rate limits are informational.
func overloadSeverity(f metrics.Finding) Severity {
	switch {
	case f.Signal == metrics.SignalRateLimited:
		return Info
	case f.Signal == metrics.SignalSocketsExhausted:
		return Warning // close to the limit is already worth acting on
	case f.Published:
		return Warning
	default:
		return Info
	}
}

func overloadTitle(sig metrics.Signal) string {
	switch sig {
	case metrics.SignalOnionskinsDropped:
		return "tor is dropping circuit handshakes (CPU overload)"
	case metrics.SignalOOM:
		return "tor ran out of queue memory (MaxMemInQueues)"
	case metrics.SignalTCPExhaustion:
		return "tor ran out of local TCP ports"
	case metrics.SignalSocketsExhausted:
		return "tor is close to its file-descriptor limit"
	case metrics.SignalRateLimited:
		return "tor hit its global bandwidth limit"
	}
	return "tor reported overload"
}

// evalAccounting warns before AccountingMax puts tor into hibernation.
func evalAccounting(ev *Evaluation, in Input, cfg Config) {
	if in.AccountingErr != "" {
		ev.Unknown = append(ev.Unknown, prefixAccounting)
		return
	}
	a := in.Accounting
	if a == nil || !a.Enabled {
		return
	}
	pct := a.Fraction() * 100
	end := a.PeriodEnd.Format("2006-01-02 15:04 MST")
	usage := fmt.Sprintf("%s of %s used (%.0f%%, AccountingRule %s); the period ends %s.", metrics.FormatBytes(a.Used), metrics.FormatBytes(a.Max), pct, a.Rule, end)
	switch {
	case a.Exhausted():
		ev.Alerts = append(ev.Alerts, Alert{ID: prefixAccounting + "exhausted", Severity: Critical, Title: "AccountingMax is used up: tor hibernates",
			Body: usage + " Tor stops relaying until the next period. Raise AccountingMax if the provider allows it."})
	case pct >= float64(cfg.AccountingThreshold):
		ev.Alerts = append(ev.Alerts, Alert{ID: prefixAccounting + "high", Severity: Warning, Title: fmt.Sprintf("%.0f%% of AccountingMax used", pct),
			Body: usage + accountingProjection(*a)})
	case a.RunsOut():
		ev.Alerts = append(ev.Alerts, Alert{ID: prefixAccounting + "runs-out", Severity: Warning, Title: "AccountingMax will run out before the period ends",
			Body: usage + accountingProjection(*a)})
	}
}

func accountingProjection(a metrics.Accounting) string {
	if !a.RunsOut() {
		return ""
	}
	return " At the pace so far it is used up around " + a.ExhaustsAt.Format("2006-01-02 15:04 MST") +
		" and tor then hibernates until the period ends. Lower RelayBandwidthRate (sudo tor-relay-setup → Bandwidth) to spread the budget over the whole period."
}

func nilIfEmpty(m map[string]OverloadMark) map[string]OverloadMark {
	if len(m) == 0 {
		return nil
	}
	return m
}
