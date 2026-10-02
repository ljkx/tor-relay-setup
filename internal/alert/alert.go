// Package alert watches a relay and notifies its operator when something
// needs attention: the service is down, the ORPort is unreachable, the
// relay left the consensus or lost a flag, tor reports overload, or the
// AccountingMax budget is running out.
//
// One run (a systemd timer starts `tor-relay-setup alert run` every few
// minutes) gathers an Input (Gather), turns it into the alerts that are
// firing now (Evaluate), compares them with the previous run's State
// (Plan) so that only transitions are sent (a problem appears, is still
// there after the reminder interval, or resolves), and hands the resulting
// Message to every configured Notifier.
package alert

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Severity orders alerts. The zero value is Info.
type Severity int

const (
	Info Severity = iota
	Warning
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case Warning:
		return "warning"
	default:
		return "info"
	}
}

// MarshalText encodes the severity as its name, in JSON and TOML.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText accepts "info", "warning" or "critical".
func (s *Severity) UnmarshalText(b []byte) error {
	switch strings.ToLower(strings.TrimSpace(string(b))) {
	case "info":
		*s = Info
	case "warning":
		*s = Warning
	case "critical":
		*s = Critical
	default:
		return fmt.Errorf("unknown severity %q: want info, warning or critical", b)
	}
	return nil
}

// Alert is one problem that is present now.
type Alert struct {
	// ID is stable across runs, e.g. "service-inactive" or
	// "flag-lost-Guard"; Plan matches alerts by it.
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Body     string   `json:"body"`
	// Event marks something that happened once, such as a lost flag: it is
	// sent when it happens and is neither reminded nor resolved.
	Event bool `json:"-"`
}

// Status says why a notification is sent.
type Status string

const (
	StatusFiring   Status = "firing"   // new (or more severe than before)
	StatusReminder Status = "reminder" // still present after the reminder interval
	StatusResolved Status = "resolved" // gone since the last run
	StatusTest     Status = "test"     // alert test
)

// Notification is an alert with the reason it is sent.
type Notification struct {
	Alert
	Status Status    `json:"status"`
	Since  time.Time `json:"since,omitzero"` // when the problem was first seen
}

// Message is what one run sends to every notifier.
type Message struct {
	Relay       string         `json:"relay"` // display name: the configured name, nickname or host
	Nickname    string         `json:"nickname,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Host        string         `json:"host,omitempty"`
	Instance    string         `json:"instance,omitempty"` // tor instance on the host, when there are several
	Time        time.Time      `json:"time"`
	Test        bool           `json:"test,omitempty"`
	Alerts      []Notification `json:"alerts"`
}

// MaxSeverity is the highest severity among alerts that are not resolved;
// Info when every alert resolved.
func (m Message) MaxSeverity() Severity {
	s := Info
	for _, a := range m.Alerts {
		if a.Status != StatusResolved && a.Severity > s {
			s = a.Severity
		}
	}
	return s
}

// AllResolved reports whether every notification is a resolution.
func (m Message) AllResolved() bool {
	return len(m.Alerts) > 0 && !slices.ContainsFunc(m.Alerts, func(n Notification) bool { return n.Status != StatusResolved })
}

// Subject is a one-line summary for an email subject or push title.
func (m Message) Subject() string {
	if len(m.Alerts) == 0 {
		return m.Relay + ": nothing to report"
	}
	first := m.Alerts[0]
	s := m.Relay + ": " + label(first) + " " + first.Title
	if n := len(m.Alerts) - 1; n > 0 {
		s += fmt.Sprintf(" (+%d more)", n)
	}
	return oneLine(s)
}

// Text renders the message as plain text for email, ntfy and chat.
func (m Message) Text() string {
	var b strings.Builder
	who := m.Relay
	var ids []string
	if m.Nickname != "" && m.Nickname != m.Relay {
		ids = append(ids, m.Nickname)
	}
	if m.Host != "" && m.Host != m.Relay {
		ids = append(ids, m.Host)
	}
	if m.Instance != "" {
		ids = append(ids, "tor instance "+m.Instance)
	}
	if m.Fingerprint != "" {
		ids = append(ids, m.Fingerprint)
	}
	if len(ids) > 0 {
		who += " (" + strings.Join(ids, ", ") + ")"
	}
	fmt.Fprintf(&b, "tor-relay-setup on %s at %s\n", who, m.Time.UTC().Format("2006-01-02 15:04 UTC"))
	for _, n := range m.Alerts {
		fmt.Fprintf(&b, "\n%s %s\n", label(n), n.Title)
		if n.Body != "" {
			for line := range strings.Lines(n.Body) {
				b.WriteString("  " + line)
			}
			if !strings.HasSuffix(n.Body, "\n") {
				b.WriteByte('\n')
			}
		}
		if !n.Since.IsZero() && n.Status != StatusFiring {
			fmt.Fprintf(&b, "  first seen %s\n", n.Since.UTC().Format("2006-01-02 15:04 UTC"))
		}
	}
	return b.String()
}

// label is the bracketed prefix of a notification line.
func label(n Notification) string {
	switch n.Status {
	case StatusResolved:
		return "[RESOLVED]"
	case StatusTest:
		return "[TEST]"
	case StatusReminder:
		return "[" + strings.ToUpper(n.Severity.String()) + ", still]"
	default:
		return "[" + strings.ToUpper(n.Severity.String()) + "]"
	}
}

// oneLine removes line breaks, so text is safe in mail and HTTP headers.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
