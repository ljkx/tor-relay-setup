package alert

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// DefaultStatePath keeps the state between runs, next to the update-check
// cache. `tor-relay-setup uninstall` removes the directory.
const DefaultStatePath = "/var/lib/tor-relay-setup/alert-state.json"

// stateVersion is bumped when the format changes incompatibly; an older
// or newer file is ignored (one run without a baseline).
const stateVersion = 1

// State is what one run leaves for the next.
type State struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Observed
	// Active holds the problems that were present at the last run, by
	// alert ID.
	Active map[string]Active `json:"active,omitempty"`
}

// Active is an open problem.
type Active struct {
	Severity     Severity  `json:"severity"`
	Title        string    `json:"title"`
	Body         string    `json:"body,omitempty"`
	Since        time.Time `json:"since"`
	LastNotified time.Time `json:"last_notified,omitzero"`
}

// Plan compares the alerts firing now with the previous state and returns
// the notifications to send and the next state:
//
//   - a new alert, or one more severe than before, is sent as firing;
//   - an open alert is sent again as a reminder once RemindEvery has passed
//     since it was last sent (never when RemindEvery is 0);
//   - an alert that is gone is sent as resolved, unless its condition
//     could not be checked this run (Evaluation.Unknown): then it stays
//     open unchanged;
//   - event alerts are sent once and not kept.
//
// Alerts below MinSeverity are tracked but not sent.
func Plan(prev State, ev Evaluation, now time.Time, cfg Config) ([]Notification, State) {
	next := State{Version: stateVersion, UpdatedAt: now, Observed: ev.Observed, Active: map[string]Active{}}
	var out []Notification
	send := func(sev Severity) bool { return sev >= cfg.MinSeverity }
	seen := map[string]bool{}
	for _, a := range ev.Alerts {
		if a.Event {
			if send(a.Severity) {
				out = append(out, Notification{Alert: a, Status: StatusFiring, Since: now})
			}
			continue
		}
		seen[a.ID] = true
		cur := Active{Severity: a.Severity, Title: a.Title, Body: a.Body, Since: now}
		p, open := prev.Active[a.ID]
		if open {
			cur.Since, cur.LastNotified = p.Since, p.LastNotified
		}
		status := Status("")
		switch {
		case !open, a.Severity > p.Severity && send(a.Severity):
			status = StatusFiring
		case p.LastNotified.IsZero() && send(a.Severity):
			status = StatusFiring // below MinSeverity until now
		case cfg.RemindEvery.Duration > 0 && now.Sub(p.LastNotified) >= cfg.RemindEvery.Duration:
			status = StatusReminder
		}
		if status != "" && send(a.Severity) {
			out = append(out, Notification{Alert: a, Status: status, Since: cur.Since})
			cur.LastNotified = now
		}
		next.Active[a.ID] = cur
	}
	for id, p := range prev.Active {
		if seen[id] {
			continue
		}
		if unknown(id, ev.Unknown) {
			next.Active[id] = p
			continue
		}
		if !p.LastNotified.IsZero() {
			out = append(out, Notification{
				Alert:  Alert{ID: id, Severity: p.Severity, Title: p.Title, Body: "No longer detected."},
				Status: StatusResolved, Since: p.Since,
			})
		}
	}
	slices.SortStableFunc(out, func(a, b Notification) int {
		if c := cmp.Compare(rank(a.Status), rank(b.Status)); c != 0 {
			return c
		}
		if c := cmp.Compare(b.Severity, a.Severity); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	if len(next.Active) == 0 {
		next.Active = nil
	}
	return out, next
}

func rank(s Status) int {
	switch s {
	case StatusFiring:
		return 0
	case StatusReminder:
		return 1
	default:
		return 2
	}
}

func unknown(id string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(id, p) })
}

// LoadState reads the state file through h. A missing file is an empty
// state. An unreadable or foreign file also yields an empty state, with an
// error the caller may report as a warning: alerts must keep working.
func LoadState(h host.Host, path string) (State, error) {
	data, err := h.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read alert state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("alert state %s is corrupt, starting afresh: %w", path, err)
	}
	if s.Version != stateVersion {
		return State{}, fmt.Errorf("alert state %s has format %d, starting afresh", path, s.Version)
	}
	return s, nil
}

// SaveState writes the state atomically with mode 0600 in a 0700
// directory. Through a dry-run host nothing is written.
func SaveState(h host.Host, path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := h.MkdirAll(filepath.Dir(path), 0o700, ""); err != nil {
		return fmt.Errorf("save alert state: %w", err)
	}
	if _, err := h.WriteFile(path, append(data, '\n'), host.FileOptions{Mode: 0o600}); err != nil {
		return fmt.Errorf("save alert state: %w", err)
	}
	return nil
}
