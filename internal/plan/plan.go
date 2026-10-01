// Package plan turns a config.Setup into an ordered list of steps and runs
// them. Each step reports progress, log lines, and notes through a Reporter,
// so the TUI, the plain-text runner, and tests all observe the same events.
package plan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

// Level is the severity of a note.
type Level int

// Note levels.
const (
	Info Level = iota
	Success
	Warn
)

// Reporter receives what a running step wants to show.
type Reporter interface {
	// Progress reports completion of the current step (0–100) and what is
	// happening right now.
	Progress(percent float64, detail string)
	// Log records one line of command output.
	Log(line string)
	// Note records a human-readable remark.
	Note(level Level, msg string)
}

// Env carries everything steps need, and collects what they produce.
type Env struct {
	Host      host.Host
	Facts     system.Facts
	Setup     config.Setup
	HTTP      *http.Client
	Program   string // shown in the generated torrc header
	Now       func() time.Time
	TorrcPath string
	StateDir  string

	// Filled in while running.
	FamilyID    string
	NewPackages []string
	RestartedAt time.Time
}

// NewEnv returns an Env with production defaults.
func NewEnv(h host.Host, facts system.Facts, s config.Setup, program string) *Env {
	return &Env{
		Host:      h,
		Facts:     facts,
		Setup:     s,
		HTTP:      &http.Client{Timeout: 20 * time.Second},
		Program:   program,
		Now:       time.Now,
		TorrcPath: "/etc/tor/torrc",
		StateDir:  "/var/lib/tor-relay-setup",
	}
}

// Step is one unit of work shown as a line in the apply checklist.
type Step struct {
	ID    string
	Title string
	// Changes lists the privileged changes the step makes, for the review.
	Changes []string
	// Weight is the step's share of the overall progress bar.
	Weight float64
	Run    func(ctx context.Context, e *Env, r Reporter) error
}

// EventKind classifies executor events.
type EventKind int

// Executor events.
const (
	StepStarted EventKind = iota
	StepProgress
	StepLog
	StepNote
	StepFinished
	StepFailed
)

// Event is emitted by Run for every state change.
type Event struct {
	Kind    EventKind
	Step    int
	Percent float64
	Text    string
	Level   Level
	Elapsed time.Duration
	Err     error
}

type reporter struct {
	step int
	emit func(Event)
}

func (r reporter) Progress(p float64, detail string) {
	r.emit(Event{Kind: StepProgress, Step: r.step, Percent: p, Text: detail})
}
func (r reporter) Log(line string) { r.emit(Event{Kind: StepLog, Step: r.step, Text: line}) }
func (r reporter) Note(l Level, msg string) {
	r.emit(Event{Kind: StepNote, Step: r.step, Level: l, Text: msg})
}

// ErrStopped wraps the error of the step that stopped a run.
var ErrStopped = errors.New("setup stopped")

// Run executes steps in order and stops at the first failure.
func Run(ctx context.Context, steps []Step, e *Env, emit func(Event)) error {
	for i, s := range steps {
		start := time.Now()
		emit(Event{Kind: StepStarted, Step: i, Text: s.Title})
		err := s.Run(ctx, e, reporter{step: i, emit: emit})
		elapsed := time.Since(start)
		if err != nil {
			emit(Event{Kind: StepFailed, Step: i, Elapsed: elapsed, Err: err, Text: err.Error()})
			return fmt.Errorf("%w at %q: %w", ErrStopped, s.Title, err)
		}
		emit(Event{Kind: StepFinished, Step: i, Elapsed: elapsed})
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

// Changes flattens every step's planned changes for the review screen.
func Changes(steps []Step) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.Changes...)
	}
	return out
}
