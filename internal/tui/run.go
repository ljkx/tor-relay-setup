package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"charm.land/huh/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

// RunSetup opens the full-screen setup wizard.
func RunSetup(opt Options) error {
	prefill := config.Default()
	if opt.Prefill != nil {
		prefill = *opt.Prefill
	}
	a := newApp(opt, nil)
	a.screen = newWizard(a, prefill)
	return run(a)
}

// RunConsole opens the operator console.
func RunConsole(opt Options) error {
	return run(newApp(opt, newConsole()))
}

// RunSetupPlain asks the wizard questions as plain, screen-reader-friendly
// prompts (huh accessible mode), then applies with line-by-line output.
func RunSetupPlain(opt Options, in io.Reader, out io.Writer) error {
	facts, err := detect(opt.Host)
	if err != nil {
		return err
	}
	prefill := config.Default()
	if opt.Prefill != nil {
		prefill = *opt.Prefill
	}
	a := newApp(opt, nil)
	a.checks.Facts, a.checks.FactsReady = facts, true
	w := newWizard(a, prefill)
	if err := w.form.WithAccessible(true).WithInput(in).WithOutput(out).Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return ErrAborted
		}
		return err
	}
	return RunApplyPlain(opt, w.ans.setup(), facts, false, in, out)
}

// RunApplyPlain prints the plan and applies it with plain output. When yes
// is false the operator confirms first.
func RunApplyPlain(opt Options, s config.Setup, facts system.Facts, yes bool, in io.Reader, out io.Writer) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if !facts.Systemd && facts.OSID == "" {
		var err error
		if facts, err = detect(opt.Host); err != nil {
			return err
		}
	}
	steps := plan.Build(s, facts)
	fmt.Fprintf(out, "\nPlanned changes for %s (%s):\n", s.Relay.Nickname, s.Relay.Mode)
	for i, c := range plan.Changes(steps) {
		fmt.Fprintf(out, "  %2d. %s\n", i+1, c)
	}
	if opt.DryRun {
		fmt.Fprintln(out, "\nDry run: commands and file writes are only shown.")
	}
	if !yes {
		ok := false
		confirm := huh.NewConfirm().Title("Apply these changes now?").Value(&ok)
		if err := confirm.RunAccessible(out, in); err != nil {
			return err
		}
		if !ok {
			return ErrAborted
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if l := localOf(opt.Host); l != nil {
		l.Observe = func(e host.Event) {
			switch {
			case e.Dry && e.Kind == host.EventCommand:
				fmt.Fprintln(out, "      would run: "+e.Text)
			case e.Dry:
				fmt.Fprintln(out, "      "+e.Text)
			}
		}
	}
	env := plan.NewEnv(opt.Host, facts, s, program(opt.Version))
	lastPct := map[int]int{}
	err := plan.Run(ctx, steps, env, func(e plan.Event) {
		prefix := fmt.Sprintf("[%d/%d]", e.Step+1, len(steps))
		switch e.Kind {
		case plan.StepStarted:
			fmt.Fprintf(out, "%s %s\n", prefix, e.Text)
		case plan.StepProgress:
			if p := int(e.Percent) / 25 * 25; p > lastPct[e.Step] && p < 100 {
				lastPct[e.Step] = p
				fmt.Fprintf(out, "      %3d%% %s\n", p, e.Text)
			}
		case plan.StepNote:
			mark := "·"
			switch e.Level {
			case plan.Success:
				mark = "✓"
			case plan.Warn:
				mark = "!"
			}
			fmt.Fprintf(out, "      %s %s\n", mark, e.Text)
		case plan.StepFinished:
			fmt.Fprintf(out, "      done in %s\n", formatDuration(e.Elapsed))
		case plan.StepFailed:
			fmt.Fprintf(out, "      FAILED: %s\n", e.Text)
		}
	})
	if err != nil {
		return err
	}
	if opt.DryRun {
		fmt.Fprintln(out, "\nDry run complete. Nothing was changed.")
		return nil
	}
	fmt.Fprintln(out, "\nRelay configured. Open the console with: sudo tor-relay-setup")
	if fp := readFingerprint(opt.Host, s.Instance()); fp != "" {
		fmt.Fprintln(out, "Fingerprint:", fp)
	}
	if env.FamilyID != "" {
		fmt.Fprintln(out, "FamilyId:", env.FamilyID)
	}
	if s.IsBridge() {
		fmt.Fprintln(out, "Bridge line: sudo tor-relay-setup status (once tor has started the transport)")
	}
	return nil
}

func detect(h host.Host) (system.Facts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return system.Detect(ctx, h, os.Getenv)
}

func localOf(h host.Host) *host.Local {
	switch v := h.(type) {
	case *host.Local:
		return v
	case *host.DryRun:
		return v.Local
	}
	return nil
}

// Interactive reports whether stdin and stdout are terminals.
func Interactive() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		info, err := f.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return false
		}
	}
	return !strings.EqualFold(os.Getenv("TERM"), "dumb")
}
