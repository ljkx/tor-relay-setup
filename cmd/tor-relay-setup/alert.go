package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/alert"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

const alertUsage = `tor-relay-setup alert — tell the operator when the relay needs attention

Usage:
  tor-relay-setup alert run [--config FILE] [--dry-run]
        check the relay once and notify about what changed since the last run
  tor-relay-setup alert test [--config FILE] [--dry-run]
        send a test notification to every configured notifier
  tor-relay-setup alert install [--every 5m] [--config FILE] [--dry-run]
        install and start a systemd timer (tor-relay-setup-alert.timer) that runs "alert run"
  tor-relay-setup alert uninstall [--dry-run]
        stop and remove the timer

Flags:
  --config FILE  alert configuration (default /etc/tor-relay-setup/alerts.toml)
  --dry-run      run: print what would be sent and keep the state file;
                 test: print the message; install/uninstall: show the files and commands
  --every D      install: how often to check, 1m to 24h (default 5m)

A problem is sent when it appears, again every remind_every (default 24h) while
it lasts, and once more when it resolves. See docs/monitoring/README.md.

Files:
  /etc/tor-relay-setup/alerts.toml           notifiers and thresholds; mode 0600 (it may hold tokens)
  /var/lib/tor-relay-setup/alert-state.json  open problems and the last MetricsPort sample

Exit codes:
  0 success · 1 the relay could not be checked or a notifier failed · 2 usage error
`

// alertArgs reports whether args run the alert command and returns its
// arguments. Global --dry-run (and --plain, which alert ignores) may come
// before "alert".
func alertArgs(args []string) ([]string, bool) {
	var lead []string
	for i, a := range args {
		switch a {
		case "--dry-run", "-dry-run":
			lead = append(lead, a)
		case "--plain", "-plain":
		case "alert":
			return append(slices.Clone(args[i+1:]), lead...), true
		default:
			return nil, false
		}
	}
	return nil, false
}

// durationFlag is a flag.Value for --every that remembers whether it was set.
type durationFlag struct {
	d   time.Duration
	set bool
}

func (f *durationFlag) String() string { return f.d.String() }

func (f *durationFlag) Set(v string) error {
	d, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	f.d, f.set = d, true
	return nil
}

func alertCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tor-relay-setup alert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, alertUsage) }
	dryRun := fs.Bool("dry-run", false, "")
	cfgPath := fs.String("config", alert.DefaultConfigPath, "")
	var every durationFlag
	fs.Var(&every, "every", "")
	help := fs.Bool("help", false, "")
	fs.BoolVar(help, "h", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sub := ""
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
	}
	switch {
	case *help || sub == "help":
		fmt.Fprint(stdout, alertUsage)
		return 0
	case sub == "":
		fmt.Fprint(stderr, "alert needs a command: run, test, install or uninstall\n\n"+alertUsage)
		return 2
	case !slices.Contains([]string{"run", "test", "install", "uninstall"}, sub):
		fmt.Fprintf(stderr, "unknown alert command %q\n\n%s", sub, alertUsage)
		return 2
	case fs.NArg() > 0:
		fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return 2
	case every.set && sub != "install":
		fmt.Fprintln(stderr, "--every is only used with alert install")
		return 2
	case !filepath.IsAbs(*cfgPath) && sub == "install":
		fmt.Fprintln(stderr, "alert install needs an absolute --config path")
		return 2
	}

	local := host.NewLocal()
	var dir onionoo.Client
	// The demo and test overrides of the main command, dry runs only.
	for env, apply := range map[string]func(string){
		"TOR_RELAY_SETUP_ROOT":        func(v string) { local.Root = v },
		"TOR_RELAY_SETUP_ONIONOO_URL": func(v string) { dir.Base = v },
	} {
		if v := os.Getenv(env); v != "" {
			if !*dryRun {
				fmt.Fprintln(stderr, env, "is only allowed together with --dry-run")
				return 2
			}
			apply(v)
		}
	}
	var h host.Host = local
	if *dryRun {
		h = host.NewDryRun(local)
	}
	// run reads tor's keys and state; install/uninstall change systemd.
	if !*dryRun && os.Geteuid() != 0 && sub != "test" {
		fmt.Fprintf(stderr, "tor-relay-setup alert %s must run as root (or add --dry-run).\n", sub)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var err error
	switch sub {
	case "run", "test":
		err = alertRun(ctx, h, dir, *cfgPath, sub == "test", *dryRun, stdout, stderr)
	case "install":
		if _, cerr := loadAlertConfig(h, *cfgPath, stderr); cerr != nil {
			if !*dryRun {
				err = fmt.Errorf("%w; alert install needs a working configuration first", cerr)
				break
			}
			fmt.Fprintln(stderr, "warning:", cerr)
		}
		exe, xerr := executable()
		if xerr != nil {
			err = xerr
			break
		}
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		err = alert.Install(ctx, h, alert.InstallOptions{Executable: exe, ConfigPath: *cfgPath, Every: every.d}, stdout)
	case "uninstall":
		err = alert.Uninstall(ctx, h, stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func alertRun(ctx context.Context, h host.Host, dir onionoo.Client, cfgPath string, test, dryRun bool, stdout, stderr io.Writer) error {
	cfg, err := loadAlertConfig(h, cfgPath, stderr)
	if err != nil {
		return err
	}
	insts, _ := relay.Discover(h)
	if len(insts) == 0 {
		insts = []relay.Instance{relay.DefaultInstance()}
	}
	r := alert.Runner{
		Host: h, Config: cfg, Notifiers: cfg.Notifiers(h, nil),
		StatePath: alert.DefaultStatePath, Out: stdout, DryRun: dryRun,
	}
	if test {
		return r.Test(ctx, alert.Identify(h, insts[0].TorrcPath))
	}
	// Every relay on the server is checked, each with its own state, and
	// messages name the relay when there is more than one.
	var errs []error
	for _, inst := range insts {
		r.StatePath = alertStatePath(inst)
		if len(insts) > 1 {
			r.Instance = inst.Name
		}
		in := alert.Gather(ctx, h, alert.GatherOptions{Instance: inst, Onionoo: dir, CheckUpdates: cfg.CheckUpdates})
		if err := r.Run(ctx, in); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", inst.Name, err))
		}
	}
	return errors.Join(errs...)
}

// alertStatePath keeps the default relay's state where it always was and
// gives every named instance a file of its own.
func alertStatePath(inst relay.Instance) string {
	if inst.Name == "" || inst.Name == relay.DefaultInstanceName {
		return alert.DefaultStatePath
	}
	return strings.TrimSuffix(alert.DefaultStatePath, ".json") + "-" + inst.Name + ".json"
}

// loadAlertConfig reads and validates the configuration through h and
// warns when other users can read it.
func loadAlertConfig(h host.Host, path string, stderr io.Writer) (alert.Config, error) {
	data, err := h.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return alert.Config{}, fmt.Errorf("no alert configuration at %s (start from docs/monitoring/alerts.toml)", path)
	}
	if err != nil {
		return alert.Config{}, err
	}
	if info, err := h.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(stderr, "warning: %s is readable by other users and may hold tokens: chmod 600 %s\n", path, path)
	}
	cfg, err := alert.ParseConfig(data)
	if err != nil {
		return alert.Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Empty() {
		return alert.Config{}, fmt.Errorf("%s configures no notifier ([[ntfy]], [[webhook]], [[email]] or [[command]])", path)
	}
	return cfg, nil
}
