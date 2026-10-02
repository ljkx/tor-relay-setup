package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/monitor"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

const monitorUsage = `tor-relay-setup monitor — a Grafana dashboard for the whole fleet, on a management server

Usage:
  tor-relay-setup monitor install --domain NAME [--email ADDR] [--inventory FILE]
                                  [--fleet-path /fleet|off] [--admin-user NAME] [--rotate-token]
        install and configure fleet serve, Prometheus, Grafana and Caddy (HTTPS) on this
        server (Debian 12/13, Ubuntu 22.04/24.04/26.04); safe to run again
  tor-relay-setup monitor install --local [--inventory FILE] [--admin-user NAME] [--rotate-token]
        the same stack without Caddy and without opening any port, e.g. on one of your
        non-exit relays (refused on an exit); Grafana is reached through an SSH tunnel
  tor-relay-setup monitor status
        services, scrape health, Grafana URL (or the tunnel command) and the SSH key
        relays must authorize
  tor-relay-setup monitor uninstall [--purge]
        stop the stack; --purge also removes the packages it installed, Grafana's
        database, the metrics history and the monitoring SSH key

On each relay, let the management server probe it (prints what to add on the server):
  tor-relay-setup fleet authorize --key 'ssh-ed25519 AAAA… tor-relay-monitor@HOST' [--from IP]

Flags:
  --domain NAME      DNS name for Grafana; Caddy gets a Let's Encrypt certificate for it
  --local            no public service: Grafana stays on 127.0.0.1:3000, reached with
                     ssh -N -L 3000:127.0.0.1:3000 USER@HOST and http://localhost:3000;
                     not combined with --domain, --email or --fleet-path. Running install
                     again without --local or --domain keeps the mode; --domain switches
                     to public, --local switches a public install to local (Caddy stopped,
                     its 80/443 rules removed)
  --email ADDR       ACME account e-mail (optional; expiry notices)
  --inventory FILE   fleet.toml that fleet serve probes (default /etc/tor-relay-setup/fleet.toml)
  --fleet-path PATH  publish the fleet web UI at https://NAME/PATH/ (default /fleet; off: loopback only)
  --admin-user NAME  Grafana administrator login (default tor-admin)
  --rotate-token     new bearer token between fleet serve and Prometheus
  --yes              do not ask before changing anything
  --dry-run          show every command and file change without making it

The Grafana password is generated once, printed once, and kept in
/etc/tor-relay-setup/grafana-admin (root only). See docs/monitoring/README.md.
`

// monitorArgs reports whether args run the monitor command; global
// --dry-run, --plain and --yes may come before it.
func monitorArgs(args []string) ([]string, bool) {
	return subcommandArgs(args, "monitor")
}

// fleetAuthorizeArgs reports whether args run `fleet authorize`.
func fleetAuthorizeArgs(args []string) ([]string, bool) {
	rest, ok := subcommandArgs(args, "fleet")
	if !ok {
		return nil, false
	}
	for i, a := range rest {
		switch {
		case a == "authorize":
			return append(slices.Clone(rest[i+1:]), rest[:i]...), true
		case strings.HasPrefix(a, "-") && isLeadFlag(a):
		default:
			return nil, false
		}
	}
	return nil, false
}

func isLeadFlag(a string) bool {
	switch strings.TrimLeft(a, "-") {
	case "dry-run", "plain", "yes":
		return true
	}
	return false
}

// subcommandArgs finds cmd after leading global flags and returns its
// arguments with those flags appended.
func subcommandArgs(args []string, cmd string) ([]string, bool) {
	var lead []string
	for i, a := range args {
		switch {
		case a == cmd:
			return append(slices.Clone(args[i+1:]), lead...), true
		case strings.HasPrefix(a, "-") && isLeadFlag(a):
			if strings.TrimLeft(a, "-") != "plain" {
				lead = append(lead, a)
			}
		default:
			return nil, false
		}
	}
	return nil, false
}

// listFlag collects repeated or comma-separated values.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// Seams for tests.
var (
	detectFacts = func(ctx context.Context, h host.Host) (system.Facts, error) { return system.Detect(ctx, h, nil) }
	newPlanEnv  = func(h host.Host, f system.Facts) *plan.Env {
		return &plan.Env{Host: h, Facts: f, HTTP: &http.Client{Timeout: 30 * time.Second}, Now: time.Now}
	}
	monitorHealth  func(ctx context.Context, url string) error // nil: the real check
	monitorStatusO monitor.StatusOptions
)

func monitorCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tor-relay-setup monitor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, monitorUsage) }
	dryRun := fs.Bool("dry-run", false, "")
	yes := fs.Bool("yes", false, "")
	domain := fs.String("domain", "", "")
	localMode := fs.Bool("local", false, "")
	email := fs.String("email", "", "")
	inventory := fs.String("inventory", "", "")
	fleetPath := fs.String("fleet-path", monitor.DefaultFleetPath, "")
	adminUser := fs.String("admin-user", "", "")
	rotate := fs.Bool("rotate-token", false, "")
	purge := fs.Bool("purge", false, "")
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
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	installOnly := []string{"domain", "local", "email", "inventory", "fleet-path", "admin-user", "rotate-token"}
	fp := *fleetPath
	if fp == "off" || fp == "none" {
		fp = ""
	}
	switch {
	case *help || sub == "help":
		fmt.Fprint(stdout, monitorUsage)
		return 0
	case sub == "":
		fmt.Fprint(stderr, "monitor needs a command: install, status or uninstall\n\n"+monitorUsage)
		return 2
	case !slices.Contains([]string{"install", "status", "uninstall"}, sub):
		fmt.Fprintf(stderr, "unknown monitor command %q\n\n%s", sub, monitorUsage)
		return 2
	case fs.NArg() > 0:
		fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return 2
	case sub != "install" && slices.ContainsFunc(installOnly, func(n string) bool { return set[n] }):
		fmt.Fprintln(stderr, "--domain, --local, --email, --inventory, --fleet-path, --admin-user and --rotate-token are only used with monitor install")
		return 2
	case *localMode && set["domain"]:
		fmt.Fprintln(stderr, "--local and --domain exclude each other: --local keeps Grafana on 127.0.0.1 behind an SSH tunnel, --domain publishes it over HTTPS with Caddy")
		return 2
	case *localMode && set["email"]:
		fmt.Fprintln(stderr, "--email is not used with --local: it is the ACME e-mail for the --domain certificate, and local mode has none")
		return 2
	case *localMode && set["fleet-path"] && fp != "":
		fmt.Fprintln(stderr, "--fleet-path is not used with --local: the fleet web UI stays on 127.0.0.1:9850 and is reached through the SSH tunnel (only --fleet-path off is accepted)")
		return 2
	case *purge && sub != "uninstall":
		fmt.Fprintln(stderr, "--purge is only used with monitor uninstall")
		return 2
	case sub == "status" && (*yes || *dryRun):
		fmt.Fprintln(stderr, "monitor status takes no --yes or --dry-run")
		return 2
	}

	local := host.NewLocal()
	var h host.Host = local
	if *dryRun {
		h = host.NewDryRun(local)
		local.Observe = dryRunPrinter(stdout)
	}
	if sub == "status" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		o := monitorStatusO
		if st, _ := monitor.ReadState(h); st.Local() {
			// The tunnel command names this server's address and SSH port.
			o.Facts, _ = detectFacts(ctx, h)
		}
		s := monitor.CollectStatus(ctx, h, o)
		s.Write(stdout)
		if !s.Healthy() {
			return 1
		}
		return 0
	}
	if !*dryRun && os.Geteuid() != 0 {
		fmt.Fprintf(stderr, "tor-relay-setup monitor %s must run as root (or add --dry-run).\n", sub)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	facts, err := detectFacts(ctx, h)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	run := planRunner{Host: h, Yes: *yes, DryRun: *dryRun, Terminal: stdinIsTerminal(stdin), In: stdin, Out: stdout}
	switch sub {
	case "install":
		exe, err := executable()
		if err == nil {
			exe, err = filepath.EvalSymlinks(exe)
		}
		if err != nil {
			fmt.Fprintln(stderr, "error: find the running executable:", err)
			return 1
		}
		// The mode is explicit (--local or --domain) or the recorded one.
		prev, _ := monitor.ReadState(h)
		isLocal := monitor.LocalMode(prev, *localMode, set["domain"])
		if isLocal && !set["fleet-path"] {
			fp = ""
		}
		if isLocal && !*localMode {
			fmt.Fprintln(stdout, "Keeping local mode from the previous install (monitor install --domain NAME switches to public mode).")
		}
		in, err := monitor.NewInstall(monitor.Options{
			Local: isLocal, Domain: *domain, Email: *email, Inventory: *inventory, FleetPath: fp, AdminUser: *adminUser,
			Executable: exe, Version: buildVersion(), RotateToken: *rotate,
		}, facts)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		in.Previous = prev
		if monitorHealth != nil {
			in.Health = monitorHealth
		}
		run.Title = "Monitoring server for " + in.Opt.URL()
		if isLocal {
			run.Title = "Monitoring stack in local mode (" + strings.TrimSuffix(monitor.LocalGrafanaURL, "/") + " via an SSH tunnel)"
		}
		if err := run.Run(ctx, in.Steps(), newPlanEnv(h, facts)); err != nil {
			return reportRunError(err, stderr)
		}
		if *dryRun {
			fmt.Fprintln(stdout, "\nDry run complete. Nothing was changed.")
			return 0
		}
		fmt.Fprintln(stdout, "\nThe monitoring server is ready.")
		for _, l := range in.SummaryLines() {
			fmt.Fprintln(stdout, l)
		}
	case "uninstall":
		st, _ := monitor.ReadState(h)
		run.Title = "Remove the monitoring stack"
		if *purge {
			run.Title += " and its data"
		}
		if err := run.Run(ctx, monitor.UninstallSteps(st, *purge), newPlanEnv(h, facts)); err != nil {
			return reportRunError(err, stderr)
		}
	}
	return 0
}

// fleetAuthorizeCmd is `fleet authorize`, run on a relay.
func fleetAuthorizeCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tor-relay-setup fleet authorize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, monitorUsage) }
	dryRun := fs.Bool("dry-run", false, "")
	yes := fs.Bool("yes", false, "")
	remove := fs.Bool("remove", false, "")
	name := fs.String("name", "", "")
	var keys, from listFlag
	fs.Var(&keys, "key", "")
	fs.Var(&from, "from", "")
	help := fs.Bool("help", false, "")
	fs.BoolVar(help, "h", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case *help:
		fmt.Fprint(stdout, monitorUsage)
		return 0
	case fs.NArg() > 0:
		fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return 2
	case *remove && (len(keys) > 0 || len(from) > 0 || *name != ""):
		fmt.Fprintln(stderr, "--remove takes no --key, --from or --name")
		return 2
	}
	exe, err := executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		fmt.Fprintln(stderr, "error: find the running executable:", err)
		return 1
	}
	o := monitor.AuthorizeOptions{Keys: keys, From: splitList(strings.Join(from, ",")), Binary: filepath.Clean(exe), Name: *name, Remove: *remove}
	if err := o.Normalize(); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	local := host.NewLocal()
	var h host.Host = local
	if *dryRun {
		h = host.NewDryRun(local)
		local.Observe = dryRunPrinter(stdout)
	} else if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "tor-relay-setup fleet authorize must run as root (or add --dry-run).")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	facts := system.Facts{EUID: os.Geteuid()}
	run := planRunner{Host: h, Yes: *yes, DryRun: *dryRun, Terminal: stdinIsTerminal(stdin), In: stdin, Out: stdout,
		Title: "Let the monitoring server probe this relay"}
	if *remove {
		run.Title = "Remove the monitoring server's access"
	}
	if err := run.Run(ctx, monitor.AuthorizeSteps(o), newPlanEnv(h, facts)); err != nil {
		return reportRunError(err, stderr)
	}
	if *remove || *dryRun {
		return 0
	}
	hostName := o.Name
	if hostName == "" {
		if data, err := h.ReadFile("/etc/hostname"); err == nil {
			hostName = strings.TrimSpace(string(data))
		}
	}
	fmt.Fprintln(stdout, "\nThis relay accepts the monitoring key for user "+monitor.ProbeUser+"; it can only run:")
	fmt.Fprintln(stdout, "  "+monitor.ProbeCommand(o.Binary))
	if line := monitor.KnownHostsLine(h, hostName); line != "" {
		fmt.Fprintln(stdout, "\nOn the monitoring server, add this relay's host key (use the name or address the inventory uses):")
		fmt.Fprintln(stdout, "  echo '"+line+"' | sudo tee -a "+monitor.MonitorHome+"/.ssh/known_hosts")
	}
	fmt.Fprintln(stdout, "\nThen check from the monitoring server:")
	fmt.Fprintln(stdout, "  sudo -u "+monitor.MonitorUser+" ssh "+orPlaceholder(hostName)+" | head -c 200")
	return 0
}

// dryRunPrinter shows what a dry run would change, like apply --plain.
func dryRunPrinter(out io.Writer) func(host.Event) {
	return func(e host.Event) {
		switch {
		case e.Dry && e.Kind == host.EventCommand:
			fmt.Fprintln(out, "      would run: "+e.Text)
		case e.Dry:
			fmt.Fprintln(out, "      "+e.Text)
		}
	}
}

func orPlaceholder(s string) string {
	if s == "" {
		return "RELAY"
	}
	return s
}

func reportRunError(err error, stderr io.Writer) int {
	if errors.Is(err, errDeclined) {
		fmt.Fprintln(stderr, "Stopped. Nothing was changed.")
		return 130
	}
	fmt.Fprintln(stderr, "error:", err)
	return 1
}

var errDeclined = errors.New("declined")

// planRunner shows a plan's changes, asks once, runs it and prints its
// events line by line (like apply --plain).
type planRunner struct {
	Host     host.Host
	Title    string
	Yes      bool
	DryRun   bool
	Terminal bool
	In       io.Reader
	Out      io.Writer
}

func (p planRunner) Run(ctx context.Context, steps []plan.Step, env *plan.Env) error {
	out := p.Out
	fmt.Fprintf(out, "\nPlanned changes (%s):\n", p.Title)
	for i, c := range plan.Changes(steps) {
		fmt.Fprintf(out, "  %2d. %s\n", i+1, c)
	}
	switch {
	case p.DryRun:
		fmt.Fprintln(out, "\nDry run: commands and file writes are only shown.")
	case p.Yes:
	case p.Terminal:
		fmt.Fprint(out, "\nApply these changes now? [y/N] ")
		answer, _ := bufio.NewReader(p.In).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return errDeclined
		}
	default:
		return errors.New("no terminal to confirm the changes: review them with --dry-run, then run again with --yes")
	}
	return plan.Run(ctx, steps, env, func(e plan.Event) {
		prefix := fmt.Sprintf("[%d/%d]", e.Step+1, len(steps))
		switch e.Kind {
		case plan.StepStarted:
			fmt.Fprintf(out, "%s %s\n", prefix, e.Text)
		case plan.StepNote:
			mark := "·"
			switch e.Level {
			case plan.Success:
				mark = "✓"
			case plan.Warn:
				mark = "!"
			}
			fmt.Fprintf(out, "      %s %s\n", mark, e.Text)
		case plan.StepFailed:
			fmt.Fprintf(out, "      FAILED: %s\n", e.Text)
		}
	})
}
