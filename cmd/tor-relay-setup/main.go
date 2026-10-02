// Command tor-relay-setup sets up and operates public Tor relays on Debian
// and Ubuntu: a guided wizard, a declarative apply mode, an operator console,
// and a machine-readable status report.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/alert"
	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/remote"
	"github.com/ljkx/tor-relay-setup/internal/status"
	"github.com/ljkx/tor-relay-setup/internal/system"
	"github.com/ljkx/tor-relay-setup/internal/tui"
	"github.com/ljkx/tor-relay-setup/internal/update"
)

// version is set at build time with -ldflags "-X main.version=v3.0.0".
var version = "dev"

// exitUpdateAvailable is the exit code of `self-update --check` when a
// newer release exists.
const exitUpdateAvailable = 10

const usage = `tor-relay-setup — set up and operate a public Tor relay

Usage:
  tor-relay-setup [flags]                   console on a configured relay, otherwise the setup wizard
  tor-relay-setup setup [flags]             run the setup wizard
  tor-relay-setup apply --config FILE       apply a saved relay.toml (add --yes to skip the confirmation)
  tor-relay-setup apply --config FILE --host [user@]HOST [--host ...] [--keep-going]
                                            apply it to remote relays over ssh, one after another
  tor-relay-setup apply --inventory FILE [--parallel N] [--only HOST[,HOST]] [--keep-going]
                                            apply a fleet inventory (fleet.toml) over ssh
  tor-relay-setup fleet [--inventory FILE]  fleet dashboard (plain status without a terminal)
  tor-relay-setup fleet status [--format text|json|prometheus]
                                            fleet status once; text and json exit 1 when something
                                            needs attention
  tor-relay-setup fleet restart|reload|update-tor [--only HOST[,HOST]] [--yes] [--keep-going]
                                            one relay at a time, waiting until each is back
  tor-relay-setup tor restart|reload|update [--yes]
                                            restart and verify, reload, or upgrade tor on this relay
  tor-relay-setup console                   open the operator console
  tor-relay-setup status [--json]           print relay health (exit code 1 when something needs attention)
  tor-relay-setup status --format text|json|prometheus
                                            prometheus: node_exporter metrics; always exits 0
  tor-relay-setup status --all              every relay instance on this server (json: an array)
  tor-relay-setup alert run|test|install|uninstall
                                            notify about problems (ntfy, webhook, email, command);
                                            install adds a systemd timer (see alert --help)
  tor-relay-setup proof [--instance NAME|--all] [--check]
                                            ContactInfo (CIISS) proof files to publish on your website;
                                            --check fetches the published copies over HTTPS
  tor-relay-setup keys status|offline|renew [--instance NAME]
                                            ed25519 identity keys: signing key expiry, offline master key
  tor-relay-setup keys offline [--remove-master]
                                            set OfflineMasterKey 1 and export the master key; then remove
                                            it from the server once you typed the SHA-256 of your copy
  tor-relay-setup keys renew [--master DIR | --from DIR] [--lifetime "30 days"]
                                            new signing key: from a master key in DIR, or install one made
                                            with tor --keygen elsewhere; without flags: how to renew offline
  tor-relay-setup uninstall [--yes]         remove this tool's state, logs and alert timer, then offer
                                            to remove the program itself (never Tor or its keys)
  tor-relay-setup self-update [--check]     install the newest release, verified like install.sh;
                                            --check only compares versions
  tor-relay-setup version

Flags:
  --dry-run        show every command and file change without making it (no root needed)
  --plain          plain line-by-line prompts and output (also used automatically without a terminal)
  --config FILE    prefill the wizard, or the file to apply
  --yes            apply without asking; uninstall: also remove the program without asking
  --json           same as --format json
  --format FORMAT  status output: text (default), json, or prometheus
  --host DEST      apply on [user@]host over ssh; repeat for several relays
  --keep-going     apply --host/--inventory, fleet actions: continue after a failure
  --inventory FILE fleet inventory for apply and fleet (fleet: default fleet.toml)
  --parallel N     apply --inventory: servers applied at once after the family host
  --only LIST      apply --inventory, fleet: only these hosts or nicknames (comma-separated)
  --check          self-update: only report whether a newer release exists;
                   proof: fetch the published proof files
  --instance NAME  the tor instance for status, console, setup, apply, tor, proof and keys
                   (overrides relay.instance); "default" is /etc/tor/torrc
  --all            status, proof: every relay instance on this server
  --remove-master  keys offline: remove the master key (asks for the SHA-256 of your copy)
  --master DIR     keys renew: directory with ed25519_master_id_secret_key (unencrypted)
  --from DIR       keys renew: directory with an uploaded signing key and certificate
  --lifetime TIME  keys renew --master: SigningKeyLifetime, e.g. "30 days" (tor's default)

Several relays on one server (Debian tor instances):
  Each extra relay is a tor instance: tor-instance-create NAME, /etc/tor/instances/NAME/torrc,
  unit tor@NAME. Set relay.instance = "NAME" in the config, or press n in the console.
  The directory authorities accept at most 8 relays per IPv4 address.

Remote apply (--host):
  Uses your ssh and scp, so ~/.ssh/config, keys and known_hosts apply. Each host gets this
  binary (same CPU architecture) and the config in a private temporary directory that is
  removed afterwards. The remote user must be root or have passwordless sudo. With
  family.mode = "generate", the first host creates the family key and every further host
  imports it, so the whole fleet is one family. --dry-run runs apply --dry-run remotely.

Fleets (--inventory, fleet):
  fleet.toml names a base relay.toml, a nickname template ({n}, {host}) and one [[host]] per
  relay; any relay.toml table can be overridden per host. Everything is validated before the
  first connection. ssh connections are shared per host for the run (ControlMaster). The
  dashboard and fleet status run tor-relay-setup fleet-probe on every host, so each host needs
  tor-relay-setup installed (install.sh); rolling actions run tor-relay-setup tor ... there.

Metrics (node_exporter textfile collector; run from cron or a systemd timer):
  tor-relay-setup status --format prometheus > /var/lib/prometheus/node-exporter/tor_relay.prom
  To avoid half-written scrapes, write to tor_relay.prom.tmp first and mv it into place.

Exit codes:
  0 success · 1 error, or status found a problem · 2 usage error
  10 self-update --check: a newer release is available · 130 stopped

Environment:
  NO_COLOR=1                          disable colour
  TOR_RELAY_SETUP_NO_UPDATE_CHECK=1   skip the console's daily check for a newer release
`

// Seams for tests.
var (
	newUpdater      = update.New
	newFleet        = remote.New
	executable      = os.Executable
	stdinIsTerminal = isTerminal
	isInteractive   = tui.Interactive
)

// hostList collects repeated --host flags.
type hostList []string

func (h *hostList) String() string { return strings.Join(*h, ",") }

func (h *hostList) Set(v string) error {
	if err := remote.ValidHost(v); err != nil {
		return err
	}
	*h = append(*h, v)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if sub, ok := alertArgs(args); ok {
		return alertCmd(sub, stdout, stderr) // alert.go
	}
	fs := flag.NewFlagSet("tor-relay-setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	dryRun := fs.Bool("dry-run", false, "")
	plain := fs.Bool("plain", false, "")
	cfgPath := fs.String("config", "", "")
	yes := fs.Bool("yes", false, "")
	asJSON := fs.Bool("json", false, "")
	format := fs.String("format", "", "")
	var hosts hostList
	fs.Var(&hosts, "host", "")
	keepGoing := fs.Bool("keep-going", false, "")
	inventory := fs.String("inventory", "", "")
	parallel := fs.Int("parallel", 0, "")
	only := fs.String("only", "", "")
	check := fs.Bool("check", false, "")
	instanceName := fs.String("instance", "", "")
	all := fs.Bool("all", false, "")
	removeMaster := fs.Bool("remove-master", false, "")
	masterDir := fs.String("master", "", "")
	fromDir := fs.String("from", "", "")
	lifetime := fs.String("lifetime", "", "")
	help := fs.Bool("help", false, "")
	fs.BoolVar(help, "h", false, "")
	showVersion := fs.Bool("version", false, "")
	// Flags may come before or after the command: parse up to the first
	// positional argument (the command), then parse what follows it. The
	// tor and fleet commands take one subcommand the same way.
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cmd, sub := "", ""
	if fs.NArg() > 0 {
		cmd = fs.Arg(0)
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
	}
	if (cmd == "tor" || cmd == "fleet" || cmd == "keys") && fs.NArg() > 0 {
		sub = fs.Arg(0)
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
	}
	if *help || cmd == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if *showVersion || cmd == "version" {
		fmt.Fprintf(stdout, "tor-relay-setup %s\n", buildVersion())
		return 0
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n\n%s", fs.Arg(0), usage)
		return 2
	}
	outFormat, err := statusFormat(*format, *asJSON)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	_, rolling := remote.ParseAction(sub)
	remoteApply := cmd == "apply" && (len(hosts) > 0 || *inventory != "")
	if msg := checkFlagUse(cmd, sub, flagUse{
		hosts: len(hosts) > 0, inventory: *inventory != "", config: *cfgPath != "", parallel: *parallel,
		only: *only != "", keepGoing: *keepGoing, remoteApply: remoteApply, rolling: rolling,
		instance: *instanceName != "", all: *all, check: *check,
		removeMaster: *removeMaster, renewFlags: *masterDir != "" || *fromDir != "" || *lifetime != "",
	}); msg != "" {
		fmt.Fprintln(stderr, msg)
		return 2
	}
	if *instanceName != "" {
		if _, err := relay.Named(*instanceName); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}

	local := host.NewLocal()
	// TOR_RELAY_SETUP_ROOT reads files from a fixture tree instead of /, for
	// demos and end-to-end tests. It is refused outside dry runs so it can
	// never redirect real changes.
	if root := os.Getenv("TOR_RELAY_SETUP_ROOT"); root != "" {
		if !*dryRun {
			fmt.Fprintln(stderr, "TOR_RELAY_SETUP_ROOT is only allowed together with --dry-run")
			return 2
		}
		local.Root = root
	}
	// TOR_RELAY_SETUP_ONIONOO_URL points Tor Metrics lookups at a stand-in
	// server (docs/demo/fakerelay); like the fixture root, dry runs only.
	var dir onionoo.Client
	if u := os.Getenv("TOR_RELAY_SETUP_ONIONOO_URL"); u != "" {
		if !*dryRun {
			fmt.Fprintln(stderr, "TOR_RELAY_SETUP_ONIONOO_URL is only allowed together with --dry-run")
			return 2
		}
		dir.Base = u
	}
	var h host.Host = local
	if *dryRun {
		h = host.NewDryRun(local)
	}
	opt := tui.Options{
		Host: h, Version: buildVersion(), DryRun: *dryRun, ConfigPath: "relay.toml", Onionoo: dir,
		// The console's "update available" hint asks the GitHub API at most
		// once a day; dry runs and TOR_RELAY_SETUP_NO_UPDATE_CHECK skip it.
		UpdateCheck: !*dryRun && os.Getenv("TOR_RELAY_SETUP_NO_UPDATE_CHECK") == "",
		Instance:    *instanceName,
	}
	interactive := !*plain && isInteractive()

	// A remote apply and the fleet commands need no local root: the remote
	// side uses sudo.
	keysChange := cmd == "keys" && (sub == "offline" || (sub == "renew" && (*masterDir != "" || *fromDir != "")))
	localChange := cmd == "" || cmd == "setup" || (cmd == "apply" && !remoteApply) || cmd == "console" || cmd == "uninstall" || cmd == "tor" || keysChange
	if !*dryRun && os.Geteuid() != 0 && localChange {
		fmt.Fprintln(stderr, "tor-relay-setup changes system configuration and must run as root.")
		fmt.Fprintln(stderr, "Try: sudo tor-relay-setup   (or add --dry-run to look around without root)")
		return 1
	}

	switch cmd {
	case "":
		if relayConfigured(h) {
			err = console(opt, interactive, stdout)
		} else {
			err = setup(opt, *cfgPath, interactive, stdin, stdout)
		}
	case "setup":
		err = setup(opt, *cfgPath, interactive, stdin, stdout)
	case "apply":
		if *inventory != "" {
			var inv fleet.Inventory
			if inv, err = loadInventory(*inventory, *only); err == nil {
				err = applyRemote(remote.Options{Inventory: &inv, DryRun: *dryRun, KeepGoing: *keepGoing, Parallel: *parallel}, stdout)
			}
			break
		}
		if *cfgPath == "" {
			fmt.Fprintln(stderr, "apply needs --config FILE (or --inventory FILE)")
			return 2
		}
		if remoteApply {
			opt := remote.Options{ConfigPath: *cfgPath, Hosts: hosts, DryRun: *dryRun, KeepGoing: *keepGoing, Parallel: *parallel}
			if *only != "" {
				var inv fleet.Inventory
				if inv, err = fleet.FromHosts(*cfgPath, hosts); err == nil {
					inv, err = inv.Only(splitList(*only))
				}
				if err != nil {
					break
				}
				opt.Inventory = &inv
			}
			err = applyRemote(opt, stdout)
			break
		}
		var s config.Setup
		if s, err = config.Load(*cfgPath); err == nil {
			if *instanceName != "" {
				s.Relay.Instance = *instanceName
			}
			err = tui.RunApplyPlain(opt, s, system.Facts{}, *yes, stdin, stdout)
		}
	case "console":
		err = console(opt, interactive, stdout)
	case "status":
		return statusCmd(h, opt.Onionoo, statusRequest{Format: outFormat, Instance: *instanceName, All: *all}, stdout)
	case "fleet-probe":
		return fleetProbe(h, stdout)
	case "tor":
		inst, _ := relay.Named(*instanceName) // validated above; "" is the default
		err = torCmd(h, sub, torOptions{Yes: *yes, Terminal: stdinIsTerminal(stdin), In: stdin, Out: stdout, Instance: inst})
	case "fleet":
		return fleetCmd(fleetOptions{
			Sub: sub, Inventory: *inventory, Only: *only, Format: outFormat, FormatSet: *format != "" || *asJSON,
			Yes: *yes, DryRun: *dryRun, KeepGoing: *keepGoing, Interactive: interactive,
			Terminal: stdinIsTerminal(stdin), In: stdin, Out: stdout, Err: stderr,
			Onionoo: dir, Local: h, Version: buildVersion(),
		})
	case "proof":
		err = proofCmd(h, proofRequest{Instance: *instanceName, All: *all, Check: *check}, stdout)
	case "keys":
		if *dryRun {
			local.Observe = func(e host.Event) {
				if e.Dry {
					fmt.Fprintln(stdout, "  would: "+e.Text)
				}
			}
		}
		err = keysCmd(h, keysRequest{
			Action: sub, Instance: *instanceName, RemoveMaster: *removeMaster,
			Master: *masterDir, From: *fromDir, Lifetime: *lifetime, In: stdin, Out: stdout,
		})
	case "uninstall":
		err = uninstall(context.Background(), h, uninstallOptions{Yes: *yes, Terminal: stdinIsTerminal(stdin), In: stdin, Out: stdout})
	case "self-update":
		return selfUpdate(*check, *dryRun, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, tui.ErrAborted):
		fmt.Fprintln(stderr, "Stopped. Nothing further was changed.")
		return 130
	default:
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
}

func setup(opt tui.Options, cfgPath string, interactive bool, stdin io.Reader, stdout io.Writer) error {
	if cfgPath != "" {
		s, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		opt.Prefill = &s
		opt.ConfigPath = cfgPath
	}
	if opt.Instance != "" {
		// --instance: start from that instance's torrc (or sensible
		// defaults for a new one) unless --config gave the answers.
		s := tui.InstancePrefill(opt.Host, opt.Instance)
		if opt.Prefill != nil {
			s = *opt.Prefill
			s.Relay.Instance = opt.Instance
		}
		opt.Prefill = &s
	}
	if interactive {
		return tui.RunSetup(opt)
	}
	return tui.RunSetupPlain(opt, stdin, stdout)
}

func console(opt tui.Options, interactive bool, stdout io.Writer) error {
	if interactive {
		return tui.RunConsole(opt)
	}
	req := statusRequest{Format: "text", Instance: opt.Instance, All: opt.Instance == ""}
	if code := statusCmd(opt.Host, opt.Onionoo, req, stdout); code != 0 {
		return errors.New("the relay needs attention")
	}
	return nil
}

// relayConfigured reports whether any tor instance on this host is a relay.
func relayConfigured(h host.Host) bool {
	list, _ := relay.Discover(h)
	return len(list) > 0
}

// statusRequest is what `status` was asked for.
type statusRequest struct {
	Format   string // text, json or prometheus
	Instance string // --instance; "" picks the default (or only) relay
	All      bool   // --all: every relay instance
}

// statusInstances resolves which instances a status request covers.
// Without --instance or --all it is the default instance when it is a relay,
// else the first relay instance found, else the default instance (which
// then reports "not configured").
func statusInstances(h host.Host, req statusRequest) []relay.Instance {
	if req.Instance != "" {
		inst, _ := relay.Named(req.Instance)
		return []relay.Instance{inst}
	}
	found, _ := relay.Discover(h)
	switch {
	case len(found) == 0:
		return []relay.Instance{relay.DefaultInstance()}
	case req.All:
		return found
	}
	if inst, ok := relay.Find(found, relay.DefaultInstanceName); ok {
		return []relay.Instance{inst}
	}
	return found[:1]
}

// collectReports gathers one report per instance concurrently, each with
// its Tor Metrics lookup.
// loadMetrics adds tor's load counters (one MetricsPort scrape per running
// relay), the accounting budget and Relay Search's overload mark to the
// Prometheus output. Overload gauges that need two samples are left to
// Prometheus (increase() over the *_total series) and to alert.
func loadMetrics(ctx context.Context, h host.Host, insts []relay.Instance, reports []status.Report) []status.LoadMetrics {
	out := make([]status.LoadMetrics, len(reports))
	for i, r := range reports {
		m := status.LoadMetrics{Instance: r.Instance, MetricsPort: r.Relay.MetricsPort != "", Directory: r.Directory}
		if m.MetricsPort && r.Service.Active {
			if s, err := metrics.Scrape(ctx, nil, r.Relay.MetricsPort); err == nil {
				m.Sample = &s
			}
		}
		if i < len(insts) {
			inst := insts[i].OrDefault()
			if data, err := h.ReadFile(inst.TorrcPath); err == nil {
				m.Accounting, _ = alert.AccountingIn(h, relay.ParseDocument(data), inst.DataDir, time.Now())
			}
		}
		out[i] = m
	}
	return out
}

func collectReports(ctx context.Context, h host.Host, dir onionoo.Client, instances []relay.Instance) []status.Report {
	reports := make([]status.Report, len(instances))
	var wg sync.WaitGroup
	for i, inst := range instances {
		wg.Go(func() {
			r := status.Collect(ctx, h, status.Options{Instance: inst})
			switch {
			case r.Relay.Fingerprint != "" && r.Relay.Bridge:
				// By hashed fingerprint only: a bridge's own never leaves the host.
				b, err := status.BridgeDirectory(ctx, dir, r.Relay.Fingerprint)
				r.BridgeDirectory = b
				if err != nil {
					r.DirectoryError = err.Error()
				}
			case r.Relay.Fingerprint != "":
				d, err := status.Directory(ctx, dir, r.Relay.Fingerprint)
				r.Directory = d
				if err != nil {
					r.DirectoryError = err.Error()
				}
			}
			reports[i] = r
		})
	}
	wg.Wait()
	return reports
}

// statusFormat resolves --format and its --json shorthand.
func statusFormat(format string, asJSON bool) (string, error) {
	switch {
	case asJSON && format != "" && format != "json":
		return "", fmt.Errorf("--json conflicts with --format %s", format)
	case asJSON:
		return "json", nil
	case format == "":
		return "text", nil
	case format == "text", format == "json", format == "prometheus":
		return format, nil
	}
	return "", fmt.Errorf("unknown --format %q: use text, json, or prometheus", format)
}

// statusCmd prints the reports. Text and JSON exit 1 when any relay needs
// attention; Prometheus output always exits 0 (the warnings gauge carries
// it) so that `status --format prometheus > f.tmp && mv f.tmp f` works.
//
// JSON is one Report object, or with --all an array of Reports (one per
// relay instance, each naming its "instance"), even when there is only one.
func statusCmd(h host.Host, dir onionoo.Client, req statusRequest, stdout io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	insts := statusInstances(h, req)
	reports := collectReports(ctx, h, dir, insts)
	switch req.Format {
	case "prometheus":
		if err := status.WritePrometheusAll(stdout, reports); err != nil {
			return 1
		}
		if err := status.WriteLoadPrometheusAll(stdout, loadMetrics(ctx, h, insts, reports)); err != nil {
			return 1
		}
		return 0
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if req.All {
			_ = enc.Encode(reports)
		} else {
			_ = enc.Encode(reports[0])
		}
	default:
		for i, r := range reports {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			printStatus(stdout, r, len(reports) > 1)
		}
	}
	for _, r := range reports {
		if !r.Healthy() {
			return 1
		}
	}
	return 0
}

func applyRemote(opt remote.Options, stdout io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	f := newFleet(stdout)
	defer f.Close()
	_, err := f.Apply(ctx, opt)
	return err
}

// flagUse is what checkFlagUse needs to know about the command line.
type flagUse struct {
	hosts, inventory, config, only, keepGoing bool
	parallel                                  int
	remoteApply, rolling                      bool
	instance, all, check                      bool
	removeMaster, renewFlags                  bool // keys offline / keys renew flags
}

// checkFlagUse rejects flags and subcommands that do not fit the command.
func checkFlagUse(cmd, sub string, u flagUse) string {
	switch {
	case u.hosts && cmd != "apply":
		return "--host is only used with apply"
	case u.inventory && cmd != "apply" && cmd != "fleet":
		return "--inventory is only used with apply and fleet"
	case u.inventory && u.hosts:
		return "use either --inventory or --host"
	case u.inventory && u.config && cmd == "apply":
		return "--config is not used with --inventory: the inventory names its base relay.toml"
	case u.parallel != 0 && !u.remoteApply:
		return "--parallel needs apply --inventory or --host"
	case u.parallel < 0 || u.parallel > 64:
		return "--parallel must be 1–64"
	case u.only && !u.remoteApply && cmd != "fleet":
		return "--only needs apply --inventory, apply --host, or fleet"
	case u.keepGoing && !u.remoteApply && !u.rolling:
		return "--keep-going needs --host, --inventory, or a rolling fleet action"
	case cmd == "fleet" && sub != "" && sub != "status" && !u.rolling:
		return fmt.Sprintf("unknown fleet command %q: use status, restart, reload, or update-tor", sub)
	case cmd == "tor" && sub != "restart" && sub != "reload" && sub != "update":
		return "tor needs restart, reload, or update"
	case cmd == "keys" && sub != "" && sub != "status" && sub != "offline" && sub != "renew":
		return fmt.Sprintf("unknown keys action %q: use status, offline or renew", sub)
	case (u.removeMaster || u.renewFlags) && cmd != "keys":
		return "--remove-master, --master, --from and --lifetime are only used with keys"
	case u.removeMaster && sub != "offline":
		return "--remove-master is only used with keys offline"
	case u.renewFlags && sub != "renew":
		return "--master, --from and --lifetime are only used with keys renew"
	case u.check && cmd != "self-update" && cmd != "proof":
		return "--check is only used with self-update and proof"
	case u.all && cmd != "status" && cmd != "proof":
		return "--all is only used with status and proof"
	case u.all && u.instance:
		return "--all conflicts with --instance"
	case u.instance && !slices.Contains([]string{"", "status", "console", "setup", "apply", "tor", "proof", "keys"}, cmd):
		return "--instance is only used with status, console, setup, apply, tor, proof and keys"
	case u.instance && u.remoteApply:
		return "--instance cannot be combined with --host or --inventory; set relay.instance in the config instead"
	}
	return ""
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// loadInventory reads an inventory and applies --only.
func loadInventory(path, only string) (fleet.Inventory, error) {
	inv, err := fleet.Load(path)
	if err != nil {
		return fleet.Inventory{}, err
	}
	return inv.Only(splitList(only))
}

func selfUpdate(check, dryRun bool, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	u := newUpdater(buildVersion(), stdout, dryRun)
	if !check {
		if err := u.Update(ctx); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	}
	res, err := u.Check(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	current := res.Current
	if !res.Known {
		current += " (not a release build; the version is unknown)"
	}
	fmt.Fprintf(stdout, "current  %s\nlatest   %s\n", current, res.Latest)
	switch {
	case !res.Available:
		fmt.Fprintln(stdout, "Up to date.")
		return 0
	case res.Known:
		fmt.Fprintln(stdout, "An update is available: sudo tor-relay-setup self-update")
	default:
		fmt.Fprintln(stdout, "The latest release may be newer: sudo tor-relay-setup self-update")
	}
	return exitUpdateAvailable
}

// printStatus prints one report. The Instance line appears when several
// instances are printed, or for a named instance; a single default relay
// looks exactly as it always did.
func printStatus(w io.Writer, r status.Report, several bool) {
	mark := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	inst, _ := relay.Named(r.Instance)
	if several || !inst.IsDefault() {
		fmt.Fprintf(w, "Instance     %s (%s)\n", inst.Name, inst.TorrcPath)
	}
	if !r.Relay.Configured {
		fmt.Fprintf(w, "No relay is configured in %s. Run: sudo tor-relay-setup\n", inst.TorrcPath)
		return
	}
	kind := map[bool]string{true: "exit", false: "guard/middle"}[r.Relay.Exit]
	if r.Bridge != nil {
		kind = "bridge, " + r.Bridge.Transport
	}
	fmt.Fprintf(w, "Relay        %s (%s)\n", r.Relay.Nickname, kind)
	if r.Relay.Fingerprint != "" {
		fmt.Fprintf(w, "Fingerprint  %s\n", r.Relay.Fingerprint)
	}
	fmt.Fprintf(w, "tor          %s %s\n", mark(r.Tor.Supported), r.Tor.Version)
	fmt.Fprintf(w, "Service      %s %s\n", mark(r.Service.Active), r.Service.Unit)
	if r.Relay.ORPort > 0 {
		fmt.Fprintf(w, "Listener     %s TCP %d\n", mark(r.Listener.IPv4 || r.Listener.IPv6), r.Relay.ORPort)
	}
	if b := r.Bridge; b != nil {
		fmt.Fprintf(w, "Transport    %s %s on port %d · distribution %s\n", mark(b.Listening), b.Transport, b.Port, b.Distribution)
		if b.Line != "" {
			fmt.Fprintf(w, "Bridge line  %s\n", b.Line)
		}
	}
	if k := r.Keys; k != nil && k.Managed() && !k.CertExpires.IsZero() {
		fmt.Fprintf(w, "Signing key  %s valid until %s (offline master key)\n", mark(k.CertExpires.After(time.Now())), k.CertExpires.Format("2006-01-02 15:04 UTC"))
	}
	reach := "no self-test notice in the last 24 h"
	if r.Reachability.IPv4 {
		reach = "reachable from outside"
	} else if r.Reachability.Failed {
		reach = "NOT reachable from outside"
	}
	fmt.Fprintf(w, "Reachability %s %s\n", mark(r.Reachability.IPv4), reach)
	if len(r.Family.IDs) > 0 {
		fmt.Fprintf(w, "Family       %s\n", strings.Join(r.Family.IDs, ", "))
	}
	switch {
	case r.BridgeDirectory != nil:
		d := r.BridgeDirectory
		fmt.Fprintf(w, "Tor Metrics  %s running=%v flags=%s distributor=%s\n", mark(d.Running), d.Running, strings.Join(d.Flags, ","), orNone(d.Distributor))
	case r.Directory != nil:
		fmt.Fprintf(w, "Tor Metrics  %s running=%v flags=%s\n", mark(r.Directory.Running), r.Directory.Running, strings.Join(r.Directory.Flags, ","))
	case r.DirectoryError != "":
		fmt.Fprintf(w, "Tor Metrics  ? %s\n", r.DirectoryError)
	case r.Relay.Fingerprint != "":
		fmt.Fprintln(w, "Tor Metrics  not published yet")
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "! %s\n", warn)
	}
}

type uninstallOptions struct {
	Yes      bool // remove the program without asking
	Terminal bool // In is a terminal, so asking is possible
	In       io.Reader
	Out      io.Writer
}

func uninstall(ctx context.Context, h host.Host, opt uninstallOptions) error {
	stdout := opt.Out
	// The alert timer runs this program; remove it before the program goes.
	if _, err := h.Stat(alert.TimerPath); err == nil {
		if err := alert.Uninstall(ctx, h, stdout); err != nil {
			return err
		}
	}
	for _, p := range []string{"/var/lib/tor-relay-setup", "/var/log/tor-relay-setup"} {
		if _, err := h.Stat(p); err != nil {
			continue
		}
		if err := h.Remove(p); err != nil {
			return err
		}
		if h.DryRun() {
			fmt.Fprintln(stdout, "would remove", p)
		} else {
			fmt.Fprintln(stdout, "removed", p)
		}
	}
	fmt.Fprintln(stdout, "Tor, torrc, keys, and firewall rules were left alone.")
	return removeProgram(ctx, h, opt)
}

// removeProgram deletes the running binary after the state is gone, unless
// the Debian package owns it.
func removeProgram(ctx context.Context, h host.Host, opt uninstallOptions) error {
	exe, err := executable()
	if err != nil {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	exe = filepath.Clean(exe)
	if update.OwnedByPackage(ctx, h.Run, exe) {
		fmt.Fprintln(opt.Out, "This program was installed from the .deb package; remove it with: sudo apt remove tor-relay-setup")
		return nil
	}
	switch {
	case h.DryRun():
		fmt.Fprintln(opt.Out, "would remove", exe)
		return nil
	case opt.Yes:
	case opt.Terminal:
		fmt.Fprintf(opt.Out, "Remove %s too? [y/N] ", exe)
		answer, _ := bufio.NewReader(opt.In).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Fprintf(opt.Out, "Kept %s.\n", exe)
			return nil
		}
	default:
		fmt.Fprintf(opt.Out, "To remove this program too: sudo rm %s\n", exe)
		return nil
	}
	if err := h.Remove(exe); err != nil {
		return err
	}
	fmt.Fprintln(opt.Out, "removed", exe)
	return nil
}

// isTerminal reports whether r is a terminal device.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
