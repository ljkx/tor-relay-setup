// Command tor-relay-setup sets up and operates public Tor relays on Debian
// and Ubuntu: a guided wizard, a declarative apply mode, an operator console,
// and a machine-readable status report.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
	"github.com/ljkx/tor-relay-setup/internal/system"
	"github.com/ljkx/tor-relay-setup/internal/tui"
)

// version is set at build time with -ldflags "-X main.version=v3.0.0".
var version = "dev"

const usage = `tor-relay-setup — set up and operate a public Tor relay

Usage:
  tor-relay-setup [flags]                   console on a configured relay, otherwise the setup wizard
  tor-relay-setup setup [flags]             run the setup wizard
  tor-relay-setup apply --config FILE       apply a saved relay.toml (add --yes to skip the confirmation)
  tor-relay-setup console                   open the operator console
  tor-relay-setup status [--json]           print relay health (exit code 1 when something needs attention)
  tor-relay-setup uninstall                 remove this tool's state and logs (never Tor or its keys)
  tor-relay-setup version

Flags:
  --dry-run        show every command and file change without making it (no root needed)
  --plain          plain line-by-line prompts and output (also used automatically without a terminal)
  --config FILE    prefill the wizard, or the file to apply
  --yes            apply without asking (apply only)
  --json           machine-readable output (status only)

Environment: NO_COLOR disables colour.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tor-relay-setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	dryRun := fs.Bool("dry-run", false, "")
	plain := fs.Bool("plain", false, "")
	cfgPath := fs.String("config", "", "")
	yes := fs.Bool("yes", false, "")
	asJSON := fs.Bool("json", false, "")
	help := fs.Bool("help", false, "")
	fs.BoolVar(help, "h", false, "")
	showVersion := fs.Bool("version", false, "")
	// Flags may come before or after the command: parse up to the first
	// positional argument (the command), then parse what follows it.
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cmd := ""
	if fs.NArg() > 0 {
		cmd = fs.Arg(0)
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
	var h host.Host = local
	if *dryRun {
		h = host.NewDryRun(local)
	}
	opt := tui.Options{Host: h, Version: buildVersion(), DryRun: *dryRun, ConfigPath: "relay.toml"}
	interactive := !*plain && tui.Interactive()

	if !*dryRun && os.Geteuid() != 0 && (cmd == "" || cmd == "setup" || cmd == "apply" || cmd == "console" || cmd == "uninstall") {
		fmt.Fprintln(stderr, "tor-relay-setup changes system configuration and must run as root.")
		fmt.Fprintln(stderr, "Try: sudo tor-relay-setup   (or add --dry-run to look around without root)")
		return 1
	}

	var err error
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
		if *cfgPath == "" {
			fmt.Fprintln(stderr, "apply needs --config FILE")
			return 2
		}
		var s config.Setup
		if s, err = config.Load(*cfgPath); err == nil {
			err = tui.RunApplyPlain(opt, s, system.Facts{}, *yes, stdin, stdout)
		}
	case "console":
		err = console(opt, interactive, stdout)
	case "status":
		return statusCmd(h, *asJSON, stdout)
	case "uninstall":
		err = uninstall(h, stdout)
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
	if interactive {
		return tui.RunSetup(opt)
	}
	return tui.RunSetupPlain(opt, stdin, stdout)
}

func console(opt tui.Options, interactive bool, stdout io.Writer) error {
	if interactive {
		return tui.RunConsole(opt)
	}
	if code := statusCmd(opt.Host, false, stdout); code != 0 {
		return errors.New("the relay needs attention")
	}
	return nil
}

func relayConfigured(h host.Host) bool {
	data, err := h.ReadFile("/etc/tor/torrc")
	return err == nil && len(relay.ParseDocument(data).ORPorts()) > 0
}

func statusCmd(h host.Host, asJSON bool, stdout io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r := status.Collect(ctx, h, status.Options{})
	if r.Relay.Fingerprint != "" {
		d, err := status.Directory(ctx, onionoo.Client{}, r.Relay.Fingerprint)
		r.Directory = d
		if err != nil {
			r.DirectoryError = err.Error()
		}
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		printStatus(stdout, r)
	}
	if !r.Healthy() {
		return 1
	}
	return 0
}

func printStatus(w io.Writer, r status.Report) {
	mark := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	if !r.Relay.Configured {
		fmt.Fprintln(w, "No relay is configured in /etc/tor/torrc. Run: sudo tor-relay-setup")
		return
	}
	fmt.Fprintf(w, "Relay        %s (%s)\n", r.Relay.Nickname, map[bool]string{true: "exit", false: "guard/middle"}[r.Relay.Exit])
	if r.Relay.Fingerprint != "" {
		fmt.Fprintf(w, "Fingerprint  %s\n", r.Relay.Fingerprint)
	}
	fmt.Fprintf(w, "tor          %s %s\n", mark(r.Tor.Supported), r.Tor.Version)
	fmt.Fprintf(w, "Service      %s %s\n", mark(r.Service.Active), r.Service.Unit)
	fmt.Fprintf(w, "Listener     %s TCP %d\n", mark(r.Listener.IPv4 || r.Listener.IPv6), r.Relay.ORPort)
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

func uninstall(h host.Host, stdout io.Writer) error {
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
	if exe, err := os.Executable(); err == nil {
		fmt.Fprintf(stdout, "Tor, torrc, keys, and firewall rules were left alone.\nTo remove this program too: sudo rm %s\n", filepath.Clean(exe))
	}
	return nil
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
