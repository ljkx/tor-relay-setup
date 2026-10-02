package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/term"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/serve"
)

// demoProbeInterval keeps the demo's graphs lively when serve.toml does
// not set probe_interval.
const demoProbeInterval = 10 * time.Second

// Seams for tests.
var (
	readPassword = readTerminalPassword
	serveRun     = serve.Run
)

type serveOptions struct {
	Action     string // "", "passwd" or "token"
	User       string // passwd: the account
	ConfigPath string // --config; empty means serve.DefaultConfig
	Inventory  string // --inventory overrides serve.toml's
	Demo       bool
	Stdin      bool // passwd: read the password from standard input
	Terminal   bool // standard input is a terminal
	In         io.Reader
	Out, Err   io.Writer
	Onionoo    onionoo.Client
	Local      host.Host
	Version    string
}

// fleetServeCmd is `fleet serve`, `fleet serve passwd USER` and
// `fleet serve token`.
func fleetServeCmd(o serveOptions) int {
	path := o.ConfigPath
	if path == "" {
		path = serve.DefaultConfig
	}
	var err error
	switch o.Action {
	case "passwd":
		err = servePasswd(o, path)
	case "token":
		err = serveToken(o, path)
	default:
		err = fleetServe(o, path)
	}
	if err != nil {
		fmt.Fprintln(o.Err, "error:", err)
		return 1
	}
	return 0
}

// servePasswd sets a web UI password: typed twice without echo, or one
// line from standard input with --stdin.
func servePasswd(o serveOptions, path string) error {
	if !serve.ValidUserName(o.User) {
		return fmt.Errorf("user name %q: use 1-64 letters, digits, '.', '_' or '-'", o.User)
	}
	var password string
	if o.Stdin {
		line, err := bufio.NewReader(o.In).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		password = strings.TrimRight(line, "\r\n")
	} else {
		if !o.Terminal {
			return errors.New("fleet serve passwd reads the password from a terminal; to pipe it in, add --stdin")
		}
		first, err := readPassword(fmt.Sprintf("New password for %s: ", o.User))
		if err != nil {
			return err
		}
		if err := serve.CheckPassword(string(first)); err != nil {
			return err
		}
		second, err := readPassword("Repeat the password: ")
		if err != nil {
			return err
		}
		if string(first) != string(second) {
			return errors.New("the passwords differ; nothing was changed")
		}
		password = string(first)
	}
	hash, err := serve.HashPassword(password)
	if err != nil {
		return err
	}
	data, err := serve.ReadConfigFile(o.Local, path)
	if err != nil {
		return err
	}
	if data, err = serve.SetUser(data, o.User, hash); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := serve.WriteConfig(o.Local, path, data); err != nil {
		return err
	}
	verb := "Saved"
	if o.Local.DryRun() {
		verb = "Would save"
	}
	fmt.Fprintf(o.Out, "%s the password of %s in %s (argon2id). Restart fleet serve to use it.\n", verb, o.User, path)
	return nil
}

// serveToken makes a new metrics token, prints it once, and stores only
// its SHA-256.
func serveToken(o serveOptions, path string) error {
	token, sum, err := serve.NewToken()
	if err != nil {
		return err
	}
	data, err := serve.ReadConfigFile(o.Local, path)
	if err != nil {
		return err
	}
	if data, err = serve.SetToken(data, sum); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := serve.WriteConfig(o.Local, path, data); err != nil {
		return err
	}
	if o.Local.DryRun() {
		fmt.Fprintf(o.Err, "Dry run: %s was not changed, so this token would not work.\n", path)
	}
	fmt.Fprintln(o.Out, token)
	fmt.Fprintf(o.Err, "Stored the token's SHA-256 in %s; the token itself is shown only now.\n"+
		"Give it to Prometheus (authorization: { type: Bearer, credentials: TOKEN }) and restart fleet serve.\n", path)
	return nil
}

// fleetServe runs the service until SIGTERM or Ctrl-C.
func fleetServe(o serveOptions, path string) error {
	cfg := serve.Defaults()
	explicit := o.ConfigPath != ""
	if !o.Demo || explicit {
		var err error
		cfg, err = serve.Load(o.Local, path)
		switch {
		case errors.Is(err, fs.ErrNotExist) && !explicit:
			return fmt.Errorf("no %s: create it (see docs/examples/serve.toml) or pass --config FILE; fleet serve --demo shows a synthetic fleet", path)
		case err != nil:
			return err
		}
	}
	if o.Inventory != "" {
		cfg.Inventory = o.Inventory
	}
	log := slog.New(slog.NewTextHandler(o.Err, nil))

	var (
		src       serve.Source
		inv       fleet.Inventory
		cachePath string
		demoLogin bool
	)
	if o.Demo {
		d := serve.NewDemo(serve.DemoSeed, nil)
		d.Latency = true
		src, inv = d, d.Inventory()
		if cfg.Path == "" {
			cfg.ProbeInterval.Duration = demoProbeInterval
		}
		var err error
		if demoLogin, err = serve.UseDemoCredentials(&cfg); err != nil {
			return err
		}
		if demoLogin {
			log.Info("demo mode: sign in as the documented demo user; /metrics takes the documented demo token", "user", serve.DemoUser)
		}
	} else {
		if cfg.Inventory == "" {
			return fmt.Errorf("no inventory: set inventory in %s or pass --inventory FILE", path)
		}
		var err error
		if inv, err = fleet.Load(cfg.Inventory); err != nil {
			return err
		}
		f := newFleet(io.Discard)
		defer f.Close()
		src = serve.NewLiveSource(f.Probe, o.Onionoo)
		if dir, err := cacheDir(); err == nil {
			cachePath = fleet.CachePath(dir, inv)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveRun(ctx, serve.Options{
		Config: cfg, Inventory: inv, Source: src, Host: o.Local, CachePath: cachePath, Log: log,
		Version: o.Version, Demo: o.Demo, DemoLogin: demoLogin,
	})
}

// readTerminalPassword prompts on standard error and reads a line from
// the terminal without echo.
func readTerminalPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(os.Stdin.Fd())
	fmt.Fprintln(os.Stderr)
	return b, err
}
