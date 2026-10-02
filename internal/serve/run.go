package serve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
)

// shutdownTimeout bounds a graceful shutdown.
const shutdownTimeout = 10 * time.Second

// Options configures Run.
type Options struct {
	Config    Config
	Inventory fleet.Inventory
	Source    Source
	// Host reads TLS files and writes the flag cache and ACME cache.
	Host      host.Host
	CachePath string
	Log       *slog.Logger
	Version   string
	Demo      bool
	DemoLogin bool
	// Listen opens the listener; net.Listen when nil (tests pass ":0").
	Listen func(network, address string) (net.Listener, error)
	// Ready, when set, receives the listening address once serving.
	Ready func(addr net.Addr)
}

// UseDemoCredentials fills in the documented demo user and token where
// serve.toml configures none. Only for --demo on a loopback listener; it
// reports whether the demo login is in use.
func UseDemoCredentials(c *Config) (bool, error) {
	if len(c.Users) > 0 && c.MetricsTokenSHA256 != "" {
		return false, nil
	}
	if !Loopback(c.Listen) {
		return false, errors.New("--demo on a non-loopback address needs its own users and metrics token in serve.toml " +
			"(tor-relay-setup fleet serve passwd USER, fleet serve token); the fixed demo credentials are for 127.0.0.1 only")
	}
	login := false
	if len(c.Users) == 0 {
		h, err := HashPassword(DemoPassword)
		if err != nil {
			return false, err
		}
		c.Users = []User{{Name: DemoUser, Hash: h}}
		login = true
	}
	if c.MetricsTokenSHA256 == "" {
		c.MetricsTokenSHA256 = TokenSum(DemoToken)
	}
	return login, nil
}

// Run serves until ctx ends, then shuts down gracefully.
func Run(ctx context.Context, o Options) error {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if err := o.Config.CheckListener(); err != nil {
		return err
	}
	if len(o.Config.Users) == 0 && o.Config.MetricsTokenSHA256 == "" && !o.Config.MetricsOpen() {
		return errors.New("nobody could log in: add a user (tor-relay-setup fleet serve passwd USER) or a metrics token (fleet serve token)")
	}
	tlsCfg, err := TLSConfig(o.Config, o.Host)
	if err != nil {
		return err
	}
	coll := NewCollector(CollectorOptions{
		Inventory: o.Inventory, Source: o.Source, Interval: o.Config.ProbeInterval.Duration, Log: o.Log,
		Cache: o.Host, CachePath: o.CachePath,
	})
	srv, err := NewServer(ServerOptions{Config: o.Config, Collector: coll, Log: o.Log, Version: o.Version, Demo: o.Demo, DemoLogin: o.DemoLogin})
	if err != nil {
		return err
	}
	listen := o.Listen
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", o.Config.Listen)
	if err != nil {
		return err
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	hs := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(o.Log.Handler(), slog.LevelWarn),
	}

	cctx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	wg.Go(func() { coll.Run(cctx) })
	errc := make(chan error, 1)
	wg.Go(func() { errc <- hs.Serve(ln) })

	scheme := "http"
	if tlsCfg != nil {
		scheme = "https"
	}
	o.Log.Info("serving", "url", fmt.Sprintf("%s://%s%s", scheme, ln.Addr(), o.Config.BasePath), "hosts", len(o.Inventory.Addresses()),
		"relays", len(o.Inventory.Entries), "probe_interval", o.Config.ProbeInterval.String(), "privacy", o.Config.Privacy, "demo", o.Demo)
	if o.Ready != nil {
		o.Ready(ln.Addr())
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	o.Log.Info("shutting down")
	stop()
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	shutErr := hs.Shutdown(sctx)
	wg.Wait()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return shutErr
}
