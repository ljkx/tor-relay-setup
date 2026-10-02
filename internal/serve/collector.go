package serve

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Source is where the fleet data comes from: ssh and Tor Metrics in
// production, a synthetic fleet in demo mode.
type Source interface {
	// Probe runs fleet-probe on one server.
	Probe(ctx context.Context, address string) fleet.HostProbe
	// Directory asks Tor Metrics about relays (fingerprints) and bridges
	// (hashed fingerprints), with traffic history.
	Directory(ctx context.Context, relays, bridges []string) fleet.DirectoryResult
}

// Collector timing.
const (
	// ProbeParallel bounds concurrent probes, like the dashboard.
	ProbeParallel = 16
	// DirectoryEvery is how often Tor Metrics is asked; it publishes hourly.
	DirectoryEvery = 30 * time.Minute
	// directoryRetry is the wait after a failed Tor Metrics lookup.
	directoryRetry   = 5 * time.Minute
	directoryTimeout = time.Minute
	// flagsRoll is how long a lost flag stays reported: the flags compared
	// against roll forward to the cached ones this often.
	flagsRoll = 24 * time.Hour
)

// Collector probes the fleet on a schedule and keeps the latest state in
// memory. All access to the model goes through View.
type Collector struct {
	src      Source
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time
	// cache keeps the flags Tor Metrics reported between runs (the
	// dashboard's flag cache); an empty cachePath keeps none.
	cache     host.Host
	cachePath string

	mu         sync.Mutex
	model      *fleet.Model
	dirRunning bool
	dirNext    time.Time
	flagsAt    time.Time
	wg         sync.WaitGroup
}

// CollectorOptions configures NewCollector.
type CollectorOptions struct {
	Inventory fleet.Inventory
	Source    Source
	Interval  time.Duration
	Log       *slog.Logger
	Now       func() time.Time
	Cache     host.Host
	CachePath string
}

// NewCollector starts with every host pending.
func NewCollector(o CollectorOptions) *Collector {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Interval <= 0 {
		o.Interval = DefaultProbeInterval
	}
	c := &Collector{src: o.Source, interval: o.Interval, log: o.Log, now: o.Now, cache: o.Cache, cachePath: o.CachePath,
		model: fleet.NewModel(o.Inventory)}
	if c.cache != nil && c.cachePath != "" {
		c.model.PrevFlags = fleet.LoadFlagCache(c.cache, c.cachePath)
		c.flagsAt = o.Now()
	}
	return c
}

// View runs f with the model locked; f must not keep it.
func (c *Collector) View(f func(m *fleet.Model)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c.model)
}

// Run probes every interval until ctx ends; a round that takes longer
// than the interval is followed by the next one right away.
func (c *Collector) Run(ctx context.Context) {
	defer c.wg.Wait()
	for {
		start := c.now()
		c.Round(ctx)
		c.maybeDirectory(ctx)
		wait := c.interval - c.now().Sub(start)
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Round probes every host once, at most ProbeParallel at a time, and
// applies each result as it arrives.
func (c *Collector) Round(ctx context.Context) {
	var addrs []string
	c.View(func(m *fleet.Model) {
		for _, h := range m.Hosts() {
			addrs = append(addrs, h.Address)
		}
	})
	start := c.now()
	sem := make(chan struct{}, ProbeParallel)
	var wg sync.WaitGroup
	for _, a := range addrs {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			hp := c.src.Probe(ctx, a)
			if ctx.Err() != nil {
				return
			}
			c.View(func(m *fleet.Model) { m.Apply(hp) })
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	end := c.now()
	var t fleet.Totals
	c.View(func(m *fleet.Model) {
		m.EndRound(start, end)
		t = m.Totals()
	})
	c.log.Info("probe round", "hosts", t.Hosts, "up", t.HostsUp, "unreachable", t.Unreachable, "without_probe", t.TooOld,
		"relays", t.Relays, "running", t.Running, "seconds", end.Sub(start).Round(time.Millisecond).Seconds())
}

// maybeDirectory starts a Tor Metrics lookup in the background when one
// is due: after the first round, then every DirectoryEvery (sooner after
// a failure).
func (c *Collector) maybeDirectory(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	c.mu.Lock()
	now := c.now()
	if c.dirRunning || now.Before(c.dirNext) {
		c.mu.Unlock()
		return
	}
	relays, bridges := c.model.Fingerprints(), c.model.BridgeFingerprints()
	if len(relays)+len(bridges) == 0 {
		c.mu.Unlock()
		return
	}
	c.dirRunning = true
	c.mu.Unlock()
	c.wg.Go(func() {
		dctx, cancel := context.WithTimeout(ctx, directoryTimeout)
		defer cancel()
		res := c.src.Directory(dctx, relays, bridges)
		c.applyDirectory(res)
	})
}

// applyDirectory records a lookup and saves the flag cache.
func (c *Collector) applyDirectory(res fleet.DirectoryResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dirRunning = false
	now := c.now()
	if res.At.IsZero() {
		res.At = now
	}
	c.model.SetDirectoryResult(res)
	if res.Err != nil {
		c.dirNext = now.Add(directoryRetry)
		c.log.Warn("Tor Metrics lookup failed", "err", res.Err)
		return
	}
	c.dirNext = now.Add(DirectoryEvery)
	c.log.Info("Tor Metrics lookup", "relays", len(res.Details), "bridges", len(res.Bridges))
	if c.cache == nil || c.cachePath == "" {
		return
	}
	if err := fleet.SaveFlagCache(c.cache, c.cachePath, c.model.PrevFlags, res.Details, now); err != nil {
		c.log.Warn("could not save the flag cache", "err", err)
		return
	}
	if now.Sub(c.flagsAt) >= flagsRoll {
		c.model.PrevFlags = fleet.LoadFlagCache(c.cache, c.cachePath)
		c.flagsAt = now
	}
}

// Healthy reports whether a probe round ended recently enough: within
// three intervals (at least two minutes).
func (c *Collector) Healthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	end := c.model.RoundEnd
	return !end.IsZero() && c.now().Sub(end) <= max(3*c.interval, 2*time.Minute)
}
