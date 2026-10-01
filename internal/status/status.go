// Package status gathers relay health for the console dashboard and for
// `tor-relay-setup status`. Local probes run concurrently and are cheap; the
// Tor Metrics lookup is separate because it needs the network.
package status

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/service"
	"github.com/ljkx/tor-relay-setup/internal/system"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

// Report is a snapshot of the relay.
type Report struct {
	CollectedAt time.Time `json:"collected_at"`

	Tor struct {
		Installed bool   `json:"installed"`
		Version   string `json:"version,omitempty"`
		Supported bool   `json:"supported"`
	} `json:"tor"`

	Service struct {
		Unit   string `json:"unit"`
		Active bool   `json:"active"`
	} `json:"service"`

	Relay struct {
		Configured  bool   `json:"configured"`
		Nickname    string `json:"nickname,omitempty"`
		Contact     string `json:"contact,omitempty"`
		Fingerprint string `json:"fingerprint,omitempty"`
		ORPort      int    `json:"or_port,omitempty"`
		IPv6        bool   `json:"ipv6"`
		Exit        bool   `json:"exit"`
		Sandbox     bool   `json:"sandbox"`
		MetricsPort string `json:"metrics_port,omitempty"`
		Bandwidth   string `json:"bandwidth,omitempty"`
		Accounting  string `json:"accounting,omitempty"`
	} `json:"relay"`

	Listener struct {
		IPv4 bool `json:"ipv4"`
		IPv6 bool `json:"ipv6"`
	} `json:"listener"`

	Reachability struct {
		IPv4   bool `json:"ipv4"`
		IPv6   bool `json:"ipv6"`
		Failed bool `json:"failed"`
		Seen   bool `json:"seen"` // any self-test notice in the window
	} `json:"reachability"`

	Family struct {
		IDs          []string     `json:"ids,omitempty"`
		KeyDirectory string       `json:"key_directory,omitempty"`
		Keys         []family.Key `json:"keys,omitempty"`
		MissingKeys  []string     `json:"missing_keys,omitempty"`
		LegacyCount  int          `json:"legacy_myfamily"`
	} `json:"family"`

	Directory      *onionoo.Relay `json:"directory,omitempty"`
	DirectoryError string         `json:"directory_error,omitempty"`

	Warnings []string `json:"warnings,omitempty"`

	// RecentLog holds the last few Tor log lines, for the dashboard.
	RecentLog []string `json:"-"`
}

// Options configures Collect.
type Options struct {
	TorrcPath string        // default /etc/tor/torrc
	Unit      string        // default tor@default
	Window    time.Duration // journal window for the self-test, default 24h
}

// Healthy reports whether nothing needs attention.
func (r Report) Healthy() bool { return len(r.Warnings) == 0 }

// Collect probes the local relay concurrently.
func Collect(ctx context.Context, h host.Host, opt Options) Report {
	if opt.TorrcPath == "" {
		opt.TorrcPath = "/etc/tor/torrc"
	}
	if opt.Unit == "" {
		opt.Unit = service.DefaultUnit
	}
	if opt.Window == 0 {
		opt.Window = 24 * time.Hour
	}
	var r Report
	r.CollectedAt = time.Now()
	r.Service.Unit = opt.Unit
	tor := service.Tor{Host: h, Unit: opt.Unit}

	var doc *relay.Document
	if data, err := h.ReadFile(opt.TorrcPath); err == nil {
		doc = relay.ParseDocument(data)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}

	run(func() {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		res, err := h.Run(pctx, host.Command{Name: "tor", Args: []string{"--version"}})
		if err != nil {
			return
		}
		v, err := torproject.ParseTorVersion(res.Output)
		mu.Lock()
		defer mu.Unlock()
		r.Tor.Installed = true
		if err == nil {
			r.Tor.Version = v
			r.Tor.Supported = torproject.VersionAtLeast(v, torproject.MinVersion)
		}
	})
	run(func() {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		active := tor.Active(pctx)
		mu.Lock()
		r.Service.Active = active
		mu.Unlock()
	})
	run(func() {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		log, err := tor.Journal(pctx, "-"+formatWindow(opt.Window), 0, "")
		if err != nil {
			return
		}
		st := relay.ParseSelfTest(log)
		recent := lastLines(log, 8)
		mu.Lock()
		r.RecentLog = recent
		r.Reachability.IPv4, r.Reachability.IPv6, r.Reachability.Failed = st.IPv4, st.IPv6, st.Failed
		r.Reachability.Seen = st.IPv4 || st.IPv6 || st.Failed
		mu.Unlock()
	})

	if doc != nil {
		r.Relay.Configured = len(doc.ORPorts()) > 0
		r.Relay.Nickname, _ = doc.Get("Nickname")
		if c, ok := doc.Get("ContactInfo"); ok {
			r.Relay.Contact = relay.Unquote(c)
		}
		r.Relay.ORPort = doc.FirstORPort()
		for _, p := range doc.ORPorts() {
			if strings.Contains(p, "[") {
				r.Relay.IPv6 = true
			}
		}
		exit, _ := doc.Get("ExitRelay")
		r.Relay.Exit = strings.TrimSpace(exit) == "1"
		sandbox, _ := doc.Get("Sandbox")
		r.Relay.Sandbox = strings.TrimSpace(sandbox) == "1"
		r.Relay.MetricsPort, _ = doc.Get("MetricsPort")
		if rate, ok := doc.Get("RelayBandwidthRate"); ok {
			burst, _ := doc.Get("RelayBandwidthBurst")
			r.Relay.Bandwidth = rate + " · burst " + burst
		}
		if max, ok := doc.Get("AccountingMax"); ok {
			rule, ok := doc.Get("AccountingRule")
			if !ok {
				rule = "max"
			}
			r.Relay.Accounting = max + "/month · " + rule
		}

		dataDir := doc.DataDirectory()
		if fp, err := h.ReadFile(strings.TrimRight(dataDir, "/") + "/fingerprint"); err == nil {
			if fields := strings.Fields(string(fp)); len(fields) > 0 {
				r.Relay.Fingerprint = strings.ToUpper(fields[len(fields)-1])
			}
		}

		fkd, _ := doc.Get("FamilyKeyDirectory")
		kd, _ := doc.Get("KeyDirectory")
		r.Family.KeyDirectory = family.KeyDirectory(fkd, kd, dataDir)
		r.Family.IDs = doc.FamilyIDs()
		r.Family.LegacyCount = len(doc.MyFamily())
		if keys, err := family.Installed(h, r.Family.KeyDirectory); err == nil {
			r.Family.Keys = keys
		}
		for _, id := range r.Family.IDs {
			if !family.HasKeyFor(r.Family.Keys, id) {
				r.Family.MissingKeys = append(r.Family.MissingKeys, id)
			}
		}
		if r.Relay.ORPort > 0 {
			run(func() {
				v4, v6, err := system.Listening(h, r.Relay.ORPort)
				if err != nil {
					return
				}
				mu.Lock()
				r.Listener.IPv4, r.Listener.IPv6 = v4, v6
				mu.Unlock()
			})
		}
	}
	wg.Wait()
	r.Warnings = warnings(r)
	return r
}

// Directory looks the relay up in Tor Metrics.
func Directory(ctx context.Context, c onionoo.Client, fingerprint string) (*onionoo.Relay, error) {
	if fingerprint == "" {
		return nil, nil
	}
	return c.Details(ctx, fingerprint)
}

func warnings(r Report) []string {
	var w []string
	switch {
	case !r.Tor.Installed:
		w = append(w, "tor is not installed")
	case r.Tor.Version != "" && !r.Tor.Supported:
		w = append(w, "tor "+r.Tor.Version+" is older than "+torproject.MinVersion+" and is rejected by the network")
	}
	if r.Relay.Configured && !r.Service.Active {
		w = append(w, r.Service.Unit+" is not running")
	}
	if r.Relay.Configured && r.Service.Active && !r.Listener.IPv4 && !r.Listener.IPv6 {
		w = append(w, "nothing is listening on the ORPort")
	}
	if r.Reachability.Failed && !r.Reachability.IPv4 {
		w = append(w, "Tor could not confirm the ORPort is reachable from outside")
	}
	for _, id := range r.Family.MissingKeys {
		w = append(w, "no family key installed for FamilyId "+id)
	}
	if r.Relay.Configured && len(r.Family.IDs) == 0 && r.Family.LegacyCount > 0 {
		w = append(w, "only a legacy MyFamily list is configured; Tor 0.4.9 families use FamilyId keys")
	}
	return w
}

func formatWindow(d time.Duration) string {
	return strconv.Itoa(int(d.Minutes())) + "min"
}

func lastLines(log string, n int) []string {
	var out []string
	for _, line := range strings.Split(log, string(rune(10))) {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "-- ") {
			out = append(out, line)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}
