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
	"github.com/ljkx/tor-relay-setup/internal/keys"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/service"
	"github.com/ljkx/tor-relay-setup/internal/system"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

// Report is a snapshot of the relay.
type Report struct {
	CollectedAt time.Time `json:"collected_at"`
	// Instance names the Debian tor instance: "default" (/etc/tor/torrc,
	// tor@default) or the tor-instance-create name.
	Instance string `json:"instance"`

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
		Bridge      bool   `json:"bridge"`
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

	// Bridge is set for bridges: transport health and the bridge line.
	Bridge *Bridge `json:"bridge,omitempty"`
	// Keys is the state of the ed25519 identity keys (offline master key,
	// signing certificate expiry).
	Keys *keys.State `json:"keys,omitempty"`
	// PublicIPv4 is the address the bridge line uses: from Tor's self-test
	// notice, else a public interface address.
	PublicIPv4 string `json:"-"`

	Directory       *onionoo.Relay  `json:"directory,omitempty"`
	BridgeDirectory *onionoo.Bridge `json:"bridge_directory,omitempty"`
	DirectoryError  string          `json:"directory_error,omitempty"`

	Warnings []string `json:"warnings,omitempty"`

	// RecentLog holds the last few Tor log lines, for the dashboard.
	RecentLog []string `json:"-"`
}

// Options configures Collect.
type Options struct {
	// Instance is the tor instance to inspect; the zero value is the default
	// instance. TorrcPath and Unit override its paths (tests, odd setups).
	Instance  relay.Instance
	TorrcPath string        // default: the instance's torrc
	Unit      string        // default: the instance's unit
	Window    time.Duration // journal window for the self-test, default 24h
	// CertWarnDays warns this many days before the signing certificate of
	// an offline master key expires; default keys.DefaultWarnDays.
	CertWarnDays int
	// Now is the clock for certificate expiry; default time.Now.
	Now func() time.Time
}

// Healthy reports whether nothing needs attention.
func (r Report) Healthy() bool { return len(r.Warnings) == 0 }

// Reachability verdicts for ReachabilityVerdict.
const (
	ReachUnknown = iota // no evidence either way
	ReachYes
	ReachNo
)

// ReachabilityVerdict says whether the ORPort is reachable from outside, with
// a short explanation. tor runs its self-test only when it starts, so a
// relay that has been up for more than the journal window has no recent
// notice; a relay Tor Metrics reports as running in the consensus is
// evidently reachable (the directory authorities measured it), so that
// counts too. Without either, the answer is unknown, not a failure.
func (r Report) ReachabilityVerdict() (verdict int, text string) {
	switch {
	case r.Reachability.IPv4 && r.Reachability.IPv6:
		return ReachYes, "reachable from outside (IPv4 + IPv6)"
	case r.Reachability.IPv4:
		return ReachYes, "reachable from outside"
	case r.Reachability.Failed:
		return ReachNo, "NOT reachable from outside"
	case r.Directory != nil && r.Directory.Running:
		return ReachYes, "running in the consensus (tor self-tests only at startup)"
	case r.BridgeDirectory != nil && r.BridgeDirectory.Running:
		return ReachYes, "running, per the bridge authority (tor self-tests only at startup)"
	}
	return ReachUnknown, "not tested in the last 24 h (tor self-tests only at startup)"
}

// Collect probes the local relay concurrently.
func Collect(ctx context.Context, h host.Host, opt Options) Report {
	inst := opt.Instance.OrDefault()
	if opt.TorrcPath == "" {
		opt.TorrcPath = inst.TorrcPath
	}
	if opt.Unit == "" {
		opt.Unit = inst.Unit
	}
	if opt.Window == 0 {
		opt.Window = 24 * time.Hour
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	var r Report
	r.CollectedAt = time.Now()
	r.Instance = inst.Name
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
		if st.Address != "" {
			r.PublicIPv4 = st.Address
		}
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

		dataDir := doc.DataDirectoryOr(inst.DataDir)
		r.Relay.Fingerprint = ReadFingerprint(h, dataDir)

		fkd, _ := doc.Get("FamilyKeyDirectory")
		kd, _ := doc.Get("KeyDirectory")
		keyDir := relay.Unquote(strings.TrimSpace(kd))
		if keyDir == "" {
			keyDir = strings.TrimRight(dataDir, "/") + "/keys"
		}
		if r.Relay.Configured {
			st := keys.Inspect(h, keyDir, doc.OfflineMasterKey())
			r.Keys = &st
		}
		if b, ok := doc.BridgeSettings(); ok {
			r.Relay.Bridge = true
			rb := &Bridge{Transport: string(b.Transport), Plugin: b.Plugin, Port: b.Port, Distribution: b.Distribution}
			if rb.Distribution == "" {
				rb.Distribution = "any"
			}
			_, err := h.Stat(b.Plugin)
			rb.PluginInstalled = err == nil
			rb.HashedFingerprint = hashedFingerprint(h, dataDir, r.Relay.Fingerprint)
			r.Bridge = rb
			if b.Port > 0 {
				run(func() {
					v4, v6, err := system.Listening(h, b.Port)
					if err == nil {
						mu.Lock()
						rb.Listening = v4 || v6
						mu.Unlock()
					}
				})
			}
			if b.Transport == relay.TransportObfs4 && b.Port > 0 && b.Port < 1024 && rb.PluginInstalled {
				run(func() {
					pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					res, err := h.Run(pctx, host.Command{Name: "getcap", Args: []string{b.Plugin}})
					if err == nil {
						mu.Lock()
						rb.CapabilityMissing = !strings.Contains(res.Output, "cap_net_bind_service")
						mu.Unlock()
					}
				})
			}
			if _, err := h.Stat(inst.WebTunnelSite()); err == nil && b.Transport == relay.TransportWebTunnel {
				run(func() {
					pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					state := "inactive"
					if (service.Tor{Host: h, Unit: "nginx"}).Active(pctx) {
						state = "active"
					}
					mu.Lock()
					rb.WebServer = state
					mu.Unlock()
				})
			}
			if b.Transport == relay.TransportObfs4 {
				run(func() {
					pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					if ip := PublicIPv4(pctx, h); ip != "" {
						mu.Lock()
						if r.PublicIPv4 == "" {
							r.PublicIPv4 = ip
						}
						mu.Unlock()
					}
				})
			}
		}
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
	if r.Bridge != nil && doc != nil {
		b, _ := doc.BridgeSettings()
		r.Bridge.Line, r.Bridge.LineComplete = BridgeLine(h, doc.DataDirectoryOr(inst.DataDir), b, r.Relay.Fingerprint, r.PublicIPv4)
	}
	r.Warnings = warnings(r)
	if r.Keys != nil {
		r.Warnings = append(r.Warnings, r.Keys.Warnings(opt.Now(), opt.CertWarnDays)...)
	}
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
	// A WebTunnel bridge's ORPort is 127.0.0.1:auto: no port to probe.
	if r.Relay.Configured && r.Service.Active && r.Relay.ORPort > 0 && !r.Listener.IPv4 && !r.Listener.IPv6 {
		w = append(w, "nothing is listening on the ORPort")
	}
	w = append(w, BridgeWarnings(r)...)
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
