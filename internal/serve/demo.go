package serve

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/keys"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/status"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

// Demo credentials, used by `fleet serve --demo` on a loopback listener
// when serve.toml configures no users or token. They are documented and
// not secret; they never apply anywhere else.
const (
	DemoUser     = "demo"
	DemoPassword = "tor-relay-demo"                    //nolint:gosec // documented demo password, only for --demo on loopback
	DemoToken    = "trs_demo_metrics_token_not_secret" //nolint:gosec // documented demo token, only for --demo on loopback
	DemoSeed     = 9850
)

// demoHost is one synthetic server.
type demoHost struct {
	address     string
	tool        string // tor-relay-setup version; before v3.3 no load counters
	unreachable bool
	legacy      bool // an older tor-relay-setup: traffic counters only
	country     string
	as, asName  string
}

// demoRelay is one synthetic relay.
type demoRelay struct {
	host       int
	instance   string
	nick       string
	role       string
	tor        string
	orPort     int
	ipv6       bool
	mean       float64 // mean bytes per second, each direction
	phase      float64
	phase2     float64
	uptime     time.Duration // tor started this long before the demo
	firstSeen  time.Duration // first in the consensus this long before the demo
	fp         string
	overloaded bool
	accounting bool
	certSoon   bool
}

// Demo is a synthetic fleet of 12 relays on 7 servers: guards, exits,
// middles and an obfs4 bridge, one unreachable server, one overloaded
// relay, one close to its AccountingMax, one with an offline master key
// whose signing certificate expires soon, and an older tor-relay-setup on
// one server. Everything is a pure function of the seed and the clock, and
// the counters grow along a daily curve, so Prometheus rate() and Grafana
// graphs behave like a live fleet.
type Demo struct {
	// Latency makes Probe take as long as the probe it reports (fleet serve
	// --demo), so probe durations and rounds look real; tests leave it off.
	Latency bool

	start  time.Time
	now    func() time.Time
	hosts  []demoHost
	relays []demoRelay
	family string
}

// NewDemo builds the fleet; now is the clock (time.Now when nil).
func NewDemo(seed uint64, now func() time.Time) *Demo {
	if now == nil {
		now = time.Now
	}
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:], seed)
	src := rand.NewChaCha8(key)
	rng := rand.New(src) //nolint:gosec // a seeded, reproducible demo, not a secret
	d := &Demo{start: now(), now: now}
	d.hosts = []demoHost{
		{"root@fra1.relays.example.net", "v3.3.0", false, false, "de", "AS24940", "Hetzner Online GmbH"},
		{"root@ams1.relays.example.net", "v3.3.0", false, false, "nl", "AS60781", "LeaseWeb Netherlands B.V."},
		{"root@par1.relays.example.net", "v3.3.0", false, false, "fr", "AS16276", "OVH SAS"},
		{"root@sto1.relays.example.net", "v3.3.0", false, false, "se", "AS42708", "GleSYS AB"},
		{"admin@nyc1.relays.example.net", "v3.2.0", false, true, "us", "AS14061", "DigitalOcean, LLC"},
		{"root@zrh1.relays.example.net", "v3.3.0", false, false, "ch", "AS13030", "Init7 (Switzerland) Ltd."},
		{"root@hel1.relays.example.net", "v3.3.0", true, false, "fi", "AS24940", "Hetzner Online GmbH"},
	}
	type spec struct {
		host                            int
		instance, nick, role, tor       string
		port                            int
		mbit                            float64
		overloaded, accounting, certSoo bool
	}
	specs := []spec{
		{0, "default", "TorFleetFRA1", fleet.RoleGuard, "0.4.9.3", 9001, 420, false, false, false},
		{0, "fra2", "TorFleetFRA2", fleet.RoleGuard, "0.4.9.3", 9002, 380, false, false, false},
		{1, "default", "TorFleetAMS1", fleet.RoleExit, "0.4.9.3", 443, 610, false, false, false},
		{1, "ams2", "TorFleetAMS2", fleet.RoleExit, "0.4.9.3", 9002, 540, false, false, false},
		{2, "default", "TorFleetPAR1", fleet.RoleMiddle, "0.4.9.2", 9001, 260, true, false, false},
		{2, "par2", "TorFleetPAR2", fleet.RoleGuard, "0.4.9.3", 9002, 300, false, false, false},
		{3, "default", "TorFleetSTO1", fleet.RoleGuard, "0.4.9.3", 9001, 190, false, true, false},
		{4, "default", "TorFleetNYC1", fleet.RoleExit, "0.4.9.2", 443, 480, false, false, false},
		{4, "nyc2", "TorFleetNYC2", fleet.RoleMiddle, "0.4.9.2", 9002, 210, false, false, true},
		{5, "default", "TorFleetBridge", fleet.RoleBridge, "0.4.9.3", 9001, 35, false, false, false},
		{5, "zrh2", "TorFleetZRH2", fleet.RoleMiddle, "0.4.10.1-alpha", 9002, 150, false, false, false},
		{6, "default", "TorFleetHEL1", fleet.RoleGuard, "0.4.9.3", 9001, 330, false, false, false},
	}
	for _, s := range specs {
		fp := make([]byte, 20)
		_, _ = src.Read(fp)
		d.relays = append(d.relays, demoRelay{
			host: s.host, instance: s.instance, nick: s.nick, role: s.role, tor: s.tor, orPort: s.port,
			ipv6:  s.role != fleet.RoleBridge && rng.IntN(3) > 0,
			mean:  s.mbit * 1e6 / 8 * (0.9 + 0.2*rng.Float64()),
			phase: rng.Float64() * 2 * math.Pi, phase2: rng.Float64() * 2 * math.Pi,
			uptime:     time.Duration(2+rng.IntN(40)) * 24 * time.Hour,
			firstSeen:  time.Duration(120+rng.IntN(900)) * 24 * time.Hour,
			fp:         strings.ToUpper(hex.EncodeToString(fp)),
			overloaded: s.overloaded, accounting: s.accounting, certSoon: s.certSoo,
		})
	}
	fam := make([]byte, 32)
	_, _ = src.Read(fam)
	d.family = base64.RawStdEncoding.EncodeToString(fam)
	return d
}

// Inventory is the fleet.toml the demo pretends to have.
func (d *Demo) Inventory() fleet.Inventory {
	inv := fleet.Inventory{Parallel: 1}
	for i, r := range d.relays {
		s := config.Default()
		s.Relay.Nickname, s.Relay.ORPort, s.Relay.Instance = r.nick, r.orPort, r.instance
		s.Relay.Mode = map[string]string{fleet.RoleExit: "exit", fleet.RoleBridge: "bridge"}[r.role]
		if s.Relay.Mode == "" {
			s.Relay.Mode = "guard"
		}
		inv.Entries = append(inv.Entries, fleet.Entry{Index: i + 1, Address: d.hosts[r.host].address, Instance: r.instance, Setup: s})
	}
	return inv
}

const (
	day     = 24 * time.Hour
	wiggleT = 97 * time.Minute
	// curve amplitudes: a daily swing and a faster wiggle.
	ampDay    = 0.35
	ampWiggle = 0.08
)

// rate is the relay's traffic in bytes per second at t.
func (r demoRelay) rate(t time.Time, skew float64) float64 {
	s := float64(t.UnixNano()) / 1e9
	return r.mean * skew * (1 + ampDay*math.Sin(2*math.Pi*s/day.Seconds()+r.phase) + ampWiggle*math.Sin(2*math.Pi*s/wiggleT.Seconds()+r.phase2))
}

// bytes is the integral of rate from tor's start to t: a counter that only
// grows.
func (r demoRelay) bytes(start, t time.Time, skew float64) float64 {
	if !t.After(start) {
		return 0
	}
	prim := func(t time.Time) float64 {
		s := float64(t.UnixNano()) / 1e9
		dd, w := day.Seconds(), wiggleT.Seconds()
		return s - ampDay*dd/(2*math.Pi)*math.Cos(2*math.Pi*s/dd+r.phase) - ampWiggle*w/(2*math.Pi)*math.Cos(2*math.Pi*s/w+r.phase2)
	}
	return r.mean * skew * (prim(t) - prim(start))
}

// unit is a deterministic number in [0, 1) for a key.
func unit(parts ...string) float64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return float64(h.Sum64()>>11) / (1 << 53)
}

// Probe returns the synthetic probe of one server at the demo's clock.
func (d *Demo) Probe(ctx context.Context, address string) fleet.HostProbe {
	hp := d.probe(address)
	if d.Latency {
		select {
		case <-ctx.Done():
		case <-time.After(hp.Duration):
		}
	}
	return hp
}

func (d *Demo) probe(address string) fleet.HostProbe {
	now := d.now()
	hp := fleet.HostProbe{Address: address, At: now}
	hi := -1
	for i, h := range d.hosts {
		if h.address == address {
			hi = i
		}
	}
	if hi < 0 {
		hp.State, hp.Detail = fleet.HostFailed, "not part of the demo fleet"
		return hp
	}
	h := d.hosts[hi]
	if h.unreachable {
		hp.State, hp.Duration = fleet.HostUnreachable, 10*time.Second
		hp.Detail = "ssh: connect to host " + fleet.HostOf(address) + " port 22: Connection timed out"
		return hp
	}
	minute := now.Truncate(time.Minute).Format(time.RFC3339)
	hp.State = fleet.HostOK
	hp.Duration = time.Duration((0.35 + 0.9*unit(address, minute)) * float64(time.Second))
	p := fleet.Probe{Version: h.tool}
	for _, r := range d.relays {
		if r.host == hi {
			p.Relays = append(p.Relays, d.relayProbe(r, h, now))
		}
	}
	// Through the wire format, exactly as a real fleet-probe answers.
	data, err := json.Marshal(p)
	if err == nil {
		p, err = fleet.ParseProbe(string(data))
	}
	if err != nil {
		hp.State, hp.Detail = fleet.HostFailed, err.Error()
		return hp
	}
	hp.Probe = p
	return hp
}

func (d *Demo) relayProbe(r demoRelay, h demoHost, now time.Time) fleet.RelayProbe {
	var rep status.Report
	rep.CollectedAt, rep.Instance = now, r.instance
	rep.Tor.Installed, rep.Tor.Version, rep.Tor.Supported = true, r.tor, torproject.VersionAtLeast(r.tor, torproject.MinVersion)
	rep.Service.Unit, rep.Service.Active = "tor@"+r.instance, true
	rep.Relay.Configured, rep.Relay.Nickname, rep.Relay.Fingerprint, rep.Relay.ORPort = true, r.nick, r.fp, r.orPort
	rep.Relay.Contact = "email:ops[]example.net ciissversion:2"
	rep.Relay.IPv6, rep.Relay.Exit, rep.Relay.Bridge = r.ipv6, r.role == fleet.RoleExit, r.role == fleet.RoleBridge
	rep.Relay.Sandbox = true
	rep.Relay.MetricsPort = "127.0.0.1:" + map[bool]string{true: "9035", false: "9036"}[r.instance == "default"]
	rep.Listener.IPv4, rep.Listener.IPv6 = true, r.ipv6
	rep.Reachability.IPv4, rep.Reachability.IPv6, rep.Reachability.Seen = true, r.ipv6, true
	dataDir := "/var/lib/tor"
	if r.instance != "default" {
		dataDir = "/var/lib/tor-instances/" + r.instance
	}
	if r.role == fleet.RoleBridge {
		hashed, _ := onionoo.HashFingerprint(r.fp)
		rep.Bridge = &status.Bridge{Transport: "obfs4", Plugin: "/usr/bin/lyrebird", PluginInstalled: true, Port: 443,
			Listening: true, Distribution: "any", HashedFingerprint: hashed, LineComplete: true}
	} else {
		rep.Family.IDs = []string{d.family}
		rep.Family.KeyDirectory = dataDir + "/keys"
		rep.Family.Keys = []family.Key{{Name: "relay-family", Path: dataDir + "/keys/relay-family.secret_family_key", ID: d.family}}
	}
	k := &keys.State{KeyDir: dataDir + "/keys", MasterOnDisk: true, Identity: base64.RawStdEncoding.EncodeToString([]byte(r.fp))[:43]}
	if r.certSoon {
		// The signing certificate was made 26 days before the demo started
		// with a 30-day lifetime: it runs out in about four days.
		k.Offline, k.MasterOnDisk = true, false
		k.CertExpires = d.start.Add(4*day + 7*time.Hour).Truncate(time.Hour)
	}
	rep.Keys = k
	if !rep.Tor.Supported {
		rep.Warnings = append(rep.Warnings, "tor "+r.tor+" is older than "+torproject.MinVersion+" and is rejected by the network")
	}
	rep.Warnings = append(rep.Warnings, k.Warnings(now, keys.DefaultWarnDays)...)

	started := d.start.Add(-r.uptime)
	read, written := r.bytes(started, now, 1), r.bytes(started, now, 1.012)
	conns := r.rate(now, 1)/4000 + 40
	if r.role == fleet.RoleBridge {
		conns = r.rate(now, 1)/9000 + 12
	}
	p := fleet.RelayProbe{Report: rep, Traffic: &fleet.Traffic{At: now, Read: uint64(read), Written: uint64(written), Connections: int(conns)}}
	if h.legacy { // an older tor-relay-setup sends only the traffic counters
		return p
	}
	s := &metrics.Sample{At: now, Read: uint64(read), Written: uint64(written), Connections: int(conns), Load: d.load(r, read, now, conns)}
	p.Sample = s
	if r.accounting {
		p.Accounting = d.accounting(now)
	}
	return p
}

// load derives tor's load counters from the traffic so far.
func (d *Demo) load(r demoRelay, read float64, now time.Time, conns float64) metrics.Load {
	hs := read / 48_000 // circuit handshakes so far
	l := metrics.Load{Seen: true}
	l.OnionskinsProcessed = metrics.Onionskins{Fast: uint64(hs * 0.03), Ntor: uint64(hs * 0.55), NtorV3: uint64(hs * 0.42)}
	l.OnionskinsDropped = metrics.Onionskins{Ntor: uint64(hs * 0.55 * 0.00002)}
	l.SocketsOpen, l.SocketsLimit = uint64(conns+60), 65_000
	if r.role == fleet.RoleExit {
		l.TCPExhaustion = uint64(read / 8e11)
		l.SocketsLimit = 524_288
	}
	if r.overloaded {
		// CPU-starved: about 2.5% of ntor handshakes dropped, the OOM
		// handler runs every few hours, and sockets are nearly used up.
		l.OnionskinsDropped = metrics.Onionskins{Ntor: uint64(hs * 0.55 * 0.025), NtorV3: uint64(hs * 0.42 * 0.025)}
		started := d.start.Add(-r.uptime)
		l.OOMBytes.Cell = uint64(now.Sub(started).Hours()/3) * 48 << 20
		l.SocketsLimit = 8_192
		l.SocketsOpen = uint64(7_400 + 500*unit(r.fp, now.Truncate(time.Minute).String()))
	}
	if r.accounting {
		l.RateLimitRead, l.RateLimitWrite = uint64(read/3e9), uint64(read/2.6e9)
	}
	return l
}

// accounting is a 14 TiB weekly budget (AccountingStart week, at midnight
// UTC six days before the demo started), spent a little faster than it
// lasts: the demo starts close to the cap, runs out before the week ends
// and hibernates, and then starts a fresh week.
func (d *Demo) accounting(now time.Time) *metrics.Accounting {
	wd := int(d.start.UTC().Add(-6 * day).Weekday())
	if wd == 0 {
		wd = 7 // tor: 1 is Monday, 7 is Sunday
	}
	cfg := metrics.AccountingConfig{Max: 14 << 40, Rule: metrics.RuleMax, Start: metrics.AccountingStart{Unit: "week", Day: wd}}
	start, end := cfg.Start.Period(now.UTC())
	frac := now.Sub(start).Seconds() / end.Sub(start).Seconds()
	used := min(float64(cfg.Max)*1.03*frac, float64(cfg.Max))
	u := metrics.AccountingUsage{IntervalStart: start, Read: uint64(used), Written: uint64(used * 0.97), LastWritten: now.UTC()}
	a := metrics.AssessAccounting(cfg, u, now.UTC())
	return &a
}

// Directory is what Tor Metrics would say about the demo fleet.
func (d *Demo) Directory(_ context.Context, relays, bridges []string) fleet.DirectoryResult {
	now := d.now()
	res := fleet.DirectoryResult{At: now, Details: map[string]*onionoo.Relay{}, Bridges: map[string]*onionoo.Bridge{}, History: map[string]*onionoo.Bandwidth{}}
	const networkWeight = 9.5e7
	for _, r := range d.relays {
		h := d.hosts[r.host]
		started := d.start.Add(-r.uptime).UTC()
		if r.role == fleet.RoleBridge {
			hashed, _ := onionoo.HashFingerprint(r.fp)
			if !contains(bridges, hashed) {
				continue
			}
			res.Bridges[hashed] = &onionoo.Bridge{
				Nickname: r.nick, HashedFingerprint: hashed, Running: true, Flags: []string{"Fast", "Running", "Stable", "Valid"},
				FirstSeen: d.start.Add(-r.firstSeen).UTC().Format(time.DateTime), LastSeen: now.UTC().Truncate(time.Hour).Format(time.DateTime),
				LastRestarted: started.Format(time.DateTime), AdvertisedBandwidth: int64(r.mean * 1.7),
				Platform: "Tor " + r.tor + " on Linux", Version: r.tor, Transports: []string{"obfs4"}, Distributor: "moat",
			}
			continue
		}
		if !contains(relays, r.fp) {
			continue
		}
		flags := []string{"Fast", "Running", "Stable", "V2Dir", "Valid"}
		weight := r.mean / 1e3 * (0.8 + 0.3*unit(r.fp, "weight"))
		dr := &onionoo.Relay{
			Nickname: r.nick, Fingerprint: r.fp, Running: true, ConsensusWeight: int64(weight),
			ConsensusWeightFraction: weight / networkWeight, MiddleProbability: weight / networkWeight * 0.8,
			AdvertisedBandwidth: int64(r.mean * 1.6), ObservedBandwidth: int64(r.mean * 1.52),
			FirstSeen: d.start.Add(-r.firstSeen).UTC().Format(time.DateTime), LastSeen: now.UTC().Truncate(time.Hour).Format(time.DateTime),
			LastRestarted: started.Format(time.DateTime), Platform: "Tor " + r.tor + " on Linux",
			Contact: "email:ops[]example.net ciissversion:2", FamilyIDs: []string{d.family},
			Country: h.country, AS: h.as, ASName: h.asName,
		}
		switch r.role {
		case fleet.RoleGuard:
			flags = append(flags, "Guard", "HSDir")
			dr.GuardProbability, dr.MiddleProbability = weight/networkWeight*1.7, weight/networkWeight*0.5
		case fleet.RoleExit:
			flags = append(flags, "Exit", "Guard")
			dr.ExitProbability, dr.MiddleProbability = weight/networkWeight*3.1, 0
		}
		if r.overloaded {
			dr.OverloadGeneral = now.UTC().Add(-2 * time.Hour).Truncate(time.Hour)
		}
		dr.Flags = flags
		res.Details[r.fp] = dr
		res.History[r.fp] = d.history(r, now)
	}
	return res
}

// history is 30 days of daily traffic, like Onionoo's 1_month graph.
func (d *Demo) history(r demoRelay, now time.Time) *onionoo.Bandwidth {
	first := now.UTC().Truncate(day).Add(-30 * day)
	mk := func(skew float64, key string) onionoo.History {
		h := onionoo.History{First: first, Last: first.Add(29 * day), Interval: day, Values: make([]float64, 30)}
		for i := range h.Values {
			dayKey := first.Add(time.Duration(i) * day).Format(time.DateOnly)
			// a slow trend up, weekly dip, and day-to-day noise
			trend := 0.82 + 0.18*float64(i)/29
			weekly := 1 - 0.06*math.Cos(2*math.Pi*float64(i)/7)
			h.Values[i] = r.mean * skew * trend * weekly * (0.9 + 0.2*unit(r.fp, key, dayKey))
		}
		return h
	}
	return &onionoo.Bandwidth{Read: mk(1, "r"), Written: mk(1.012, "w")}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
