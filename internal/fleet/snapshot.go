package fleet

import (
	"math"
	"slices"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// Snapshot is the fleet as the web UI and GET /api/fleet see it: totals,
// hosts, relays and the attention list, flattened for a browser. It never
// carries a bridge's real fingerprint or bridge line, and in privacy mode
// no per-relay traffic or connection counts.
type Snapshot struct {
	GeneratedAt      time.Time       `json:"generated_at"`
	Privacy          bool            `json:"privacy"`
	LastProbe        time.Time       `json:"last_probe,omitzero"`
	ProbeSeconds     float64         `json:"probe_seconds,omitempty"`
	DirectoryUpdated time.Time       `json:"directory_updated,omitzero"`
	DirectoryError   string          `json:"directory_error,omitempty"`
	Totals           SnapshotTotals  `json:"totals"`
	History          *SnapshotSeries `json:"history,omitempty"`
	Versions         []VersionCount  `json:"tor_versions"`
	Hosts            []SnapshotHost  `json:"hosts"`
	Relays           []SnapshotRelay `json:"relays"`
	Attention        []SnapshotItem  `json:"attention"`
}

// SnapshotTotals are the fleet-wide numbers.
type SnapshotTotals struct {
	Relays          int     `json:"relays"`
	Running         int     `json:"running"`
	Hosts           int     `json:"hosts"`
	HostsUp         int     `json:"hosts_up"`
	Unreachable     int     `json:"hosts_unreachable"`
	WithoutProbe    int     `json:"hosts_without_probe"`
	Published       int     `json:"published"`
	ConsensusWeight int64   `json:"consensus_weight"`
	WeightFraction  float64 `json:"consensus_weight_fraction"`
	Guard           float64 `json:"guard_probability"`
	Middle          float64 `json:"middle_probability"`
	Exit            float64 `json:"exit_probability"`
	Advertised      int64   `json:"advertised_bandwidth"`
	Observed        int64   `json:"observed_bandwidth"`
	LiveRead        float64 `json:"live_read"`    // bytes per second
	LiveWritten     float64 `json:"live_written"` // bytes per second
	Connections     int     `json:"or_connections"`
	Attention       int     `json:"attention"`
}

// SnapshotSeries is the fleet's daily traffic from Tor Metrics, read plus
// written bytes per second; null for days without data.
type SnapshotSeries struct {
	First   string     `json:"first_day"`
	Daily   []*float64 `json:"daily"`
	Read    float64    `json:"read_bytes"`
	Written float64    `json:"written_bytes"`
}

// SnapshotHost is one server.
type SnapshotHost struct {
	Host    string    `json:"host"`
	State   HostState `json:"state"`
	Detail  string    `json:"detail,omitempty"`
	Version string    `json:"version,omitempty"`
	At      time.Time `json:"probed_at,omitzero"`
	LastOK  time.Time `json:"last_ok,omitzero"`
	Seconds float64   `json:"probe_seconds,omitempty"`
	Relays  int       `json:"relays"`
}

// SnapshotItem is one "Needs attention" finding.
type SnapshotItem struct {
	Level string `json:"level"` // "bad" or "warn"
	Kind  string `json:"kind"`
	Text  string `json:"text"`
}

// SnapshotRelay is one relay or bridge.
type SnapshotRelay struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Instance    string `json:"instance"`
	Nickname    string `json:"nickname"`
	Fingerprint string `json:"fingerprint,omitempty"` // hashed for bridges
	Role        string `json:"role"`
	State       string `json:"state"`
	InInventory bool   `json:"in_inventory"`
	// Fresh is false when the host did not answer the last probe; the
	// report fields are then from the last successful probe.
	Fresh      bool     `json:"fresh"`
	TorVersion string   `json:"tor_version,omitempty"`
	Active     bool     `json:"service_active"`
	ORPort     int      `json:"or_port,omitempty"`
	IPv6       bool     `json:"ipv6"`
	Listening  Families `json:"listening"`
	Reachable  Families `json:"reachable"`
	Warnings   []string `json:"warnings"`
	LostFlags  []string `json:"lost_flags,omitempty"`

	LiveRead    *float64 `json:"live_read,omitempty"`    // bytes per second; never in privacy mode
	LiveWritten *float64 `json:"live_written,omitempty"` // bytes per second; never in privacy mode
	Connections *int     `json:"or_connections,omitempty"`

	Load       *SnapshotLoad       `json:"load,omitempty"`
	Accounting *SnapshotAccounting `json:"accounting,omitempty"`
	Keys       *SnapshotKeys       `json:"keys,omitempty"`
	Family     *SnapshotFamily     `json:"family,omitempty"`
	Bridge     *SnapshotBridge     `json:"bridge,omitempty"`
	Directory  *SnapshotDirectory  `json:"directory,omitempty"`
}

// Families is an IPv4/IPv6 pair.
type Families struct {
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`
}

// SnapshotLoad are tor's load counters since it started.
type SnapshotLoad struct {
	OnionskinsProcessed uint64 `json:"onionskins_processed"`
	OnionskinsDropped   uint64 `json:"onionskins_dropped"`
	OOMBytes            uint64 `json:"oom_bytes"`
	TCPExhaustion       uint64 `json:"tcp_exhaustion"`
	RateLimitReached    uint64 `json:"rate_limit_reached"`
	SocketsOpen         uint64 `json:"sockets_open"`
	SocketsLimit        uint64 `json:"sockets_limit"`
}

// SnapshotAccounting is the AccountingMax budget.
type SnapshotAccounting struct {
	Rule       string    `json:"rule"`
	Max        uint64    `json:"max_bytes"`
	Used       uint64    `json:"used_bytes"`
	Projected  uint64    `json:"projected_bytes"`
	PeriodEnd  time.Time `json:"period_end"`
	ExhaustsAt time.Time `json:"exhausts_at,omitzero"`
}

// SnapshotKeys is the ed25519 signing certificate.
type SnapshotKeys struct {
	OfflineMaster bool      `json:"offline_master_key"`
	CertExpires   time.Time `json:"signing_cert_expires,omitzero"`
	Problem       string    `json:"problem,omitempty"`
}

// SnapshotFamily is the relay's FamilyId setup.
type SnapshotFamily struct {
	IDs         int   `json:"ids"`
	MissingKeys int   `json:"missing_keys"`
	Consistent  *bool `json:"consistent,omitempty"`
}

// SnapshotBridge is a bridge's transport and distribution.
type SnapshotBridge struct {
	Transport    string   `json:"transport"`
	Listening    bool     `json:"listening"`
	Distribution string   `json:"distribution,omitempty"`
	Distributor  string   `json:"distributor,omitempty"`
	Blocklist    []string `json:"blocklist,omitempty"`
}

// SnapshotDirectory is what Tor Metrics says about the relay.
type SnapshotDirectory struct {
	Published       bool      `json:"published"`
	Running         bool      `json:"running"`
	Flags           []string  `json:"flags"`
	Country         string    `json:"country,omitempty"`
	AS              string    `json:"as,omitempty"`
	ASName          string    `json:"as_name,omitempty"`
	ConsensusWeight int64     `json:"consensus_weight"`
	WeightFraction  float64   `json:"consensus_weight_fraction"`
	Guard           float64   `json:"guard_probability"`
	Middle          float64   `json:"middle_probability"`
	Exit            float64   `json:"exit_probability"`
	Advertised      int64     `json:"advertised_bandwidth"`
	Observed        int64     `json:"observed_bandwidth"`
	FirstSeen       time.Time `json:"first_seen,omitzero"`
	LastRestarted   time.Time `json:"last_restarted,omitzero"`
	Overloaded      bool      `json:"overloaded"`
	OverloadGeneral time.Time `json:"overload_general,omitzero"`
}

// Snapshot builds the browser's view of the fleet at now.
func (m *Model) Snapshot(now time.Time, privacy bool) Snapshot {
	t := m.Totals()
	items := m.Attention()
	s := Snapshot{
		GeneratedAt: now.UTC(), Privacy: privacy, LastProbe: m.RoundEnd, ProbeSeconds: m.RoundDuration.Seconds(),
		DirectoryUpdated: m.DirOK,
		Totals: SnapshotTotals{
			Relays: t.Relays, Running: t.Running, Hosts: t.Hosts, HostsUp: t.HostsUp, Unreachable: t.Unreachable,
			WithoutProbe: t.TooOld, Published: t.Published, ConsensusWeight: t.ConsensusWeight, WeightFraction: t.WeightFraction,
			Guard: t.Guard, Middle: t.Middle, Exit: t.Exit, Advertised: t.Advertised, Observed: t.Observed,
			LiveRead: t.Read, LiveWritten: t.Written, Connections: t.Connections, Attention: len(items),
		},
		Versions:  m.TorVersions(),
		Hosts:     []SnapshotHost{},
		Relays:    []SnapshotRelay{},
		Attention: []SnapshotItem{},
	}
	if m.DirErr != nil {
		s.DirectoryError = m.DirErr.Error()
	}
	if len(t.History) > 0 {
		h := &SnapshotSeries{First: t.HistoryFirst.Format(time.DateOnly), Read: t.HistoryIn, Written: t.HistoryOut}
		for _, v := range t.History {
			if math.IsNaN(v) {
				h.Daily = append(h.Daily, nil)
				continue
			}
			h.Daily = append(h.Daily, &v)
		}
		s.History = h
	}
	for _, it := range items {
		level := "warn"
		if it.Level == Bad {
			level = "bad"
		}
		s.Attention = append(s.Attention, SnapshotItem{Level: level, Kind: it.Kind, Text: it.Text})
	}
	counts := map[string]int{}
	for _, r := range m.relays {
		counts[r.Address]++
	}
	for _, h := range m.hosts {
		s.Hosts = append(s.Hosts, SnapshotHost{Host: HostOf(h.Address), State: h.State, Detail: h.Detail, Version: h.Version,
			At: h.At, LastOK: h.LastOK, Seconds: h.Duration.Seconds(), Relays: counts[h.Address]})
	}
	sets, majority, _ := m.familySets()
	for _, r := range m.relays {
		s.Relays = append(s.Relays, m.snapshotRelay(r, now, privacy, sets, majority))
	}
	return s
}

func (m *Model) snapshotRelay(r *Relay, now time.Time, privacy bool, sets map[*Relay]string, majority string) SnapshotRelay {
	sr := SnapshotRelay{
		ID: HostOf(r.Address) + "/" + r.Instance, Host: HostOf(r.Address), Instance: r.Instance, Nickname: r.Nickname(),
		Fingerprint: r.PublicFingerprint(), Role: m.Role(r), State: m.RelayState(r), InInventory: r.Entry != nil,
		TorVersion: r.TorVersion(), Warnings: slices.Clone(r.Warnings()), LostFlags: m.LostFlags(r),
	}
	if sr.Warnings == nil {
		sr.Warnings = []string{}
	}
	fresh := m.Fresh(r)
	sr.Fresh = fresh != nil
	if p := r.Probe; p != nil {
		rep := p.Report
		sr.Active = fresh != nil && rep.Service.Active
		sr.ORPort, sr.IPv6 = rep.Relay.ORPort, rep.Relay.IPv6
		sr.Listening = Families{rep.Listener.IPv4, rep.Listener.IPv6}
		sr.Reachable = Families{rep.Reachability.IPv4, rep.Reachability.IPv6}
		if smp := p.MetricsSample(); smp != nil && fresh != nil {
			if !privacy {
				conns := smp.Connections
				sr.Connections = &conns
				if r.HasRate {
					rd, wr := r.Rate.Read, r.Rate.Written
					sr.LiveRead, sr.LiveWritten = &rd, &wr
				}
			}
			if l := smp.Load; l.Seen {
				sr.Load = &SnapshotLoad{
					OnionskinsProcessed: l.OnionskinsProcessed.TAP + l.OnionskinsProcessed.Fast + l.OnionskinsProcessed.NtorTotal(),
					OnionskinsDropped:   l.OnionskinsDropped.TAP + l.OnionskinsDropped.Fast + l.OnionskinsDropped.NtorTotal(),
					OOMBytes:            l.OOMBytes.Total(), TCPExhaustion: l.TCPExhaustion, RateLimitReached: l.RateLimitRead + l.RateLimitWrite,
					SocketsOpen: l.SocketsOpen, SocketsLimit: l.SocketsLimit,
				}
			}
		}
		if a := p.Accounting; a != nil && a.Enabled {
			sr.Accounting = &SnapshotAccounting{Rule: a.Rule, Max: a.Max, Used: a.Used, Projected: a.Projected, PeriodEnd: a.PeriodEnd}
			if a.RunsOut() {
				sr.Accounting.ExhaustsAt = a.ExhaustsAt
			}
		}
		if k := rep.Keys; k != nil && k.Managed() {
			sr.Keys = &SnapshotKeys{OfflineMaster: k.Offline, CertExpires: k.CertExpires, Problem: k.CertProblem}
		}
		if rep.Relay.Configured && !r.IsBridge() {
			f := &SnapshotFamily{IDs: len(rep.Family.IDs), MissingKeys: len(rep.Family.MissingKeys)}
			if key, ok := sets[r]; ok {
				c := key == majority
				f.Consistent = &c
			}
			sr.Family = f
		}
		if b := rep.Bridge; b != nil {
			sr.Bridge = &SnapshotBridge{Transport: b.Transport, Listening: b.Listening, Distribution: b.Distribution}
		}
	}
	published, known := m.Published(r)
	switch d, bd := m.DirectoryOf(r), m.BridgeDirectoryOf(r); {
	case d != nil:
		sr.Directory = &SnapshotDirectory{
			Published: true, Running: d.Running, Flags: slices.Clone(d.Flags), Country: d.Country, AS: d.AS, ASName: d.ASName,
			ConsensusWeight: d.ConsensusWeight, WeightFraction: d.ConsensusWeightFraction, Guard: d.GuardProbability,
			Middle: d.MiddleProbability, Exit: d.ExitProbability, Advertised: d.AdvertisedBandwidth, Observed: d.ObservedBandwidth,
			FirstSeen: onionoo.ParseTime(d.FirstSeen), LastRestarted: onionoo.ParseTime(d.LastRestarted),
			Overloaded: d.Overloaded(now), OverloadGeneral: d.OverloadGeneral,
		}
	case bd != nil:
		sr.Directory = &SnapshotDirectory{
			Published: true, Running: bd.Running, Flags: slices.Clone(bd.Flags), Advertised: bd.AdvertisedBandwidth,
			FirstSeen: onionoo.ParseTime(bd.FirstSeen), LastRestarted: onionoo.ParseTime(bd.LastRestarted),
			Overloaded: bd.Overloaded(now), OverloadGeneral: bd.OverloadGeneral(),
		}
		if sr.Bridge != nil {
			sr.Bridge.Distributor, sr.Bridge.Blocklist = bd.Distributor, slices.Clone(bd.Blocklist)
		}
	case known && !published:
		sr.Directory = &SnapshotDirectory{Flags: []string{}}
	}
	return sr
}
