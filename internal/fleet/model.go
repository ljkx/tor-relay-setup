package fleet

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// HostState classifies a host's last probe.
type HostState string

// Host states.
const (
	HostPending     HostState = "pending"       // not probed yet
	HostOK          HostState = "ok"            // fleet-probe answered
	HostUnreachable HostState = "unreachable"   // ssh could not connect or authenticate
	HostTooOld      HostState = "too-old"       // the installed tor-relay-setup has no fleet-probe
	HostMissing     HostState = "not-installed" // no tor-relay-setup on the host
	HostFailed      HostState = "failed"        // anything else
)

// HostProbe is the outcome of probing one server.
type HostProbe struct {
	Address  string
	At       time.Time
	Duration time.Duration // how long the probe took, connection included
	State    HostState
	Detail   string // why it failed, for the operator
	Probe    Probe
}

// HostStatus is the dashboard's view of one server.
type HostStatus struct {
	Address  string
	State    HostState
	Detail   string
	Version  string // tor-relay-setup on the host
	At       time.Time
	Duration time.Duration // the last probe's duration
	LastOK   time.Time     // the last successful probe; zero before one
}

// Relay is one row of the dashboard: an inventory entry, or a relay a host
// reported that the inventory does not list.
type Relay struct {
	Address  string
	Instance string
	Entry    *Entry      // nil when the inventory does not list this relay
	Probe    *RelayProbe // the last probe; nil before one arrived
	// Missing is set when the host answered without this relay.
	Missing bool

	last    metrics.Sample
	Rate    metrics.Rate // live traffic between the last two probes
	HasRate bool

	// counted holds the traffic counters last added to the fleet's
	// traffic total (see Model.count).
	counted       bool
	countedRead   uint64
	countedWrites uint64
}

// IsBridge reports whether the last probe found a bridge, or, before one,
// whether the inventory configures one.
func (r *Relay) IsBridge() bool {
	if r.Probe != nil {
		return r.Probe.Report.Bridge != nil
	}
	return r.Entry != nil && r.Entry.Setup.Relay.Mode == "bridge"
}

// HashedFingerprint is a bridge's hashed fingerprint, the only one that
// may leave the management machine; empty for relays.
func (r *Relay) HashedFingerprint() string {
	if r.Probe == nil || r.Probe.Report.Bridge == nil {
		return ""
	}
	return r.Probe.Report.Bridge.HashedFingerprint
}

// PublicFingerprint identifies the relay in metrics, the web UI and Tor
// Metrics lookups: the fingerprint of a relay, the hashed fingerprint of a
// bridge.
func (r *Relay) PublicFingerprint() string {
	if r.IsBridge() {
		return r.HashedFingerprint()
	}
	return r.Fingerprint()
}

// Nickname is the configured nickname, or the inventory's.
func (r *Relay) Nickname() string {
	if r.Probe != nil && r.Probe.Report.Relay.Nickname != "" {
		return r.Probe.Report.Relay.Nickname
	}
	if r.Entry != nil {
		return r.Entry.Nickname()
	}
	return ""
}

// Fingerprint is the relay's fingerprint when the probe knows it.
func (r *Relay) Fingerprint() string {
	if r.Probe == nil {
		return ""
	}
	return r.Probe.Report.Relay.Fingerprint
}

// Running reports whether the tor service of this relay is active.
func (r *Relay) Running() bool {
	return r.Probe != nil && r.Probe.Report.Service.Active
}

// Warnings are the relay's own status warnings.
func (r *Relay) Warnings() []string {
	if r.Probe == nil {
		return nil
	}
	return r.Probe.Report.Warnings
}

// TorVersion is the relay's tor version, when known.
func (r *Relay) TorVersion() string {
	if r.Probe == nil {
		return ""
	}
	return r.Probe.Report.Tor.Version
}

// Model aggregates host probes and Tor Metrics data for the dashboard and
// for `fleet status`. It is not safe for concurrent use.
type Model struct {
	Inventory Inventory
	hosts     []*HostStatus
	relays    []*Relay

	// Directory holds Tor Metrics details by fingerprint; DirAt is when they
	// were last asked for (zero before the first lookup), DirErr why that
	// lookup failed, and DirOK when a lookup last succeeded.
	Directory map[string]*onionoo.Relay
	DirAt     time.Time
	DirErr    error
	DirOK     time.Time
	// BridgeDirectory holds Tor Metrics bridge details by hashed
	// fingerprint.
	BridgeDirectory map[string]*onionoo.Bridge
	// History holds Tor Metrics traffic history by fingerprint.
	History map[string]*onionoo.Bandwidth
	// PrevFlags are the flags the previous dashboard run saw.
	PrevFlags FlagCache

	// RoundEnd and RoundDuration describe the last full probe round
	// (fleet serve, fleet status); zero before one ended.
	RoundEnd      time.Time
	RoundDuration time.Duration
	rounds        int
	// trafficRead and trafficWritten are the fleet's traffic counters.
	trafficRead, trafficWritten float64
}

// NewModel starts a model with every inventory entry pending.
func NewModel(inv Inventory) *Model {
	m := &Model{Inventory: inv, Directory: map[string]*onionoo.Relay{}, BridgeDirectory: map[string]*onionoo.Bridge{}, History: map[string]*onionoo.Bandwidth{}}
	for _, addr := range inv.Addresses() {
		m.hosts = append(m.hosts, &HostStatus{Address: addr, State: HostPending})
	}
	for i := range inv.Entries {
		e := &inv.Entries[i]
		m.relays = append(m.relays, &Relay{Address: e.Address, Instance: e.Instance, Entry: e})
	}
	return m
}

// Hosts lists the servers in inventory order.
func (m *Model) Hosts() []*HostStatus { return m.hosts }

// Relays lists the relays: inventory order, then relays found on hosts.
func (m *Model) Relays() []*Relay { return m.relays }

// Host returns the status of a server.
func (m *Model) Host(address string) *HostStatus {
	for _, h := range m.hosts {
		if strings.EqualFold(h.Address, address) {
			return h
		}
	}
	return nil
}

// Apply records a host probe: the host's state, and for each relay its
// report and live rate since the previous probe.
func (m *Model) Apply(p HostProbe) {
	h := m.Host(p.Address)
	if h == nil {
		h = &HostStatus{Address: p.Address}
		m.hosts = append(m.hosts, h)
	}
	h.State, h.Detail, h.At, h.Duration = p.State, p.Detail, p.At, p.Duration
	if p.State != HostOK {
		// The last reports stay for the detail view, but live rates are
		// not live any more.
		for _, r := range m.relays {
			if strings.EqualFold(r.Address, p.Address) {
				r.HasRate = false
			}
		}
		return
	}
	h.Version, h.LastOK = p.Probe.Version, p.At
	seen := map[*Relay]bool{}
	for i := range p.Probe.Relays {
		rp := p.Probe.Relays[i]
		r := m.relay(p.Address, rp.Instance())
		if r == nil {
			r = &Relay{Address: p.Address, Instance: rp.Instance()}
			m.relays = append(m.relays, r)
		}
		seen[r] = true
		r.Probe, r.Missing = &rp, false
		s := rp.MetricsSample()
		r.record(s)
		if s != nil {
			m.count(r, *s)
		}
	}
	for _, r := range m.relays {
		if strings.EqualFold(r.Address, p.Address) && !seen[r] {
			r.Missing, r.Probe, r.HasRate = true, nil, false
		}
	}
}

func (m *Model) relay(address, instance string) *Relay {
	for _, r := range m.relays {
		if strings.EqualFold(r.Address, address) && r.Instance == instance {
			return r
		}
	}
	return nil
}

// count adds a relay's traffic to the fleet's traffic counters, which only
// ever grow: in the first probe round every relay adds its counters, later
// each adds its increase since it was last counted (or its counters, when
// they went backwards because tor restarted). A relay first seen after the
// first round starts from its current counters, so its whole past traffic
// does not show up as one burst.
func (m *Model) count(r *Relay, s metrics.Sample) {
	add := func(prev, cur uint64, total *float64) {
		switch {
		case !r.counted:
			if m.rounds == 0 {
				*total += float64(cur)
			}
		case cur < prev:
			*total += float64(cur)
		default:
			*total += float64(cur - prev)
		}
	}
	add(r.countedRead, s.Read, &m.trafficRead)
	add(r.countedWrites, s.Written, &m.trafficWritten)
	r.counted, r.countedRead, r.countedWrites = true, s.Read, s.Written
}

// EndRound records the end of a full probe round of all hosts.
func (m *Model) EndRound(start, end time.Time) {
	m.RoundEnd, m.RoundDuration = end, end.Sub(start)
	m.rounds++
}

// Fresh returns the relay's probe when its host answered the last probe,
// nil otherwise: the report of an unreachable host is out of date.
func (m *Model) Fresh(r *Relay) *RelayProbe {
	if r.Probe == nil || r.Missing {
		return nil
	}
	if h := m.Host(r.Address); h == nil || h.State != HostOK {
		return nil
	}
	return r.Probe
}

// record turns consecutive traffic samples into a live rate. A probe
// without traffic clears it; counters that went backwards (Tor restarted)
// start over.
func (r *Relay) record(t *metrics.Sample) {
	if t == nil {
		r.last, r.HasRate = metrics.Sample{}, false
		return
	}
	s := *t
	switch rate, ok := metrics.Between(r.last, s); {
	case r.last.At.IsZero():
	case ok:
		r.Rate, r.HasRate = rate, true
	case s.Read < r.last.Read || s.Written < r.last.Written:
		r.HasRate = false
	}
	r.last = s
}

// Fingerprints lists the known relay fingerprints, for Tor Metrics
// lookups. Bridges are left out: their fingerprints must never leave the
// management machine (see BridgeFingerprints).
func (m *Model) Fingerprints() []string {
	var out []string
	for _, r := range m.relays {
		if r.IsBridge() {
			continue
		}
		if fp := r.Fingerprint(); fp != "" && !slices.Contains(out, fp) {
			out = append(out, fp)
		}
	}
	return out
}

// BridgeFingerprints lists the hashed fingerprints of the known bridges.
func (m *Model) BridgeFingerprints() []string {
	var out []string
	for _, r := range m.relays {
		if fp := r.HashedFingerprint(); fp != "" && !slices.Contains(out, fp) {
			out = append(out, fp)
		}
	}
	return out
}

// SetDirectory records a bulk Tor Metrics details lookup.
func (m *Model) SetDirectory(details map[string]*onionoo.Relay, err error, at time.Time) {
	m.DirAt, m.DirErr = at, err
	if err == nil {
		m.Directory, m.DirOK = details, at
		if m.Directory == nil {
			m.Directory = map[string]*onionoo.Relay{}
		}
	}
}

// SetBridgeDirectory records a bulk Tor Metrics bridge lookup.
func (m *Model) SetBridgeDirectory(bridges map[string]*onionoo.Bridge) {
	if bridges != nil {
		m.BridgeDirectory = bridges
	}
}

// SetDirectoryResult records a FetchDirectory lookup.
func (m *Model) SetDirectoryResult(d DirectoryResult) {
	m.SetDirectory(d.Details, d.Err, d.At)
	if d.Err == nil {
		m.SetBridgeDirectory(d.Bridges)
		m.SetHistory(d.History)
	}
}

// SetHistory records a bulk Tor Metrics bandwidth lookup.
func (m *Model) SetHistory(history map[string]*onionoo.Bandwidth) {
	if history != nil {
		m.History = history
	}
}

// DirectoryOf returns the Tor Metrics details of a relay, or nil (always
// for bridges; see BridgeDirectoryOf).
func (m *Model) DirectoryOf(r *Relay) *onionoo.Relay {
	if r.IsBridge() {
		return nil
	}
	if fp := r.Fingerprint(); fp != "" {
		return m.Directory[fp]
	}
	return nil
}

// BridgeDirectoryOf returns the Tor Metrics details of a bridge, or nil.
func (m *Model) BridgeDirectoryOf(r *Relay) *onionoo.Bridge {
	if fp := r.HashedFingerprint(); fp != "" {
		return m.BridgeDirectory[fp]
	}
	return nil
}

// Published reports whether Tor Metrics lists the relay or bridge, and
// whether that is known at all (a lookup succeeded and the fingerprint is
// known).
func (m *Model) Published(r *Relay) (published, known bool) {
	if m.DirOK.IsZero() || r.PublicFingerprint() == "" {
		return false, false
	}
	if r.IsBridge() {
		return m.BridgeDirectoryOf(r) != nil, true
	}
	return m.DirectoryOf(r) != nil, true
}

// Roles of a relay in the fleet metrics.
const (
	RoleGuard  = "guard"
	RoleExit   = "exit"
	RoleMiddle = "middle"
	RoleBridge = "bridge"
)

// Role classifies the relay: bridge; exit with the Exit flag; guard with
// the Guard flag; middle otherwise. A relay with both flags counts as an
// exit. Before Tor Metrics lists a relay, the configuration decides
// (ExitRelay 1 is an exit, everything else a middle).
func (m *Model) Role(r *Relay) string {
	if r.IsBridge() {
		return RoleBridge
	}
	if d := m.DirectoryOf(r); d != nil {
		switch {
		case slices.Contains(d.Flags, "Exit"):
			return RoleExit
		case slices.Contains(d.Flags, "Guard"):
			return RoleGuard
		}
		return RoleMiddle
	}
	switch {
	case r.Probe != nil && r.Probe.Report.Relay.Exit:
		return RoleExit
	case r.Probe == nil && r.Entry != nil && r.Entry.Setup.Relay.Mode == "exit":
		return RoleExit
	}
	return RoleMiddle
}

// Totals are the fleet-wide numbers of the dashboard header.
type Totals struct {
	Relays, Running            int
	Hosts, Unreachable, TooOld int // TooOld also counts hosts without tor-relay-setup
	HostsUp                    int // hosts whose last probe answered
	Published                  int // relays and bridges Tor Metrics lists
	ConsensusWeight            int64
	WeightFraction             float64 // share of the network's consensus weight
	Guard, Middle, Exit        float64 // summed selection probabilities
	Read, Written              float64 // live bytes per second
	Advertised                 int64   // bytes per second, bridges included
	Observed                   int64   // bytes per second
	// Connections sums the open OR connections of the relays whose
	// MetricsPort answered the last probe (Sampled of them).
	Connections, Sampled int
	// TrafficRead and TrafficWritten are the fleet's traffic counters in
	// bytes: they only grow (see Model.count).
	TrafficRead, TrafficWritten float64
	// History is the fleet's daily traffic (read + written, bytes per
	// second), oldest first; HistoryFirst is its first day.
	History               []float64
	HistoryFirst          time.Time
	HistoryIn, HistoryOut float64 // bytes over the history
}

// Totals sums the fleet.
func (m *Model) Totals() Totals {
	var t Totals
	t.Hosts = len(m.hosts)
	t.TrafficRead, t.TrafficWritten = m.trafficRead, m.trafficWritten
	for _, h := range m.hosts {
		switch h.State {
		case HostOK:
			t.HostsUp++
		case HostUnreachable, HostFailed:
			t.Unreachable++
		case HostTooOld, HostMissing:
			t.TooOld++
		}
	}
	var histories []*onionoo.Bandwidth
	for _, r := range m.relays {
		t.Relays++
		fresh := m.Fresh(r)
		if fresh != nil && fresh.Report.Service.Active {
			t.Running++
		}
		if fresh != nil {
			if s := fresh.MetricsSample(); s != nil {
				t.Connections += s.Connections
				t.Sampled++
			}
		}
		if r.HasRate {
			t.Read += r.Rate.Read
			t.Written += r.Rate.Written
		}
		if d := m.DirectoryOf(r); d != nil {
			t.Published++
			t.ConsensusWeight += d.ConsensusWeight
			t.WeightFraction += d.ConsensusWeightFraction
			t.Guard += d.GuardProbability
			t.Middle += d.MiddleProbability
			t.Exit += d.ExitProbability
			t.Advertised += d.AdvertisedBandwidth
			t.Observed += d.ObservedBandwidth
		}
		if b := m.BridgeDirectoryOf(r); b != nil {
			t.Published++
			t.Advertised += b.AdvertisedBandwidth
		}
		if fp := r.Fingerprint(); fp != "" && m.History[fp] != nil {
			histories = append(histories, m.History[fp])
		}
	}
	t.History, t.HistoryFirst, t.HistoryIn, t.HistoryOut = SumHistory(histories)
	return t
}

// day is one calendar day of history in UTC.
const day = 24 * time.Hour

// SumHistory adds traffic histories up by date: every data point counts on
// its UTC day, so relays whose graphs start on different days line up. It
// returns read+written bytes per second per day from the first to the last
// day (NaN for days without data), the first day, and the bytes read and
// written in total.
func SumHistory(hs []*onionoo.Bandwidth) (daily []float64, first time.Time, in, out float64) {
	sums := map[time.Time]float64{}
	add := func(h onionoo.History, total *float64) {
		for i, v := range h.Values {
			if math.IsNaN(v) {
				continue
			}
			d := h.First.Add(time.Duration(i) * h.Interval).UTC().Truncate(day)
			sums[d] += v
			*total += v * h.Interval.Seconds()
		}
	}
	for _, h := range hs {
		add(h.Read, &in)
		add(h.Written, &out)
	}
	if len(sums) == 0 {
		return nil, time.Time{}, in, out
	}
	days := make([]time.Time, 0, len(sums))
	for d := range sums {
		days = append(days, d)
	}
	sort.Slice(days, func(i, j int) bool { return days[i].Before(days[j]) })
	first, last := days[0], days[len(days)-1]
	n := int(last.Sub(first)/day) + 1
	daily = make([]float64, n)
	for i := range daily {
		v, ok := sums[first.Add(time.Duration(i)*day)]
		if !ok {
			v = math.NaN()
		}
		daily[i] = v
	}
	return daily, first, in, out
}

// Level ranks an attention item.
type Level int

// Levels, most urgent first.
const (
	Bad Level = iota
	Warn
)

// Item is one line of the "Needs attention" panel.
type Item struct {
	Level Level  `json:"-"`
	Kind  string `json:"kind"`
	Text  string `json:"text"`
}

// trackedFlags are the flags whose loss is reported.
var trackedFlags = []string{"Guard", "Stable", "Fast"}

// Attention runs the fleet checks: hosts that cannot be probed, relays
// that are down or unpublished, family problems, version drift, and flags
// lost since the previous dashboard run.
func (m *Model) Attention() []Item {
	var items []Item
	add := func(level Level, kind, format string, a ...any) {
		items = append(items, Item{Level: level, Kind: kind, Text: fmt.Sprintf(format, a...)})
	}
	for _, h := range m.hosts {
		switch h.State {
		case HostUnreachable:
			add(Bad, "unreachable", "%s: unreachable over ssh%s", h.Address, detail(h.Detail))
		case HostFailed:
			add(Bad, "probe-failed", "%s: probe failed%s", h.Address, detail(h.Detail))
		case HostTooOld:
			add(Warn, "too-old", "%s: tor-relay-setup too old on this host — run self-update", h.Address)
		case HostMissing:
			add(Warn, "not-installed", "%s: tor-relay-setup is not installed on this host (install.sh)", h.Address)
		}
	}
	dirOK := !m.DirAt.IsZero() && m.DirErr == nil
	for _, r := range m.relays {
		name := m.label(r)
		switch {
		case r.Missing:
			add(Bad, "missing", "%s: not found on the host", name)
			continue
		case r.Probe == nil:
			continue
		}
		rep := r.Probe.Report
		switch {
		case !rep.Relay.Configured:
			add(Bad, "not-configured", "%s: no relay is configured on the host", name)
		case !rep.Service.Active:
			add(Bad, "not-running", "%s: %s is not running", name, rep.Service.Unit)
		}
		if published, known := m.Published(r); dirOK && known {
			running := false
			if d := m.DirectoryOf(r); d != nil {
				running = d.Running
			}
			if b := m.BridgeDirectoryOf(r); b != nil {
				running = b.Running
			}
			switch {
			case !published:
				add(Warn, "unpublished", "%s: not in Tor Metrics (new relays appear after about 3 hours)", name)
			case !running:
				add(Bad, "directory-down", "%s: Tor Metrics reports it as not running", name)
			}
		}
		for _, id := range rep.Family.MissingKeys {
			add(Bad, "family-key", "%s: no family key installed for FamilyId %s", name, shortID(id))
		}
		if rep.Relay.Configured && rep.Family.LegacyCount > 0 {
			add(Warn, "legacy-myfamily", "%s: legacy MyFamily (%d fingerprints); Tor 0.4.9 families use FamilyId", name, rep.Family.LegacyCount)
		}
		for _, w := range rep.Warnings {
			if !coveredWarning(w) {
				add(Warn, "relay-warning", "%s: %s", name, w)
			}
		}
	}
	items = append(items, m.familyDrift()...)
	if v := m.versionDrift(); v != "" {
		add(Warn, "version-drift", "tor versions differ: %s", v)
	}
	if dirOK {
		for _, r := range m.relays {
			if lost := m.LostFlags(r); len(lost) > 0 {
				add(Warn, "lost-flags", "%s lost %s since the last dashboard run", m.label(r), strings.Join(lost, ", "))
			}
		}
	}
	return items
}

// coveredWarning reports whether a relay's own status warning is already
// one of the fleet checks (service down, family key, legacy MyFamily).
func coveredWarning(w string) bool {
	return strings.HasSuffix(w, " is not running") ||
		strings.HasPrefix(w, "no family key installed") ||
		strings.HasPrefix(w, "only a legacy MyFamily")
}

func detail(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

// label names a relay in messages: its nickname and, when the server runs
// more than one relay or the nickname is unknown, the server.
func (m *Model) label(r *Relay) string {
	nick := r.Nickname()
	if nick == "" {
		nick = HostOf(r.Address)
	}
	if r.Instance != DefaultInstance {
		return nick + " (" + HostOf(r.Address) + "/" + r.Instance + ")"
	}
	return nick
}

// familySets returns each configured relay's FamilyId set (sorted, joined)
// and the most common set; ties go to the set that sorts first. Bridges
// are left out: a bridge must not be in a relay family. distinct is the
// number of different sets.
func (m *Model) familySets() (sets map[*Relay]string, majority string, distinct int) {
	counts := map[string]int{}
	sets = map[*Relay]string{}
	for _, r := range m.relays {
		if r.Probe == nil || !r.Probe.Report.Relay.Configured || r.IsBridge() {
			continue
		}
		ids := slices.Clone(r.Probe.Report.Family.IDs)
		slices.Sort(ids)
		key := strings.Join(ids, " ")
		sets[r] = key
		counts[key]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return cmp.Or(-cmp.Compare(counts[a], counts[b]), cmp.Compare(a, b)) })
	if len(keys) > 0 {
		majority = keys[0]
	}
	return sets, majority, len(keys)
}

// FamilyConsistent reports whether the relay's FamilyId set matches the
// fleet's most common set, and whether that is known (bridges and relays
// without a report have none).
func (m *Model) FamilyConsistent(r *Relay) (consistent, known bool) {
	sets, majority, _ := m.familySets()
	key, ok := sets[r]
	return ok && key == majority, ok
}

// familyDrift flags relays whose FamilyId set differs from the most common
// set in the fleet.
func (m *Model) familyDrift() []Item {
	sets, majority, distinct := m.familySets()
	if distinct < 2 {
		return nil
	}
	var items []Item
	for _, r := range m.relays {
		key, ok := sets[r]
		if !ok || key == majority {
			continue
		}
		text := m.label(r) + ": FamilyId set differs from the rest of the fleet"
		if key == "" {
			text = m.label(r) + ": not in the fleet's family (no FamilyId)"
		}
		items = append(items, Item{Level: Warn, Kind: "family-drift", Text: text})
	}
	return items
}

// versionDrift lists tor versions with counts when they differ, most
// common first: "0.4.9.3 ×5, 0.4.8.12 ×1".
func (m *Model) versionDrift() string {
	counts := m.TorVersions()
	if len(counts) < 2 {
		return ""
	}
	parts := make([]string, len(counts))
	for i, c := range counts {
		parts[i] = fmt.Sprintf("%s ×%d", c.Version, c.Count)
	}
	return strings.Join(parts, ", ")
}

// VersionCount is how many relays run one tor version.
type VersionCount struct {
	Version string
	Count   int
}

// TorVersions counts the tor versions in the fleet, most common first.
func (m *Model) TorVersions() []VersionCount {
	counts := map[string]int{}
	for _, r := range m.relays {
		if v := r.TorVersion(); v != "" {
			counts[v]++
		}
	}
	out := make([]VersionCount, 0, len(counts))
	for v, n := range counts {
		out = append(out, VersionCount{v, n})
	}
	slices.SortFunc(out, func(a, b VersionCount) int {
		return cmp.Or(-cmp.Compare(a.Count, b.Count), cmp.Compare(a.Version, b.Version))
	})
	return out
}

// LostFlags returns the tracked flags (Guard, Stable, Fast) the relay had
// in the previous run's cache but no longer has in Tor Metrics.
func (m *Model) LostFlags(r *Relay) []string {
	d := m.DirectoryOf(r)
	if d == nil {
		return nil
	}
	var lost []string
	for _, f := range m.PrevFlags.Flags[r.Fingerprint()] {
		if slices.Contains(trackedFlags, f) && !slices.Contains(d.Flags, f) {
			lost = append(lost, f)
		}
	}
	return lost
}

// flagOrder and flagLetters abbreviate relay flags, most telling first.
var (
	flagOrder   = []string{"Guard", "Stable", "Fast", "Exit", "HSDir", "Valid", "Running", "V2Dir", "BadExit", "MiddleOnly", "Authority", "StaleDesc", "NoEdConsensus"}
	flagLetters = map[string]string{
		"Guard": "G", "Stable": "S", "Fast": "F", "Exit": "E", "HSDir": "H", "Valid": "V", "Running": "R",
		"V2Dir": "D", "BadExit": "B", "MiddleOnly": "M", "Authority": "A", "StaleDesc": "s", "NoEdConsensus": "N",
	}
)

// AbbrevFlags shortens relay flags to letters in a fixed order, e.g.
// "GSFVR"; unknown flags are left out.
func AbbrevFlags(flags []string) string {
	var b strings.Builder
	for _, f := range flagOrder {
		if slices.Contains(flags, f) {
			b.WriteString(flagLetters[f])
		}
	}
	return b.String()
}
