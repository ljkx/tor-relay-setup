package fleet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

// Healthy reports whether no check needs attention.
func (m *Model) Healthy() bool { return len(m.Attention()) == 0 }

// WriteText prints the fleet for `fleet status` and `fleet --plain`.
func (m *Model) WriteText(w io.Writer) error {
	t := m.Totals()
	var b bytes.Buffer
	fmt.Fprintf(&b, "Relays       %d of %d running on %d hosts", t.Running, t.Relays, t.Hosts)
	if t.Unreachable > 0 {
		fmt.Fprintf(&b, ", %d unreachable", t.Unreachable)
	}
	if t.TooOld > 0 {
		fmt.Fprintf(&b, ", %d without fleet-probe", t.TooOld)
	}
	b.WriteString("\n")
	switch {
	case m.DirErr != nil:
		fmt.Fprintf(&b, "Tor Metrics  ? %v\n", m.DirErr)
	case !m.DirAt.IsZero():
		fmt.Fprintf(&b, "Weight       %d (%s of the network), %d of %d relays published\n", t.ConsensusWeight, Percent(t.WeightFraction), t.Published, t.Relays)
		fmt.Fprintf(&b, "Selection    guard %s · middle %s · exit %s\n", Percent(t.Guard), Percent(t.Middle), Percent(t.Exit))
		fmt.Fprintf(&b, "Advertised   %s\n", Rate(float64(t.Advertised)))
	}
	if t.Read+t.Written > 0 {
		fmt.Fprintf(&b, "Live         ↓ %s  ↑ %s\n", Rate(t.Read), Rate(t.Written))
	}
	if len(t.History) > 0 {
		fmt.Fprintf(&b, "%-12s in %s · out %s\n", fmt.Sprintf("%d days", len(t.History)), Bytes(t.HistoryIn), Bytes(t.HistoryOut))
	}
	b.WriteString("\n")
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tNICKNAME\tINSTANCE\tSTATE\tFLAGS\tTOR\tWEIGHT\tWARNINGS")
	for _, r := range m.relays {
		flags, weight := "-", "-"
		if d := m.DirectoryOf(r); d != nil {
			flags, weight = AbbrevFlags(d.Flags), strconv.FormatInt(d.ConsensusWeight, 10)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", HostOf(r.Address), dash(r.Nickname()), r.Instance,
			m.RelayState(r), dash(flags), dash(r.TorVersion()), weight, len(r.Warnings()))
	}
	_ = tw.Flush()
	if items := m.Attention(); len(items) > 0 {
		b.WriteString("\nNeeds attention:\n")
		for _, it := range items {
			b.WriteString("! " + it.Text + "\n")
		}
	}
	_, err := w.Write(b.Bytes())
	return err
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// RelayState is a one-word state for a relay row.
func (m *Model) RelayState(r *Relay) string {
	if h := m.Host(r.Address); h != nil && h.State != HostOK {
		return string(h.State)
	}
	switch {
	case r.Missing:
		return "missing"
	case r.Probe == nil:
		return "pending"
	case !r.Probe.Report.Relay.Configured:
		return "unconfigured"
	case !r.Probe.Report.Service.Active:
		return "stopped"
	}
	return "running"
}

// Percent formats a 0–1 fraction as a percentage with useful precision.
func Percent(f float64) string {
	p := f * 100
	switch {
	case p == 0:
		return "0%"
	case p < 0.01:
		return fmt.Sprintf("%.4f%%", p)
	case p < 1:
		return fmt.Sprintf("%.3f%%", p)
	}
	return fmt.Sprintf("%.2f%%", p)
}

// Rate formats bytes per second as bits per second.
func Rate(bytesPerSecond float64) string {
	bits := bytesPerSecond * 8
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.2f Gbit/s", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.1f Mbit/s", bits/1e6)
	case bits >= 1e3:
		return fmt.Sprintf("%.0f kbit/s", bits/1e3)
	}
	return fmt.Sprintf("%.0f bit/s", bits)
}

// Bytes formats a byte count with decimal units, as providers bill.
func Bytes(n float64) string {
	for _, u := range []struct {
		div  float64
		unit string
	}{{1e15, "PB"}, {1e12, "TB"}, {1e9, "GB"}, {1e6, "MB"}, {1e3, "kB"}} {
		if n >= u.div {
			return fmt.Sprintf("%.1f %s", n/u.div, u.unit)
		}
	}
	return fmt.Sprintf("%.0f B", n)
}

// jsonDoc is `fleet status --format json`.
type jsonDoc struct {
	CollectedAt time.Time   `json:"collected_at"`
	Totals      jsonTotals  `json:"totals"`
	Hosts       []jsonHost  `json:"hosts"`
	Relays      []jsonRelay `json:"relays"`
	Attention   []Item      `json:"attention"`
}

type jsonTotals struct {
	Relays             int       `json:"relays"`
	Running            int       `json:"running"`
	Hosts              int       `json:"hosts"`
	Unreachable        int       `json:"hosts_unreachable"`
	Outdated           int       `json:"hosts_without_probe"`
	Published          int       `json:"published"`
	ConsensusWeight    int64     `json:"consensus_weight"`
	WeightFraction     float64   `json:"consensus_weight_fraction"`
	Guard              float64   `json:"guard_probability"`
	Middle             float64   `json:"middle_probability"`
	Exit               float64   `json:"exit_probability"`
	Advertised         int64     `json:"advertised_bandwidth"`
	HistoryDaily       []float64 `json:"history_daily_bytes_per_second,omitempty"`
	HistoryFirst       string    `json:"history_first_day,omitempty"`
	HistoryReadBytes   float64   `json:"history_read_bytes"`
	HistoryWriteBytes  float64   `json:"history_written_bytes"`
	LiveReadPerSecond  float64   `json:"live_read_bytes_per_second"`
	LiveWritePerSecond float64   `json:"live_written_bytes_per_second"`
}

type jsonHost struct {
	Address string    `json:"address"`
	State   HostState `json:"state"`
	Detail  string    `json:"detail,omitempty"`
	Version string    `json:"version,omitempty"`
}

type jsonRelay struct {
	Address   string         `json:"address"`
	Instance  string         `json:"instance"`
	Nickname  string         `json:"nickname"`
	State     string         `json:"state"`
	InFleet   bool           `json:"in_inventory"`
	Report    *status.Report `json:"report,omitempty"`
	Traffic   *Traffic       `json:"traffic,omitempty"`
	Directory *onionoo.Relay `json:"directory,omitempty"`
	LostFlags []string       `json:"lost_flags,omitempty"`
}

// WriteJSON prints the fleet as one JSON document.
func (m *Model) WriteJSON(w io.Writer, now time.Time) error {
	t := m.Totals()
	doc := jsonDoc{
		CollectedAt: now.UTC(),
		Totals: jsonTotals{
			Relays: t.Relays, Running: t.Running, Hosts: t.Hosts, Unreachable: t.Unreachable, Outdated: t.TooOld,
			Published: t.Published, ConsensusWeight: t.ConsensusWeight, WeightFraction: t.WeightFraction,
			Guard: t.Guard, Middle: t.Middle, Exit: t.Exit, Advertised: t.Advertised,
			HistoryReadBytes: t.HistoryIn, HistoryWriteBytes: t.HistoryOut,
			LiveReadPerSecond: t.Read, LiveWritePerSecond: t.Written,
		},
		Attention: m.Attention(),
	}
	for _, v := range t.History {
		if math.IsNaN(v) {
			v = 0
		}
		doc.Totals.HistoryDaily = append(doc.Totals.HistoryDaily, v)
	}
	if len(t.History) > 0 {
		doc.Totals.HistoryFirst = t.HistoryFirst.Format(time.DateOnly)
	}
	if doc.Attention == nil {
		doc.Attention = []Item{}
	}
	for _, h := range m.hosts {
		doc.Hosts = append(doc.Hosts, jsonHost{Address: h.Address, State: h.State, Detail: h.Detail, Version: h.Version})
	}
	for _, r := range m.relays {
		jr := jsonRelay{Address: r.Address, Instance: r.Instance, Nickname: r.Nickname(), State: m.RelayState(r),
			InFleet: r.Entry != nil, Directory: m.DirectoryOf(r), LostFlags: m.LostFlags(r)}
		if r.Probe != nil {
			jr.Report, jr.Traffic = &r.Probe.Report, r.Probe.Traffic
		}
		doc.Relays = append(doc.Relays, jr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
