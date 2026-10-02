// Package metrics reads Tor's MetricsPort (Prometheus text format): relay
// traffic and open OR connections for the console, and the load counters
// behind Tor's overload signals (see overload.go). accounting.go reads
// AccountingMax usage from Tor's state file, because the MetricsPort has no
// accounting series.
package metrics

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxBody = 4 << 20 // 4 MiB; a relay's metrics page is about 40 KiB

var defaultHTTP = &http.Client{Timeout: 3 * time.Second}

// Sample is one scrape of the MetricsPort. The JSON form is persisted as a
// baseline between runs (see AssessOverload).
type Sample struct {
	At          time.Time `json:"at"`
	Read        uint64    `json:"read"`        // tor_relay_traffic_bytes{direction="read"}
	Written     uint64    `json:"written"`     // tor_relay_traffic_bytes{direction="written"}
	Connections int       `json:"connections"` // open OR connections, both directions and families
	Load        Load      `json:"load"`
}

// Load holds the tor_relay_load_* series (tor 0.4.7 and later). Counters
// count since tor started; the socket values are gauges.
type Load struct {
	Seen bool `json:"seen"` // the page had at least one tor_relay_load_* series

	// tor_relay_load_onionskins_total{type,action="processed"|"dropped"}
	OnionskinsProcessed Onionskins `json:"onionskins_processed"`
	OnionskinsDropped   Onionskins `json:"onionskins_dropped"`

	// tor_relay_load_oom_bytes_total{subsys}: bytes the out-of-memory
	// handler freed after MaxMemInQueues was reached.
	OOMBytes OOMBytes `json:"oom_bytes"`

	// tor_relay_load_tcp_exhaustion_total: connections that failed because
	// the local TCP port range ran out.
	TCPExhaustion uint64 `json:"tcp_exhaustion"`

	// tor_relay_load_global_rate_limit_reached_total{side}: how often the
	// global BandwidthRate/BandwidthBurst token bucket ran empty.
	RateLimitRead  uint64 `json:"rate_limit_read"`
	RateLimitWrite uint64 `json:"rate_limit_write"`

	// tor_relay_load_socket_total{state="opened"} and the unlabelled
	// tor_relay_load_socket_total, the most sockets tor allows itself.
	SocketsOpen  uint64 `json:"sockets_open"`
	SocketsLimit uint64 `json:"sockets_limit"`
}

// Onionskins counts circuit-creation handshakes by type.
type Onionskins struct {
	TAP    uint64 `json:"tap"`
	Fast   uint64 `json:"fast"`
	Ntor   uint64 `json:"ntor"`
	NtorV3 uint64 `json:"ntor_v3"`
}

// NtorTotal is ntor plus ntor_v3, the handshakes behind tor's onionskin
// overload signal.
func (o Onionskins) NtorTotal() uint64 { return o.Ntor + o.NtorV3 }

// OOMBytes is the memory the OOM handler freed, by subsystem.
type OOMBytes struct {
	Cell  uint64 `json:"cell"`
	DNS   uint64 `json:"dns"`
	GeoIP uint64 `json:"geoip"`
	HSDir uint64 `json:"hsdir"`
}

// Total is the sum over all subsystems.
func (o OOMBytes) Total() uint64 { return o.Cell + o.DNS + o.GeoIP + o.HSDir }

// Rate is the traffic between two samples, in bytes per second.
type Rate struct {
	Read, Written float64
}

// Total is read plus written bytes per second.
func (r Rate) Total() float64 { return r.Read + r.Written }

// Between returns the rate from prev to cur. It is false when the samples
// are not in order or the counters went backwards (Tor restarted).
func Between(prev, cur Sample) (Rate, bool) {
	secs := cur.At.Sub(prev.At).Seconds()
	if secs <= 0 || cur.Read < prev.Read || cur.Written < prev.Written {
		return Rate{}, false
	}
	return Rate{
		Read:    float64(cur.Read-prev.Read) / secs,
		Written: float64(cur.Written-prev.Written) / secs,
	}, true
}

// URL returns the metrics URL for a MetricsPort value such as
// "127.0.0.1:9035", "[::1]:9035", or a bare port (Tor's default address is
// 127.0.0.1). A trailing torrc flag after the address is ignored.
func URL(metricsPort string) (string, error) {
	addr, _, _ := strings.Cut(strings.TrimSpace(metricsPort), " ")
	if addr == "" {
		return "", fmt.Errorf("MetricsPort is not set")
	}
	if _, err := strconv.Atoi(addr); err == nil {
		addr = "127.0.0.1:" + addr
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", fmt.Errorf("invalid MetricsPort %q: %w", metricsPort, err)
	}
	return "http://" + addr + "/metrics", nil
}

// Scrape fetches and parses the MetricsPort at metricsPort. A nil client
// uses a 3-second timeout.
func Scrape(ctx context.Context, client *http.Client, metricsPort string) (Sample, error) {
	u, err := URL(metricsPort)
	if err != nil {
		return Sample{}, err
	}
	if client == nil {
		client = defaultHTTP
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Sample{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Sample{}, fmt.Errorf("MetricsPort: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Sample{}, fmt.Errorf("MetricsPort returned %s", resp.Status)
	}
	s, err := Parse(io.LimitReader(resp.Body, maxBody))
	s.At = time.Now()
	return s, err
}

// Parse reads the counters from a Prometheus text exposition. It fails when
// the page has no traffic counter, which means it is not Tor's. Sample.At
// is left zero; Scrape sets it.
func Parse(r io.Reader) (Sample, error) {
	var s Sample
	found := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name, labels, value, ok := splitSample(line)
		if !ok {
			continue
		}
		switch name {
		case "tor_relay_traffic_bytes":
			switch labels["direction"] {
			case "read":
				s.Read, found = uint64(value), true
			case "written":
				s.Written, found = uint64(value), true
			}
		case "tor_relay_connections":
			if labels["type"] == "OR" && labels["state"] == "opened" {
				s.Connections += int(value)
			}
		default:
			if strings.HasPrefix(name, "tor_relay_load_") {
				s.Load.Seen = true
				s.Load.add(name, labels, uint64(value))
			}
		}
	}
	if err := sc.Err(); err != nil {
		return s, fmt.Errorf("MetricsPort: %w", err)
	}
	if !found {
		return s, fmt.Errorf("MetricsPort: no tor_relay_traffic_bytes counter")
	}
	return s, nil
}

// add records one tor_relay_load_* sample. Unknown names and label values
// (a future handshake type, say) are ignored.
func (l *Load) add(name string, labels map[string]string, v uint64) {
	switch name {
	case "tor_relay_load_onionskins_total":
		var o *Onionskins
		switch labels["action"] {
		case "processed":
			o = &l.OnionskinsProcessed
		case "dropped":
			o = &l.OnionskinsDropped
		default:
			return
		}
		switch labels["type"] {
		case "tap":
			o.TAP = v
		case "fast":
			o.Fast = v
		case "ntor":
			o.Ntor = v
		case "ntor_v3":
			o.NtorV3 = v
		}
	case "tor_relay_load_oom_bytes_total":
		switch labels["subsys"] {
		case "cell":
			l.OOMBytes.Cell = v
		case "dns":
			l.OOMBytes.DNS = v
		case "geoip":
			l.OOMBytes.GeoIP = v
		case "hsdir":
			l.OOMBytes.HSDir = v
		}
	case "tor_relay_load_tcp_exhaustion_total":
		l.TCPExhaustion = v
	case "tor_relay_load_global_rate_limit_reached_total":
		switch labels["side"] {
		case "read":
			l.RateLimitRead = v
		case "write":
			l.RateLimitWrite = v
		}
	case "tor_relay_load_socket_total":
		switch labels["state"] {
		case "opened":
			l.SocketsOpen = v
		case "":
			l.SocketsLimit = v
		}
	}
}

// splitSample parses `name{k="v",...} value [timestamp]`.
func splitSample(line string) (name string, labels map[string]string, value float64, ok bool) {
	var rest string
	if i := strings.IndexByte(line, '{'); i >= 0 {
		j := strings.LastIndexByte(line, '}')
		if j < i {
			return "", nil, 0, false
		}
		name, rest = line[:i], line[j+1:]
		labels = parseLabels(line[i+1 : j])
	} else {
		var found bool
		name, rest, found = strings.Cut(line, " ")
		if !found {
			return "", nil, 0, false
		}
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", nil, 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || v < 0 {
		return "", nil, 0, false
	}
	return name, labels, v, true
}

func parseLabels(s string) map[string]string {
	out := map[string]string{}
	for s != "" {
		key, rest, ok := strings.Cut(s, "=")
		if !ok || !strings.HasPrefix(rest, `"`) {
			return out
		}
		rest = rest[1:]
		var val strings.Builder
		i := 0
		for ; i < len(rest); i++ {
			c := rest[i]
			if c == '\\' && i+1 < len(rest) {
				i++
				val.WriteByte(rest[i])
				continue
			}
			if c == '"' {
				break
			}
			val.WriteByte(c)
		}
		out[strings.TrimSpace(key)] = val.String()
		if i >= len(rest) {
			return out
		}
		s = strings.TrimLeft(rest[i+1:], ", ")
	}
	return out
}
