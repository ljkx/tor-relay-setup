// Package metrics reads the few counters the console shows from Tor's
// MetricsPort (Prometheus text format): relay traffic and open OR
// connections.
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

// Sample is one scrape of the MetricsPort.
type Sample struct {
	At          time.Time
	Read        uint64 // tor_relay_traffic_bytes{direction="read"}
	Written     uint64 // tor_relay_traffic_bytes{direction="written"}
	Connections int    // open OR connections, both directions and families
}

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
// the page has no traffic counter, which means it is not Tor's.
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
