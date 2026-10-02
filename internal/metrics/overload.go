package metrics

import (
	"fmt"
	"time"
)

// Overload signals. Tor publishes three "overload" lines in its descriptors
// (dir-spec; proposal 328), and Relay Search marks a relay as overloaded
// from the first one only:
//
//   - overload-general (server descriptor, kept 72 h after the last event):
//     the OOM handler ran because MaxMemInQueues was reached, a connection
//     failed because the local TCP port range ran out, or at least 1% of
//     ntor/ntor_v3 onionskins were dropped over a 6-hour assessment period
//     with at least 1000 requests (src/feature/stats/rephist.c).
//   - overload-ratelimits (extra-info, kept 24 h): the global
//     BandwidthRate/BandwidthBurst token bucket ran empty
//     (src/core/mainloop/connection.c). RelayBandwidthRate has its own
//     bucket and does not count.
//   - overload-fd-exhausted (extra-info, kept 72 h): opening a socket failed
//     because tor ran out of file descriptors.
//
// The MetricsPort exposes a counter for each cause except the last, for
// which tor_relay_load_socket_total (open sockets against tor's limit) is
// the closest gauge. See https://support.torproject.org/relays/performance/overloaded/
type Signal string

const (
	SignalOnionskinsDropped Signal = "onionskins_dropped"
	SignalOOM               Signal = "oom"
	SignalTCPExhaustion     Signal = "tcp_exhaustion"
	SignalSocketsExhausted  Signal = "sockets_exhausted"
	SignalRateLimited       Signal = "rate_limited"
)

// Signals lists every signal in a fixed order.
var Signals = []Signal{SignalOnionskinsDropped, SignalOOM, SignalTCPExhaustion, SignalSocketsExhausted, SignalRateLimited}

// Descriptor lines a signal maps to.
const (
	LineGeneral     = "overload-general"
	LineRateLimits  = "overload-ratelimits"
	LineFDExhausted = "overload-fd-exhausted"
)

// Line returns the descriptor line the signal feeds.
func (s Signal) Line() string {
	switch s {
	case SignalRateLimited:
		return LineRateLimits
	case SignalSocketsExhausted:
		return LineFDExhausted
	default:
		return LineGeneral
	}
}

const (
	// ntorDropFraction and ntorMinRequests are tor's default consensus
	// parameters for the onionskin overload signal
	// (overload_onionskin_ntor_scale_percent = 1%, at least 1000 requests).
	ntorDropFraction = 0.01
	ntorMinRequests  = 1000
	// SocketsNearPercent is the share of tor's socket limit at which open
	// sockets count as nearly exhausted.
	SocketsNearPercent = 90
)

// Finding is one signal that fired in the assessed window.
type Finding struct {
	Signal Signal `json:"signal"`
	Line   string `json:"line"` // descriptor line, see Signal.Line
	// Count is the counter increase in the window: dropped onionskins, OOM
	// bytes freed, TCP exhaustion events, or rate-limit hits. For
	// SignalSocketsExhausted it is the number of open sockets.
	Count uint64 `json:"count"`
	// Published is true when tor itself would publish Line for this (for
	// onionskins: 1% of at least 1000 ntor requests; for sockets: the limit
	// is reached). Relay Search shows overload-general lines only.
	Published   bool   `json:"published"`
	Summary     string `json:"summary"`     // what happened, with numbers
	Explanation string `json:"explanation"` // what it means
	Remedy      string `json:"remedy"`      // what Tor recommends
}

// Overload is the assessment of one window between two samples.
type Overload struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Supported is false when the MetricsPort has no tor_relay_load_*
	// series (tor before 0.4.7); nothing was assessed.
	Supported bool `json:"supported"`
	// Baseline is true when an earlier sample was compared; without one
	// only the socket gauge is assessed.
	Baseline bool `json:"baseline"`
	// Restarted is true when counters went backwards: tor restarted inside
	// the window, so its counters were taken as increases since the restart.
	Restarted bool      `json:"restarted"`
	Findings  []Finding `json:"findings,omitempty"`
}

// Fired reports whether sig fired.
func (o Overload) Fired(sig Signal) bool {
	_, ok := o.Find(sig)
	return ok
}

// Find returns the finding for sig.
func (o Overload) Find(sig Signal) (Finding, bool) {
	for _, f := range o.Findings {
		if f.Signal == sig {
			return f, true
		}
	}
	return Finding{}, false
}

// General reports whether tor would publish overload-general for this
// window, which makes Relay Search show the relay as overloaded.
func (o Overload) General() bool {
	for _, f := range o.Findings {
		if f.Line == LineGeneral && f.Published {
			return true
		}
	}
	return false
}

// Window is the assessed duration, zero without a baseline.
func (o Overload) Window() time.Duration {
	if !o.Baseline {
		return 0
	}
	return o.To.Sub(o.From)
}

// AssessOverload compares two samples of the same relay, normally the one
// persisted by the previous run and a fresh scrape. prev may be the zero
// Sample when there is no baseline yet.
func AssessOverload(prev, cur Sample) Overload {
	o := Overload{From: prev.At, To: cur.At, Supported: cur.Load.Seen}
	if !o.Supported {
		return o
	}
	o.Baseline = !prev.At.IsZero() && prev.Load.Seen && prev.At.Before(cur.At)
	p, c := prev.Load, cur.Load
	if o.Baseline {
		o.Restarted = cur.Read < prev.Read || cur.Written < prev.Written ||
			c.OnionskinsProcessed.NtorTotal() < p.OnionskinsProcessed.NtorTotal() ||
			c.OnionskinsDropped.NtorTotal() < p.OnionskinsDropped.NtorTotal() ||
			c.OOMBytes.Total() < p.OOMBytes.Total() || c.TCPExhaustion < p.TCPExhaustion ||
			c.RateLimitRead < p.RateLimitRead || c.RateLimitWrite < p.RateLimitWrite
		if o.Restarted {
			p = Load{}
		}
		o.addCounters(p, c)
	} else {
		o.From = time.Time{}
	}

	if c.SocketsLimit > 0 && c.SocketsOpen*100 >= c.SocketsLimit*SocketsNearPercent {
		o.add(SignalSocketsExhausted, c.SocketsOpen,
			c.SocketsOpen+1 >= c.SocketsLimit, // tor refuses new sockets at limit-1 (lib/net/socket.c)
			fmt.Sprintf("%d of %d sockets open (%d%%)", c.SocketsOpen, c.SocketsLimit, c.SocketsOpen*100/c.SocketsLimit))
	}
	return o
}

// addCounters adds the findings that come from counter increases.
func (o *Overload) addCounters(p, c Load) {
	if dropped := delta(p.OnionskinsDropped.NtorTotal(), c.OnionskinsDropped.NtorTotal()); dropped > 0 {
		requests := dropped + delta(p.OnionskinsProcessed.NtorTotal(), c.OnionskinsProcessed.NtorTotal())
		share := float64(dropped) / float64(requests)
		o.add(SignalOnionskinsDropped, dropped, requests >= ntorMinRequests && share >= ntorDropFraction,
			fmt.Sprintf("%d of %d ntor onionskins dropped (%.1f%%)", dropped, requests, share*100))
	}
	if freed := delta(p.OOMBytes.Total(), c.OOMBytes.Total()); freed > 0 {
		o.add(SignalOOM, freed, true, "the out-of-memory handler freed "+FormatBytes(freed))
	}
	if n := delta(p.TCPExhaustion, c.TCPExhaustion); n > 0 {
		o.add(SignalTCPExhaustion, n, true, fmt.Sprintf("%d connections failed because no local TCP port was free", n))
	}
	if n := delta(p.RateLimitRead, c.RateLimitRead) + delta(p.RateLimitWrite, c.RateLimitWrite); n > 0 {
		o.add(SignalRateLimited, n, true, fmt.Sprintf("the global bandwidth limit was reached %d times", n))
	}
}

func (o *Overload) add(sig Signal, count uint64, published bool, summary string) {
	explanation, remedy := sig.Describe()
	o.Findings = append(o.Findings, Finding{
		Signal: sig, Line: sig.Line(), Count: count, Published: published,
		Summary: summary, Explanation: explanation, Remedy: remedy,
	})
}

// Describe returns what a signal means and what the Tor Project recommends
// (https://support.torproject.org/relays/performance/overloaded/).
func (s Signal) Describe() (explanation, remedy string) {
	switch s {
	case SignalOnionskinsDropped:
		return "Tor's CPU workers could not keep up with circuit-creation handshakes and dropped some; " +
				"this is usually a CPU (sometimes RAM) shortage. At 1% of requests tor publishes overload-general.",
			"Give tor more CPU: let it use every core (do not set NumCPUs below the core count), stop other " +
				"CPU-heavy work, or move to a faster CPU. Lowering RelayBandwidthRate also reduces the circuit load."
	case SignalOOM:
		return "Tor's queues reached MaxMemInQueues and tor discarded queued data to stay alive; " +
				"tor publishes overload-general.",
			"Add RAM (Tor recommends at least 2 GB, 4 GB for fast relays). If the server has plenty of free " +
				"memory, raise MaxMemInQueues in torrc; otherwise lower RelayBandwidthRate. Persistent growth may be " +
				"a tor memory leak worth reporting."
	case SignalTCPExhaustion:
		return "The local port range ran out (mostly on exit relays); tor publishes overload-general.",
			`Widen the port range: sysctl -w net.ipv4.ip_local_port_range="15000 64000", and make it ` +
				"permanent in /etc/sysctl.d/."
	case SignalSocketsExhausted:
		return "Tor is close to its file-descriptor limit; when it is reached, new connections fail " +
				"and tor publishes overload-fd-exhausted.",
			"Raise tor's open-file limit: a systemd drop-in for the tor unit with a higher LimitNOFILE " +
				"(systemctl edit tor@default), then restart tor. Tor sizes its socket limit from it."
	case SignalRateLimited:
		return "Tor's BandwidthRate/BandwidthBurst bucket ran empty; tor publishes overload-ratelimits " +
				"(Relay Search does not show it as overloaded). With a deliberate limit this is expected.",
			"If it happens constantly and the line has headroom, raise BandwidthRate/BandwidthBurst. A sudden " +
				"jump can also mean the relay guards a busy onion service or is under attack."
	}
	return "", ""
}

// delta is cur-prev for a counter, or cur when the counter was reset.
func delta(prev, cur uint64) uint64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// FormatBytes renders a byte count with a binary unit, like tor's logs.
func FormatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
