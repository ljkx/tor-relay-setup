package system

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// IPv6DirectoryAuthorities are the IPv6 addresses of Tor directory
// authorities from tor's src/app/config/auth_dirs.inc (tor26, gabelmoo,
// dannenberg, maatuska, bastet).
var IPv6DirectoryAuthorities = []string{
	"2a02:16a8:662:2203::1",
	"2001:638:a000:4140::ffff:189",
	"2001:678:558:1000::244",
	"2001:67c:289c::9",
	"2620:13:4000:6000::1000:118",
}

// ipv6DialTimeout bounds each authority connection attempt.
const ipv6DialTimeout = 3 * time.Second

// authorityORPort is the IPv6 ORPort each authority listens on.
func authorityORPort(addr string) string {
	if addr == "2001:67c:289c::9" { // maatuska
		return "80"
	}
	return "443"
}

// CheckIPv6Outbound checks outbound IPv6 by opening TCP connections to the
// directory authorities' IPv6 ORPorts concurrently (ping would need ICMP
// privileges). It returns how many connected out of how many were tried.
// dial defaults to net.Dialer.DialContext.
func CheckIPv6Outbound(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (reachable int, total int) {
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	var ok atomic.Int64
	var wg sync.WaitGroup
	for _, a := range IPv6DirectoryAuthorities {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, ipv6DialTimeout)
			defer cancel()
			conn, err := dial(dctx, "tcp6", net.JoinHostPort(a, authorityORPort(a)))
			if err != nil {
				return
			}
			_ = conn.Close()
			ok.Add(1)
		}()
	}
	wg.Wait()
	return int(ok.Load()), len(IPv6DirectoryAuthorities)
}

// Listening reports whether a TCP socket listens on port over IPv4
// (/proc/net/tcp) and IPv6 (/proc/net/tcp6). A missing table (IPv6
// disabled) counts as not listening; an error is returned only when neither
// table can be read.
func Listening(h host.Host, port int) (ipv4, ipv6 bool, err error) {
	d4, err4 := h.ReadFile("/proc/net/tcp")
	d6, err6 := h.ReadFile("/proc/net/tcp6")
	if err4 != nil && err6 != nil {
		return false, false, err4
	}
	return ParseProcNetTCP(d4, port), ParseProcNetTCP(d6, port), nil
}

// tcpListen is the kernel's TCP_LISTEN state in /proc/net/tcp.
const tcpListen = "0A"

// ParseProcNetTCP reports whether a /proc/net/tcp or /proc/net/tcp6 table
// has a socket in LISTEN state on the local port.
func ParseProcNetTCP(data []byte, port int) bool {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		// sl local_address rem_address st ...
		if len(fields) < 4 || fields[3] != tcpListen {
			continue
		}
		i := strings.LastIndexByte(fields[1], ':')
		if i < 0 {
			continue
		}
		if p, err := strconv.ParseUint(fields[1][i+1:], 16, 16); err == nil && int(p) == port {
			return true
		}
	}
	return false
}
