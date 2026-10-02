package relay

import (
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Transport names a pluggable transport a bridge offers.
type Transport string

// Bridge transports.
const (
	// TransportObfs4 is the obfs4 transport (lyrebird, formerly obfs4proxy):
	// a public port that looks like random bytes to a censor.
	TransportObfs4 Transport = "obfs4"
	// TransportWebTunnel hides the bridge behind an HTTPS website: a web
	// server proxies a secret path to the webtunnel server on localhost.
	TransportWebTunnel Transport = "webtunnel"
)

// Pluggable transport binaries. Debian's obfs4proxy package installs
// /usr/bin/obfs4proxy (bookworm, trixie, Ubuntu jammy/noble); its successor
// lyrebird (Debian forky and later) installs /usr/bin/lyrebird. The Tor
// Project's webtunnel package installs /usr/bin/webtunnel-server.
const (
	Obfs4ProxyPath = "/usr/bin/obfs4proxy"
	LyrebirdPath   = "/usr/bin/lyrebird"
	WebTunnelPath  = "/usr/bin/webtunnel-server"
)

// DefaultWebTunnelPort is the local port the webtunnel server listens on and
// the web server proxies to, as in the Tor Project's WebTunnel guide.
const DefaultWebTunnelPort = 15000

// ScanURL is the Tor Project's TCP reachability test for obfs4 ports.
const ScanURL = "https://bridges.torproject.org/scan/"

// BridgeStatusURL shows the bridge authority's test results for a bridge,
// by hashed fingerprint (tor logs this link on start-up).
const BridgeStatusURL = "https://bridges.torproject.org/status?id="

// Distributions lists the BridgeDistribution values this tool offers: the
// ones tor 0.4.9 recognises (none, any, https, email, settings; relay_config.c)
// plus telegram, which the Tor support pages list and tor accepts with an
// "Unrecognized BridgeDistribution value" warning. moat is being replaced
// by settings and is not offered.
var Distributions = []string{"any", "https", "email", "settings", "telegram", "none"}

// ValidDistribution reports whether v is one of Distributions.
func ValidDistribution(v string) bool { return slices.Contains(Distributions, v) }

// Bridge holds the bridge-only settings of a Config.
type Bridge struct {
	Transport Transport
	// Plugin is the transport binary tor starts (ServerTransportPlugin).
	Plugin string
	// Port is the obfs4 port clients connect to, or for WebTunnel the local
	// port the web server proxies to.
	Port int
	// Distribution is the BridgeDistribution value; "" leaves tor's default
	// (any).
	Distribution string
	// URL is the WebTunnel address, https://domain/secret-path.
	URL string
}

// validate checks the bridge settings and returns every problem.
func (b Bridge) validate(orPort int) []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !path.IsAbs(b.Plugin) || strings.ContainsAny(b.Plugin, " \t\"") {
		add("invalid bridge Plugin %q: need the absolute path of the transport binary", b.Plugin)
	}
	if !ValidPort(b.Port) {
		add("invalid bridge Port %d: must be 1-65535", b.Port)
	}
	if b.Distribution != "" && !ValidDistribution(b.Distribution) {
		add("invalid BridgeDistribution %q: want one of %s", b.Distribution, strings.Join(Distributions, ", "))
	}
	switch b.Transport {
	case TransportObfs4:
		if b.Port == orPort {
			add("invalid bridge Port %d: the obfs4 port must differ from the ORPort", b.Port)
		}
	case TransportWebTunnel:
		if _, _, ok := SplitWebTunnelURL(b.URL); !ok {
			add("invalid WebTunnel URL %q: need https://domain/path", b.URL)
		}
	default:
		add("invalid bridge Transport %q: want obfs4 or webtunnel", b.Transport)
	}
	return errs
}

// Comments of the managed bridge block.
const (
	bridgeComment     = "# Bridge mode: unlisted entry point for users in censored networks."
	extORPortComment  = "# Local link between tor and the transport. Always auto."
	webTunnelORPortTx = "# WebTunnel: the ORPort stays on localhost; the web server is the public side."
)

// bridgeLines renders the bridge block of a fresh torrc.
func (c Config) bridgeLines() []string {
	b := c.Bridge
	lines := []string{bridgeComment, "BridgeRelay 1"}
	switch b.Transport {
	case TransportWebTunnel:
		// Exactly the Tor Project's WebTunnel bridge torrc
		// (community.torproject.org/relay/setup/webtunnel/source/).
		lines = append(lines,
			webTunnelORPortTx,
			"ORPort 127.0.0.1:auto",
			"AssumeReachable 1",
			fmt.Sprintf("ServerTransportPlugin webtunnel exec %s", b.Plugin),
			fmt.Sprintf("ServerTransportListenAddr webtunnel 127.0.0.1:%d", b.Port),
			"ServerTransportOptions webtunnel url="+b.URL,
		)
	default:
		// The Debian/Ubuntu obfs4 bridge guide
		// (community.torproject.org/relay/setup/bridge/debian-ubuntu/).
		lines = append(lines, fmt.Sprintf("ORPort %d", c.ORPort))
		if c.IPv6Address != "" {
			lines = append(lines, fmt.Sprintf("ORPort [%s]:%d", strings.Trim(c.IPv6Address, "[]"), c.ORPort))
		}
		lines = append(lines,
			fmt.Sprintf("ServerTransportPlugin obfs4 exec %s", b.Plugin),
			fmt.Sprintf("ServerTransportListenAddr obfs4 0.0.0.0:%d", b.Port),
		)
	}
	lines = append(lines, extORPortComment, "ExtORPort auto")
	if b.Distribution != "" {
		lines = append(lines, "BridgeDistribution "+b.Distribution)
	}
	return lines
}

// SplitWebTunnelURL splits https://domain/path into its domain and path
// (without the leading slash). The path must be non-empty and made of URL
// path characters; the domain must be a DNS name.
func SplitWebTunnelURL(u string) (domain, secret string, ok bool) {
	rest, found := strings.CutPrefix(u, "https://")
	if !found {
		return "", "", false
	}
	domain, secret, _ = strings.Cut(rest, "/")
	if !ValidDomain(domain) || !ValidWebTunnelPath(secret) {
		return "", "", false
	}
	return domain, secret, true
}

// WebTunnelURL joins a domain and secret path into the WebTunnel URL.
func WebTunnelURL(domain, secret string) string {
	return "https://" + domain + "/" + strings.TrimPrefix(secret, "/")
}

var webTunnelPathRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{8,128}$`)

// ValidWebTunnelPath reports whether p can be the secret WebTunnel path: 8 to
// 128 unreserved URL characters, without slashes (the guide generates 24
// random letters and digits).
func ValidWebTunnelPath(p string) bool { return webTunnelPathRe.MatchString(p) }

// ValidDomain reports whether s is a fully qualified DNS name with at least
// two labels and no IP address, as a TLS certificate needs.
func ValidDomain(s string) bool {
	if !strings.Contains(s, ".") || !ValidHostname(s) {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	labels := strings.Split(s, ".")
	tld := labels[len(labels)-1]
	return strings.IndexFunc(tld, func(r rune) bool { return r >= '0' && r <= '9' }) < 0
}

// BridgeSettings reads the bridge block back from a torrc. ok is false when
// BridgeRelay is not set.
func (d *Document) BridgeSettings() (Bridge, bool) {
	v, _ := d.Get("BridgeRelay")
	if strings.TrimSpace(v) != "1" {
		return Bridge{}, false
	}
	var b Bridge
	for _, line := range d.GetAll("ServerTransportPlugin") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == "exec" {
			b.Transport, b.Plugin = Transport(f[0]), f[2]
			break
		}
	}
	for _, line := range d.GetAll("ServerTransportListenAddr") {
		if f := strings.Fields(line); len(f) >= 2 && Transport(f[0]) == b.Transport {
			b.Port = PortNumber(f[1])
		}
	}
	for _, line := range d.GetAll("ServerTransportOptions") {
		f := strings.Fields(line)
		if len(f) < 2 || Transport(f[0]) != b.Transport {
			continue
		}
		for _, kv := range f[1:] {
			if u, ok := strings.CutPrefix(kv, "url="); ok {
				b.URL = u
			}
		}
	}
	if dist, ok := d.Get("BridgeDistribution"); ok {
		b.Distribution = strings.ToLower(strings.TrimSpace(dist))
	}
	return b, true
}

// BridgePorts returns the TCP ports the transports of a bridge torrc listen
// on (ServerTransportListenAddr), for port-conflict checks.
func (d *Document) BridgePorts() []int {
	var out []int
	for _, line := range d.GetAll("ServerTransportListenAddr") {
		if f := strings.Fields(line); len(f) >= 2 {
			if p := PortNumber(f[1]); p > 0 && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}
