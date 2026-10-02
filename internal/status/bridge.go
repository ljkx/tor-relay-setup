package status

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// Bridge is the bridge part of a report.
type Bridge struct {
	Transport string `json:"transport"`
	Plugin    string `json:"plugin,omitempty"`
	// PluginInstalled reports whether the transport binary exists.
	PluginInstalled bool `json:"plugin_installed"`
	// Port is the obfs4 port, or the local port of the webtunnel server.
	Port         int    `json:"port,omitempty"`
	Listening    bool   `json:"listening"`
	Distribution string `json:"distribution,omitempty"`
	// HashedFingerprint identifies the bridge in Tor Metrics and on
	// bridges.torproject.org without revealing its fingerprint.
	HashedFingerprint string `json:"hashed_fingerprint,omitempty"`
	// Line is the bridge line to share (without the "Bridge " prefix).
	// It is a secret of sorts: whoever has it can use and block the bridge.
	Line string `json:"bridge_line,omitempty"`
	// LineComplete is false while placeholders remain (no public address
	// known yet, or tor has not started the transport).
	LineComplete bool `json:"bridge_line_complete"`
	// CapabilityMissing reports an obfs4 port below 1024 whose transport
	// binary lacks CAP_NET_BIND_SERVICE (a package upgrade drops it).
	CapabilityMissing bool `json:"capability_missing,omitempty"`
	// WebServer is the state of a WebTunnel bridge's nginx managed by this
	// tool: "active", "inactive", or "" when it does not manage one.
	WebServer string `json:"web_server,omitempty"`
}

// Files tor and the transports write into the DataDirectory. tor 0.4.9
// writes "bridgelines" with one complete "Bridge TRANSPORT ADDR FP ARGS"
// line per transport (verified with tor 0.4.9.13, obfs4proxy 0.0.14 and
// webtunnel 0.0.7); obfs4proxy and lyrebird also write
// pt_state/obfs4_bridgeline.txt with <IP ADDRESS>, <PORT> and <FINGERPRINT>
// placeholders (community.torproject.org/relay/setup/bridge/post-install/).
const (
	bridgeLinesFile = "bridgelines"
	obfs4LineFile   = "pt_state/obfs4_bridgeline.txt"
	hashedFPFile    = "hashed-fingerprint"
	ipPlaceholder   = "<IP ADDRESS>"
)

// BridgeLine returns the shareable bridge line for transport t, filling in
// the public IPv4 address ip (and, for the obfs4proxy file, port and
// fingerprint) where tor left placeholders. complete is false while any
// placeholder remains. The "Bridge " prefix is dropped: Tor Browser and
// bridges.torproject.org use the bare form.
func BridgeLine(h host.Host, dataDir string, b relay.Bridge, fingerprint, ip string) (line string, complete bool) {
	dir := strings.TrimRight(dataDir, "/") + "/"
	pick := func(data []byte) string {
		for l := range strings.Lines(string(data)) {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			l = strings.TrimPrefix(l, "Bridge ")
			if f := strings.Fields(l); len(f) > 0 && relay.Transport(f[0]) == b.Transport {
				return l
			}
		}
		return ""
	}
	if data, err := h.ReadFile(dir + bridgeLinesFile); err == nil {
		line = pick(data)
	}
	if line == "" && b.Transport == relay.TransportObfs4 {
		if data, err := h.ReadFile(dir + obfs4LineFile); err == nil {
			line = pick(data)
			line = strings.Replace(line, "<PORT>", strconv.Itoa(b.Port), 1)
			if fingerprint != "" {
				line = strings.Replace(line, "<FINGERPRINT>", fingerprint, 1)
			}
		}
	}
	if line == "" {
		return "", false
	}
	if ip != "" {
		line = strings.Replace(line, ipPlaceholder, ip, 1)
	}
	return line, !strings.Contains(line, "<")
}

// ReadFingerprint returns the relay's RSA fingerprint from
// DataDirectory/fingerprint ("Nickname FINGERPRINT"), or "".
func ReadFingerprint(h host.Host, dataDir string) string {
	fp, err := h.ReadFile(strings.TrimRight(dataDir, "/") + "/fingerprint")
	if err != nil {
		return ""
	}
	if fields := strings.Fields(string(fp)); len(fields) > 0 {
		return strings.ToUpper(fields[len(fields)-1])
	}
	return ""
}

// hashedFingerprint returns the bridge's hashed fingerprint: tor's
// hashed-fingerprint file, else computed from the fingerprint.
func hashedFingerprint(h host.Host, dataDir, fingerprint string) string {
	if data, err := h.ReadFile(strings.TrimRight(dataDir, "/") + "/" + hashedFPFile); err == nil {
		if f := strings.Fields(string(data)); len(f) > 0 {
			return strings.ToUpper(f[len(f)-1])
		}
	}
	if fingerprint == "" {
		return ""
	}
	hashed, _ := onionoo.HashFingerprint(fingerprint)
	return hashed
}

// PublicIPv4 returns the first global, non-private IPv4 address of the
// host's interfaces (`ip -4 -o addr show scope global`), or "" behind NAT.
func PublicIPv4(ctx context.Context, h host.Host) string {
	res, err := h.Run(ctx, host.Command{Name: "ip", Args: []string{"-4", "-o", "addr", "show", "scope", "global"}})
	if err != nil {
		return ""
	}
	return parseIPAddr(res.Output)
}

// parseIPAddr picks the first public address from `ip -o addr` output
// ("2: eth0    inet 203.0.113.5/24 brd ... scope global eth0").
func parseIPAddr(out string) string {
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] != "inet" {
				continue
			}
			p, err := netip.ParsePrefix(f[i+1])
			if err != nil {
				continue
			}
			a := p.Addr()
			if a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a) {
				return a.String()
			}
		}
	}
	return ""
}

// cgnat is the shared address space of carrier-grade NAT (RFC 6598).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// BridgeDirectory looks a bridge up in Tor Metrics by hashed fingerprint.
func BridgeDirectory(ctx context.Context, c onionoo.Client, fingerprint string) (*onionoo.Bridge, error) {
	if fingerprint == "" {
		return nil, nil
	}
	return c.BridgeDetails(ctx, fingerprint)
}

// ScanURL is the obfs4 reachability test for this bridge. The address goes
// into the query string because that is how the Tor Project's form works.
func (b Bridge) ScanURL(ip string) string {
	if b.Transport != string(relay.TransportObfs4) || ip == "" || b.Port == 0 {
		return relay.ScanURL
	}
	return relay.ScanURL + "?address=" + ip + "&port=" + strconv.Itoa(b.Port)
}

// bridgeWarnings returns what needs attention on a bridge.
func bridgeWarnings(r Report) []string {
	b := r.Bridge
	if b == nil {
		return nil
	}
	var w []string
	if !b.PluginInstalled {
		w = append(w, "the "+b.Transport+" transport binary "+b.Plugin+" is missing; re-run setup to install it")
	}
	if r.Service.Active && b.PluginInstalled && !b.Listening {
		where := "TCP " + strconv.Itoa(b.Port)
		if b.Transport == string(relay.TransportWebTunnel) {
			where = "127.0.0.1:" + strconv.Itoa(b.Port)
		}
		w = append(w, "the "+b.Transport+" transport is not listening on "+where+"; check the Tor log")
	}
	if b.CapabilityMissing {
		w = append(w, b.Plugin+" lacks CAP_NET_BIND_SERVICE for port "+strconv.Itoa(b.Port)+" (package upgrades reset it): run setcap cap_net_bind_service=+ep "+b.Plugin+" and restart tor")
	}
	if b.WebServer == "inactive" {
		w = append(w, "nginx is not running, so the WebTunnel bridge is unreachable")
	}
	return w
}
