// Package config is the declarative description of a relay: everything the
// setup wizard asks, in a form that can be saved as TOML and replayed with
// `tor-relay-setup apply --config relay.toml`.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// BandwidthCustom keeps hand-written torrc limits exactly (see FromDocument).
const BandwidthCustom = "custom"

// DefaultMetricsPort is the local-only MetricsPort address.
const DefaultMetricsPort = "127.0.0.1:9035"

// Setup is the complete set of answers for a guided setup.
type Setup struct {
	Relay     Relay         `toml:"relay"`
	Exit      Exit          `toml:"exit"`
	Bridge    Bridge        `toml:"bridge"`
	Family    Family        `toml:"family"`
	Bandwidth BandwidthPlan `toml:"bandwidth"`
	System    System        `toml:"system"`
}

// Relay holds the public identity and listener settings.
type Relay struct {
	Nickname    string `toml:"nickname"`
	Contact     string `toml:"contact"`
	ORPort      int    `toml:"or_port"`
	Mode        string `toml:"mode"` // guard | exit | bridge
	IPv6        string `toml:"ipv6"` // global address, or empty for none
	Sandbox     bool   `toml:"sandbox"`
	MetricsPort bool   `toml:"metrics_port"`
	// OfflineMasterKey writes OfflineMasterKey 1: the ed25519 master
	// identity key is kept off the server (see `tor-relay-setup keys`).
	OfflineMasterKey bool `toml:"offline_master_key,omitempty"`
	// Instance names the Debian tor instance (tor-instance-create NAME,
	// unit tor@NAME); empty or "default" is /etc/tor/torrc (tor@default).
	Instance string `toml:"instance"`
	// MetricsAddress is the MetricsPort address picked for this host when
	// MetricsPort is on (plan.ResolveMetricsAddress); empty means
	// DefaultMetricsPort. It is never saved: every host picks a free port.
	MetricsAddress string `toml:"-"`
}

// Exit holds exit-relay settings; ignored for guard relays.
type Exit struct {
	// ProviderPermission must be true: the operator confirms the provider
	// allows exits and that abuse complaints will be handled.
	ProviderPermission bool   `toml:"provider_permission"`
	Policy             string `toml:"policy"` // reduced | default | web | custom
	// CustomPolicy holds the ExitPolicy entries of policy "custom", first
	// match wins, ending with "reject *:*" (or "accept *:*").
	CustomPolicy   []string `toml:"custom_policy,omitempty"`
	IPv6Exit       bool     `toml:"ipv6_exit"`
	Unbound        bool     `toml:"unbound"`
	LockResolvConf bool     `toml:"lock_resolv_conf"`
	// Notice serves an exit notice page on port 80 with tor's own DirPort
	// (DirPortFrontPage), as Tor's exit guidelines recommend.
	Notice bool `toml:"notice,omitempty"`
}

// Bridge holds bridge settings; ignored unless relay.mode is "bridge".
type Bridge struct {
	Transport string `toml:"transport"` // obfs4 | webtunnel
	// Obfs4Port is the public obfs4 port; it must differ from the ORPort.
	Obfs4Port int `toml:"obfs4_port,omitempty"`
	// Distribution is tor's BridgeDistribution: how the Tor Project hands
	// the bridge out (any, https, email, settings, telegram), or none. Empty
	// means any for obfs4 and https for WebTunnel.
	Distribution string `toml:"distribution"`

	// WebTunnel: Domain points at this server and serves HTTPS; Path is the
	// secret location proxied to the webtunnel server (generated when
	// empty, and kept from torrc on later runs).
	Domain    string `toml:"domain,omitempty"`
	Path      string `toml:"path,omitempty"`
	LocalPort int    `toml:"local_port,omitempty"` // webtunnel server, default 15000
	// WebServer is "nginx" (installed and configured by this tool) or
	// "manual" (you run the web server; the tool prints the snippet).
	WebServer string `toml:"web_server,omitempty"`
	// Certificate for nginx: "existing" uses CertFile and KeyFile; "certbot"
	// requests one from Let's Encrypt with certbot --nginx, which needs
	// CertbotAgreeTOS (certbot accepts Let's Encrypt's terms for you).
	Certificate     string `toml:"certificate,omitempty"`
	CertFile        string `toml:"cert_file,omitempty"`
	KeyFile         string `toml:"key_file,omitempty"`
	CertbotEmail    string `toml:"certbot_email,omitempty"`
	CertbotAgreeTOS bool   `toml:"certbot_agree_tos,omitempty"`

	// Plugin is the transport binary picked for this host (lyrebird where
	// Debian packages it, else obfs4proxy); never saved.
	Plugin string `toml:"-"`
}

// Bridge transports, web servers and certificate sources.
const (
	WebServerNginx    = "nginx"
	WebServerManual   = "manual"
	CertExisting      = "existing"
	CertCertbot       = "certbot"
	DefaultObfs4Port  = 8443
	DefaultBridgePort = 9443 // bridge ORPort suggestion: Tor asks bridges to avoid 9001
)

// Family describes the relay family (Tor 0.4.9 FamilyId).
type Family struct {
	Mode      string `toml:"mode"` // none | generate | import
	KeyName   string `toml:"key_name"`
	ImportKey string `toml:"import_key"` // path to NAME.secret_family_key
	FamilyID  string `toml:"family_id"`  // required for import when no .public_family_id sits next to the key
	// Keep lists FamilyIds already configured on this relay (reconfiguring
	// an existing relay keeps them).
	Keep []string `toml:"keep_ids,omitempty"`
}

// BandwidthPlan describes how traffic is limited.
type BandwidthPlan struct {
	Mode            string `toml:"mode"` // steady | manual | accounting | none
	MonthlyQuota    string `toml:"monthly_quota"`
	HeadroomPercent int    `toml:"headroom_percent"`
	Billing         string `toml:"billing"` // sum | out | max
	RateMbit        int    `toml:"rate_mbit"`
	BurstMbit       int    `toml:"burst_mbit"`
	// Custom mode keeps hand-written limits exactly as they are in torrc;
	// AccountingGBytes also adds a cap to manual mode.
	RateKBytes       int `toml:"rate_kbytes,omitempty"`
	BurstKBytes      int `toml:"burst_kbytes,omitempty"`
	AccountingGBytes int `toml:"accounting_gbytes,omitempty"`
}

// System holds host-level choices.
type System struct {
	Hostname           string `toml:"hostname"` // empty keeps the current hostname
	UnattendedUpgrades bool   `toml:"unattended_upgrades"`
	Nyx                bool   `toml:"nyx"`
	Firewall           string `toml:"firewall"` // auto | none
	EnableUFW          bool   `toml:"enable_ufw"`
	// Tuning applies conservative kernel and service limits for
	// high-bandwidth relays (see plan's tuning step).
	Tuning bool `toml:"tuning"`
}

// Default returns the recommended answers for a new guard relay.
func Default() Setup {
	return Setup{
		Relay:     Relay{ORPort: 9001, Mode: string(relay.ModeGuard), Sandbox: true},
		Exit:      Exit{Policy: string(relay.PolicyReduced), IPv6Exit: true, Unbound: true},
		Bridge:    Bridge{Transport: string(relay.TransportObfs4)},
		Family:    Family{Mode: "none", KeyName: "relay-family"},
		Bandwidth: BandwidthPlan{Mode: string(relay.BandwidthSteady), HeadroomPercent: 10, Billing: string(relay.RuleSum)},
		System:    System{UnattendedUpgrades: true, Nyx: true, Firewall: "auto", EnableUFW: true},
	}
}

// Load reads a TOML file on top of Default and rejects unknown keys.
func Load(path string) (Setup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Setup{}, err
	}
	return Parse(data)
}

// Parse decodes TOML on top of Default and rejects unknown keys.
func Parse(data []byte) (Setup, error) {
	s := Default()
	md, err := toml.Decode(string(data), &s)
	if err != nil {
		return Setup{}, fmt.Errorf("parse config: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return Setup{}, fmt.Errorf("unknown config keys: %s", strings.Join(keys, ", "))
	}
	return s, nil
}

// Marshal encodes the setup as commented TOML.
func (s Setup) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# tor-relay-setup configuration.\n")
	buf.WriteString("# Apply on a fresh server with: sudo tor-relay-setup apply --config <this file>\n\n")
	if err := toml.NewEncoder(&buf).Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Instance returns the tor instance this setup configures. An invalid name
// yields the default instance; Validate reports it.
func (s Setup) Instance() relay.Instance {
	inst, err := relay.Named(s.Relay.Instance)
	if err != nil {
		return relay.DefaultInstance()
	}
	return inst
}

// IsExit reports whether this is an exit relay.
func (s Setup) IsExit() bool { return s.Relay.Mode == string(relay.ModeExit) }

// IsBridge reports whether this is a bridge.
func (s Setup) IsBridge() bool { return s.Relay.Mode == string(relay.ModeBridge) }

// IsWebTunnel reports whether this is a WebTunnel bridge.
func (s Setup) IsWebTunnel() bool {
	return s.IsBridge() && s.Bridge.Transport == string(relay.TransportWebTunnel)
}

// ManagedNginx reports whether this tool installs and configures nginx for a
// WebTunnel bridge.
func (s Setup) ManagedNginx() bool { return s.IsWebTunnel() && s.Bridge.WebServer != WebServerManual }

// UsesCertbot reports whether apply requests a certificate with certbot.
func (s Setup) UsesCertbot() bool { return s.ManagedNginx() && s.Bridge.Certificate == CertCertbot }

// WebTunnelPort is the local port of the webtunnel server.
func (s Setup) WebTunnelPort() int {
	if s.Bridge.LocalPort > 0 {
		return s.Bridge.LocalPort
	}
	return relay.DefaultWebTunnelPort
}

// PendingPath stands in for a WebTunnel path that apply generates.
const PendingPath = "GENERATED-DURING-APPLY"

// WebTunnelURL is the bridge's WebTunnel URL; PendingPath marks a path that
// is generated during apply.
func (s Setup) WebTunnelURL() string {
	p := s.Bridge.Path
	if p == "" {
		p = PendingPath
	}
	return relay.WebTunnelURL(s.Bridge.Domain, p)
}

// Plugin is the transport binary torrc names.
func (s Setup) Plugin() string {
	switch {
	case s.Bridge.Plugin != "":
		return s.Bridge.Plugin
	case s.IsWebTunnel():
		return relay.WebTunnelPath
	}
	return relay.Obfs4ProxyPath
}

// Distribution is the BridgeDistribution value; WebTunnel bridges default
// to https, the only distributor that hands them out.
func (s Setup) Distribution() string {
	switch {
	case s.Bridge.Distribution != "":
		return s.Bridge.Distribution
	case s.IsWebTunnel():
		return "https"
	}
	return "any"
}

// Port is a TCP port the relay needs reachable from the Internet.
type Port struct {
	Number int
	Label  string // firewall rule comment, e.g. "Tor relay ORPort"
}

// PublicPorts lists the TCP ports to open in the firewall: the ORPort, plus
// the obfs4 port, the WebTunnel web server, or the exit notice.
func (s Setup) PublicPorts() []Port {
	switch {
	case s.IsWebTunnel():
		ports := []Port{{443, "Tor WebTunnel bridge HTTPS"}}
		if s.UsesCertbot() {
			ports = append(ports, Port{80, "Tor WebTunnel ACME HTTP-01"})
		}
		return ports
	case s.IsBridge():
		return []Port{{s.Relay.ORPort, "Tor bridge ORPort"}, {s.Bridge.Obfs4Port, "Tor bridge obfs4"}}
	case s.IsExit() && s.Exit.Notice:
		return []Port{{s.Relay.ORPort, "Tor relay ORPort"}, {relay.ExitNoticePort, "Tor exit notice"}}
	}
	return []Port{{s.Relay.ORPort, "Tor relay ORPort"}}
}

// validateBridge checks the [bridge] table of a bridge setup.
func (s Setup) validateBridge() []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	b := s.Bridge
	if b.Distribution != "" && !relay.ValidDistribution(b.Distribution) {
		add("bridge.distribution: one of %s", strings.Join(relay.Distributions, ", "))
	}
	switch relay.Transport(b.Transport) {
	case relay.TransportObfs4:
		switch {
		case !relay.ValidPort(b.Obfs4Port):
			add("bridge.obfs4_port: must be 1–65535")
		case b.Obfs4Port == s.Relay.ORPort:
			add("bridge.obfs4_port: must differ from relay.or_port (both must be reachable)")
		}
	case relay.TransportWebTunnel:
		if !relay.ValidDomain(b.Domain) {
			add("bridge.domain: a DNS name pointing at this server, e.g. bridge.example.org")
		}
		if b.Path != "" && !relay.ValidWebTunnelPath(b.Path) {
			add("bridge.path: 8–128 letters, digits, '.', '_', '~' or '-' (empty generates one)")
		}
		if b.LocalPort != 0 && !relay.ValidPort(b.LocalPort) {
			add("bridge.local_port: must be 1–65535")
		}
		switch b.WebServer {
		case "", WebServerNginx:
			switch b.Certificate {
			case CertExisting:
				if !strings.HasPrefix(b.CertFile, "/") || !strings.HasPrefix(b.KeyFile, "/") {
					add("bridge.cert_file and bridge.key_file: absolute paths of the certificate chain and its key")
				}
			case CertCertbot:
				if !b.CertbotAgreeTOS {
					add("bridge.certbot_agree_tos: set it to true to let certbot accept the Let's Encrypt Subscriber Agreement for you")
				}
				if b.CertbotEmail != "" && !relay.ValidEmail(b.CertbotEmail) {
					add("bridge.certbot_email: an email address, or empty")
				}
			default:
				add("bridge.certificate: \"existing\" (cert_file and key_file) or \"certbot\"")
			}
		case WebServerManual:
		default:
			add("bridge.web_server: \"nginx\" or \"manual\"")
		}
	default:
		add("bridge.transport: \"obfs4\" or \"webtunnel\"")
	}
	if s.Relay.Sandbox {
		add("relay.sandbox: tor refuses pluggable transports with Sandbox 1; set sandbox = false for bridges")
	}
	if (s.Family.Mode != "" && s.Family.Mode != "none") || len(s.Family.Keep) > 0 {
		add("family: bridges must not join a relay family (it would link the bridge to your public relays); set family.mode = \"none\"")
	}
	return errs
}

// Warnings returns advice that does not block the setup, such as ports
// censors are known to scan.
func (s Setup) Warnings() []string {
	var w []string
	if s.IsBridge() {
		if s.Relay.ORPort == 9001 && !s.IsWebTunnel() {
			w = append(w, "ORPort 9001 is commonly associated with Tor and censors scan for it; Tor's bridge guide asks bridges to avoid it")
		}
		if s.Bridge.Obfs4Port == 9001 && !s.IsWebTunnel() {
			w = append(w, "obfs4 port 9001 is commonly associated with Tor and censors scan for it")
		}
		if p := s.Bridge.Obfs4Port; !s.IsWebTunnel() && p > 0 && p < 1024 {
			w = append(w, fmt.Sprintf("obfs4 port %d is below 1024: the transport binary gets CAP_NET_BIND_SERVICE (setcap) and the tor unit NoNewPrivileges=no, as Tor's bridge guide describes; a package upgrade can drop the capability (status warns)", p))
		}
		if d := s.Distribution(); s.IsWebTunnel() && d != "https" && d != "none" {
			w = append(w, "WebTunnel bridges are only handed out by the https distributor; with \""+d+"\" nobody receives this bridge unless you share it")
		}
		if s.Distribution() == "none" {
			w = append(w, "BridgeDistribution none: the Tor Project never hands this bridge out; share its bridge line yourself")
		}
	}
	return w
}

// Validate checks every answer and returns all problems at once.
func (s Setup) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	r := s.Relay
	if !relay.ValidNickname(r.Nickname) {
		add("relay.nickname: use 1–19 letters or digits")
	}
	if !relay.ValidContactInfo(r.Contact) {
		add("relay.contact: required, at most 250 characters, no '#'")
	}
	if !relay.ValidPort(r.ORPort) {
		add("relay.or_port: must be 1–65535")
	}
	switch r.Mode {
	case string(relay.ModeGuard), string(relay.ModeExit), string(relay.ModeBridge):
	default:
		add("relay.mode: must be \"guard\", \"exit\" or \"bridge\"")
	}
	if r.IPv6 != "" && !relay.ValidIPv6(r.IPv6) {
		add("relay.ipv6: %q is not a global IPv6 address", r.IPv6)
	}
	if _, err := relay.Named(r.Instance); err != nil {
		add("relay.instance: empty or \"default\" for /etc/tor/torrc, otherwise 1–27 letters or digits (tor-instance-create NAME)")
	}

	if s.IsExit() {
		if !s.Exit.ProviderPermission {
			add("exit.provider_permission: confirm your provider allows Tor exits and that abuse complaints are handled")
		}
		switch p := relay.ExitPolicy(s.Exit.Policy); {
		case !relay.ValidExitPolicy(p):
			add("exit.policy: must be \"reduced\", \"default\", \"web\" or \"custom\"")
		case p == relay.PolicyCustom:
			if _, err := relay.NormalizePolicy(s.Exit.CustomPolicy); err != nil {
				add("exit.custom_policy: %v", err)
			}
		}
		if s.Exit.Notice && r.ORPort == relay.ExitNoticePort {
			add("exit.notice: the notice is served on port %d, which is the ORPort", relay.ExitNoticePort)
		}
	}
	if s.IsBridge() {
		errs = append(errs, s.validateBridge()...)
	}

	switch s.Family.Mode {
	case "", "none":
	case "generate":
		if !relay.ValidFamilyKeyName(s.Family.KeyName) {
			add("family.key_name: letters, digits, '.', '_' or '-' (max 64)")
		}
	case "import":
		if !strings.HasSuffix(s.Family.ImportKey, ".secret_family_key") {
			add("family.import_key: path to a NAME.secret_family_key file")
		}
		if s.Family.FamilyID != "" && !relay.ValidFamilyID(s.Family.FamilyID) {
			add("family.family_id: 43 base64 characters, as printed by tor --keygen-family")
		}
	default:
		add("family.mode: must be \"none\", \"generate\" or \"import\"")
	}

	if _, err := s.Bandwidth.Resolve(); err != nil {
		add("bandwidth: %v", err)
	}

	if s.System.Hostname != "" && !relay.ValidHostname(s.System.Hostname) {
		add("system.hostname: DNS-style labels only")
	}
	switch s.System.Firewall {
	case "", "auto", "none":
	default:
		add("system.firewall: must be \"auto\" or \"none\"")
	}
	return errors.Join(errs...)
}

// Resolve turns the plan into concrete torrc bandwidth settings.
func (b BandwidthPlan) Resolve() (relay.Bandwidth, error) {
	switch b.Mode {
	case "", string(relay.BandwidthNone):
		return relay.Bandwidth{Mode: relay.BandwidthNone}, nil
	case string(relay.BandwidthSteady):
		quota, err := relay.ParseQuota(b.MonthlyQuota)
		if err != nil {
			return relay.Bandwidth{}, fmt.Errorf("monthly_quota %q: %w", b.MonthlyQuota, err)
		}
		p, err := relay.Steady(quota, b.HeadroomPercent, relay.BillingRule(b.Billing))
		if err != nil {
			return relay.Bandwidth{}, err
		}
		return p.Bandwidth, nil
	case string(relay.BandwidthManual):
		if b.RateMbit < 1 {
			return relay.Bandwidth{}, errors.New("rate_mbit must be at least 1")
		}
		burst := b.BurstMbit
		if burst == 0 {
			burst = 2 * b.RateMbit
		}
		if burst < b.RateMbit {
			return relay.Bandwidth{}, errors.New("burst_mbit must be at least rate_mbit")
		}
		bw := relay.Bandwidth{Mode: relay.BandwidthManual, RateMbit: b.RateMbit, BurstMbit: burst}
		if b.AccountingGBytes > 0 {
			bw.AccountingMaxGBytes, bw.AccountingRule = b.AccountingGBytes, relay.BillingRule(b.Billing)
		}
		return bw, nil
	case BandwidthCustom:
		switch {
		case b.RateKBytes > 0:
			return relay.Bandwidth{
				Mode: relay.BandwidthSteady, RateKBytes: b.RateKBytes, BurstKBytes: max(b.BurstKBytes, b.RateKBytes),
				AccountingMaxGBytes: b.AccountingGBytes, AccountingRule: relay.BillingRule(b.Billing),
			}, nil
		case b.AccountingGBytes > 0:
			return relay.Bandwidth{
				Mode: relay.BandwidthAccounting, AccountingMaxGBytes: b.AccountingGBytes,
				AccountingRule: relay.BillingRule(b.Billing),
			}, nil
		}
		return relay.Bandwidth{Mode: relay.BandwidthNone}, nil
	case string(relay.BandwidthAccounting):
		quota, err := relay.ParseQuota(b.MonthlyQuota)
		if err != nil {
			return relay.Bandwidth{}, fmt.Errorf("monthly_quota %q: %w", b.MonthlyQuota, err)
		}
		if b.HeadroomPercent < 0 || b.HeadroomPercent > 50 {
			return relay.Bandwidth{}, errors.New("headroom_percent must be 0–50")
		}
		usable := quota * (100 - b.HeadroomPercent) / 100
		if usable < 1 {
			return relay.Bandwidth{}, errors.New("quota is below 1 GByte after headroom")
		}
		return relay.Bandwidth{
			Mode:                relay.BandwidthAccounting,
			AccountingMaxGBytes: usable,
			AccountingRule:      relay.BillingRule(b.Billing),
		}, nil
	default:
		return relay.Bandwidth{}, fmt.Errorf("mode %q must be steady, manual, accounting, custom or none", b.Mode)
	}
}

// RelayConfig derives the torrc model. familyIDs are the IDs known so far;
// a family that will be generated during apply renders as a placeholder.
func (s Setup) RelayConfig(familyIDs []string) relay.Config {
	bw, _ := s.Bandwidth.Resolve()
	familyIDs = append(append([]string(nil), s.Family.Keep...), familyIDs...)
	c := relay.Config{
		Nickname:    s.Relay.Nickname,
		ContactInfo: s.Relay.Contact,
		ORPort:      s.Relay.ORPort,
		IPv6Address: s.Relay.IPv6,
		Mode:        relay.Mode(s.Relay.Mode),
		ExitPolicy:  relay.ExitPolicy(s.Exit.Policy),
		IPv6Exit:    s.IsExit() && s.Relay.IPv6 != "" && s.Exit.IPv6Exit,
		FamilyIDs:   familyIDs,
		Sandbox:     s.Relay.Sandbox,
		Bandwidth:   bw,
	}
	if len(familyIDs) == 0 {
		switch s.Family.Mode {
		case "generate":
			c.FamilyPending = true
		case "import":
			if relay.ValidFamilyID(s.Family.FamilyID) {
				c.FamilyIDs = []string{s.Family.FamilyID}
			}
		}
	}
	if s.Relay.MetricsPort {
		c.MetricsPort = DefaultMetricsPort
		if s.Relay.MetricsAddress != "" {
			c.MetricsPort = s.Relay.MetricsAddress
		}
	}
	c.OfflineMasterKey = s.Relay.OfflineMasterKey
	if s.IsExit() {
		if c.ExitPolicy == relay.PolicyCustom {
			c.ExitPolicyLines, _ = relay.NormalizePolicy(s.Exit.CustomPolicy)
		}
		if s.Exit.Notice {
			c.ExitNotice = s.Instance().ExitNoticePath()
		}
	}
	if s.IsBridge() {
		// Bridges never join a family and cannot sandbox their transport.
		c.FamilyIDs, c.FamilyPending, c.Sandbox, c.IPv6Exit = nil, false, false, false
		c.Bridge = relay.Bridge{
			Transport:    relay.Transport(s.Bridge.Transport),
			Plugin:       s.Plugin(),
			Port:         s.Bridge.Obfs4Port,
			Distribution: s.Distribution(),
		}
		if s.IsWebTunnel() {
			c.Bridge.Port, c.Bridge.URL = s.WebTunnelPort(), s.WebTunnelURL()
		}
	}
	return c
}
