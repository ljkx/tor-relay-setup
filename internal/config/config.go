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
	Family    Family        `toml:"family"`
	Bandwidth BandwidthPlan `toml:"bandwidth"`
	System    System        `toml:"system"`
}

// Relay holds the public identity and listener settings.
type Relay struct {
	Nickname    string `toml:"nickname"`
	Contact     string `toml:"contact"`
	ORPort      int    `toml:"or_port"`
	Mode        string `toml:"mode"` // guard | exit
	IPv6        string `toml:"ipv6"` // global address, or empty for none
	Sandbox     bool   `toml:"sandbox"`
	MetricsPort bool   `toml:"metrics_port"`
}

// Exit holds exit-relay settings; ignored for guard relays.
type Exit struct {
	// ProviderPermission must be true: the operator confirms the provider
	// allows exits and that abuse complaints will be handled.
	ProviderPermission bool   `toml:"provider_permission"`
	Policy             string `toml:"policy"` // reduced | default
	IPv6Exit           bool   `toml:"ipv6_exit"`
	Unbound            bool   `toml:"unbound"`
	LockResolvConf     bool   `toml:"lock_resolv_conf"`
}

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
}

// Default returns the recommended answers for a new guard relay.
func Default() Setup {
	return Setup{
		Relay:     Relay{ORPort: 9001, Mode: string(relay.ModeGuard), Sandbox: true},
		Exit:      Exit{Policy: string(relay.PolicyReduced), IPv6Exit: true, Unbound: true},
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

// IsExit reports whether this is an exit relay.
func (s Setup) IsExit() bool { return s.Relay.Mode == string(relay.ModeExit) }

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
	case string(relay.ModeGuard), string(relay.ModeExit):
	default:
		add("relay.mode: must be \"guard\" or \"exit\"")
	}
	if r.IPv6 != "" && !relay.ValidIPv6(r.IPv6) {
		add("relay.ipv6: %q is not a global IPv6 address", r.IPv6)
	}

	if s.IsExit() {
		if !s.Exit.ProviderPermission {
			add("exit.provider_permission: confirm your provider allows Tor exits and that abuse complaints are handled")
		}
		switch s.Exit.Policy {
		case string(relay.PolicyReduced), string(relay.PolicyDefault):
		default:
			add("exit.policy: must be \"reduced\" or \"default\"")
		}
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
	}
	return c
}
