package tui

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// answers holds the form values. Inputs are strings; setup() converts them.
type answers struct {
	Mode          string
	Nickname      string
	ContactFormat string // ciiss | free
	Email         string
	URL           string
	Hoster        string
	ContactFree   string
	ORPort        string
	IPv6Choice    string // an address, "none", or "manual"
	IPv6Manual    string

	ExitPermission bool
	ExitPolicy     string
	ExitCustom     string // custom exit policy, one entry per line
	ExitNotice     bool
	IPv6Exit       bool
	Unbound        bool
	LockResolv     bool

	BridgeTransport string
	Obfs4Port       string
	Obfs4Dist       string
	Domain          string
	WTPath          string
	WTDist          string
	WTLocalPort     int // kept from torrc, never asked
	WebServer       string
	Certificate     string
	CertFile        string
	KeyFile         string
	CertbotEmail    string
	CertbotAgree    bool
	OfflineKey      bool // kept from torrc, never asked

	FamilyMode   string
	FamilyKey    string
	FamilyImport string
	FamilyID     string
	Keep         []string // FamilyIds already configured (reconfigure)

	BandwidthMode string
	Quota         string
	Headroom      string
	Billing       string
	RateMbit      string
	BurstMbit     string
	// Hand-written limits kept verbatim (custom mode, reconfigure only).
	RateKBytes       int
	BurstKBytes      int
	AccountingGBytes int

	Hostname   string
	Unattended bool
	Nyx        bool
	Metrics    bool
	Sandbox    bool
	Firewall   string
	EnableUFW  bool
	Tuning     bool

	// Instance is the tor instance being configured ("" = default);
	// NewInstance asks for its name (adding another relay to the server).
	Instance    string
	NewInstance bool
}

func answersFrom(s config.Setup) *answers {
	a := &answers{
		Instance:       s.Relay.Instance,
		Tuning:         s.System.Tuning,
		Mode:           s.Relay.Mode,
		Nickname:       s.Relay.Nickname,
		ContactFormat:  "ciiss",
		ORPort:         itoa(s.Relay.ORPort),
		IPv6Choice:     "none",
		ExitPermission: s.Exit.ProviderPermission,
		ExitPolicy:     s.Exit.Policy,
		IPv6Exit:       s.Exit.IPv6Exit,
		Unbound:        s.Exit.Unbound,
		LockResolv:     s.Exit.LockResolvConf,
		FamilyMode:     s.Family.Mode,
		FamilyKey:      s.Family.KeyName,
		FamilyImport:   s.Family.ImportKey,
		FamilyID:       s.Family.FamilyID,
		BandwidthMode:  s.Bandwidth.Mode,
		Quota:          s.Bandwidth.MonthlyQuota,
		Headroom:       itoa(s.Bandwidth.HeadroomPercent),
		Billing:        s.Bandwidth.Billing,
		Hostname:       s.System.Hostname,
		Unattended:     s.System.UnattendedUpgrades,
		Nyx:            s.System.Nyx,
		Metrics:        s.Relay.MetricsPort,
		Sandbox:        s.Relay.Sandbox,
		Firewall:       s.System.Firewall,
		EnableUFW:      s.System.EnableUFW,
	}
	if a.FamilyMode == "" {
		a.FamilyMode = "none"
	}
	a.ExitCustom = strings.Join(s.Exit.CustomPolicy, "\n")
	if a.ExitCustom == "" {
		a.ExitCustom = strings.Join(relay.WebExitPolicy, "\n")
	}
	a.ExitNotice = s.Exit.Notice
	b := s.Bridge
	a.BridgeTransport, a.Domain, a.WTPath, a.WTLocalPort = b.Transport, b.Domain, b.Path, b.LocalPort
	if a.BridgeTransport == "" {
		a.BridgeTransport = string(relay.TransportObfs4)
	}
	if a.WTPath == "" {
		// Generated now so a saved relay.toml keeps it.
		a.WTPath = plan.NewWebTunnelPath()
	}
	a.Obfs4Port = itoa(b.Obfs4Port)
	if b.Obfs4Port == 0 {
		a.Obfs4Port = itoa(config.DefaultObfs4Port)
	}
	a.Obfs4Dist, a.WTDist = "any", "https"
	if b.Distribution != "" {
		a.Obfs4Dist, a.WTDist = b.Distribution, b.Distribution
	}
	a.WebServer, a.Certificate = b.WebServer, b.Certificate
	if a.WebServer == "" {
		a.WebServer = config.WebServerNginx
	}
	if a.Certificate == "" {
		a.Certificate = config.CertCertbot
	}
	a.CertFile, a.KeyFile, a.CertbotEmail, a.CertbotAgree = b.CertFile, b.KeyFile, b.CertbotEmail, b.CertbotAgreeTOS
	a.OfflineKey = s.Relay.OfflineMasterKey
	if s.Relay.Contact != "" {
		a.ContactFormat, a.ContactFree = "free", s.Relay.Contact
	}
	if s.Relay.IPv6 != "" {
		a.IPv6Choice, a.IPv6Manual = "manual", s.Relay.IPv6
	}
	if s.Bandwidth.RateMbit > 0 {
		a.RateMbit, a.BurstMbit = itoa(s.Bandwidth.RateMbit), itoa(s.Bandwidth.BurstMbit)
	}
	a.Keep = append([]string(nil), s.Family.Keep...)
	a.RateKBytes, a.BurstKBytes, a.AccountingGBytes = s.Bandwidth.RateKBytes, s.Bandwidth.BurstKBytes, s.Bandwidth.AccountingGBytes
	return a
}

func (a *answers) isBridge() bool { return a.Mode == string(relay.ModeBridge) }

func (a *answers) isWebTunnel() bool {
	return a.isBridge() && a.BridgeTransport == string(relay.TransportWebTunnel)
}

func (a *answers) contact() string {
	if a.ContactFormat == "free" {
		return strings.TrimSpace(a.ContactFree)
	}
	if strings.TrimSpace(a.Email) == "" {
		return ""
	}
	return relay.BuildCIISS(strings.TrimSpace(a.Email), strings.TrimSpace(a.URL), strings.TrimSpace(a.Hoster))
}

func (a *answers) ipv6() string {
	switch a.IPv6Choice {
	case "none", "":
		return ""
	case "manual":
		return strings.TrimSpace(a.IPv6Manual)
	default:
		return a.IPv6Choice
	}
}

func (a *answers) setup() config.Setup {
	s := config.Default()
	s.Relay = config.Relay{
		Nickname:    strings.TrimSpace(a.Nickname),
		Contact:     a.contact(),
		ORPort:      atoi(a.ORPort),
		Mode:        a.Mode,
		IPv6:        a.ipv6(),
		Sandbox:     a.Sandbox,
		MetricsPort: a.Metrics,
		Instance:    strings.TrimSpace(a.Instance),

		OfflineMasterKey: a.OfflineKey,
	}
	s.Exit = config.Exit{
		ProviderPermission: a.ExitPermission,
		Policy:             a.ExitPolicy,
		IPv6Exit:           a.IPv6Exit,
		Unbound:            a.Unbound,
		LockResolvConf:     a.LockResolv,
		Notice:             a.ExitNotice,
	}
	if a.ExitPolicy == string(relay.PolicyCustom) {
		s.Exit.CustomPolicy = relay.SplitPolicy(a.ExitCustom)
	}
	if a.isBridge() {
		// Bridges run their transport outside tor's sandbox and never join
		// a family.
		s.Relay.Sandbox = false
		s.Bridge = config.Bridge{Transport: a.BridgeTransport}
		if a.isWebTunnel() {
			s.Bridge.Domain = strings.ToLower(strings.TrimSpace(a.Domain))
			s.Bridge.Path = strings.TrimSpace(a.WTPath)
			s.Bridge.LocalPort = a.WTLocalPort
			s.Bridge.Distribution = a.WTDist
			s.Bridge.WebServer = a.WebServer
			if a.WebServer == config.WebServerNginx {
				s.Bridge.Certificate = a.Certificate
				switch a.Certificate {
				case config.CertExisting:
					s.Bridge.CertFile, s.Bridge.KeyFile = strings.TrimSpace(a.CertFile), strings.TrimSpace(a.KeyFile)
				case config.CertCertbot:
					s.Bridge.CertbotEmail, s.Bridge.CertbotAgreeTOS = strings.TrimSpace(a.CertbotEmail), a.CertbotAgree
				}
			}
		} else {
			s.Bridge.Obfs4Port = atoi(a.Obfs4Port)
			s.Bridge.Distribution = a.Obfs4Dist
		}
	}
	s.Family = config.Family{
		Mode: a.FamilyMode, KeyName: strings.TrimSpace(a.FamilyKey), ImportKey: strings.TrimSpace(a.FamilyImport),
		FamilyID: strings.TrimSpace(a.FamilyID), Keep: append([]string(nil), a.Keep...),
	}
	if a.isBridge() {
		s.Family = config.Family{Mode: "none", KeyName: s.Family.KeyName}
	}
	s.Bandwidth = config.BandwidthPlan{
		Mode:             a.BandwidthMode,
		MonthlyQuota:     strings.TrimSpace(a.Quota),
		HeadroomPercent:  atoi(a.Headroom),
		Billing:          a.Billing,
		RateMbit:         atoi(a.RateMbit),
		BurstMbit:        atoi(a.BurstMbit),
		RateKBytes:       a.RateKBytes,
		BurstKBytes:      a.BurstKBytes,
		AccountingGBytes: a.AccountingGBytes,
	}
	s.System = config.System{
		Hostname:           strings.TrimSpace(a.Hostname),
		UnattendedUpgrades: a.Unattended,
		Nyx:                a.Nyx,
		Firewall:           a.Firewall,
		EnableUFW:          a.EnableUFW,
		Tuning:             a.Tuning && plan.SuggestTuning(s),
	}
	return s
}

// budgetSummary explains what the bandwidth answers produce.
func (a *answers) budgetSummary() string {
	s := a.setup()
	switch a.BandwidthMode {
	case string(relay.BandwidthSteady):
		quota, err := relay.ParseQuota(s.Bandwidth.MonthlyQuota)
		if err != nil {
			return "Enter a monthly quota such as 10TB or 5000GB (decimal, as providers bill)."
		}
		p, err := relay.Steady(quota, s.Bandwidth.HeadroomPercent, relay.BillingRule(s.Bandwidth.Billing))
		if errors.Is(err, relay.ErrBelowMinimum) {
			return fmt.Sprintf("≈ %.1f Mbit/s — below Tor's 10 Mbit/s minimum. Raise the quota or use a manual rate.", p.Mbit)
		}
		if err != nil {
			return err.Error()
		}
		note := fmt.Sprintf("≈ %.1f Mbit/s steady (RelayBandwidthRate %d KBytes, burst %d KBytes)\nAccountingMax %d GBytes/month as a safety fuse · %d GBytes per direction",
			p.Mbit, p.Bandwidth.RateKBytes, p.Bandwidth.BurstKBytes, p.Bandwidth.AccountingMaxGBytes, p.PerDirectionGBytes)
		if p.BelowRecommended {
			note += "\nTor recommends 16 Mbit/s or more when possible."
		}
		return note
	case config.BandwidthCustom:
		bw, err := s.Bandwidth.Resolve()
		if err != nil {
			return err.Error()
		}
		return fmt.Sprintf("Keeps the current limits: %s", describeBandwidth(bw))
	case string(relay.BandwidthAccounting):
		bw, err := s.Bandwidth.Resolve()
		if err != nil {
			return err.Error()
		}
		return fmt.Sprintf("AccountingMax %d GBytes per month. The relay runs at full speed and hibernates once the quota is used.", bw.AccountingMaxGBytes)
	}
	return ""
}

// wizard is the setup form screen.
type wizard struct {
	ans  *answers
	form *huh.Form
	last int // last known step, for fields without a key
	// metrics is the MetricsPort address this host would use (9035 for
	// the default instance, the next free port for another relay).
	metrics string
}

func newWizard(a *App, prefill config.Setup) *wizard {
	return newWizardFor(a, answersFrom(prefill))
}

// newInstanceWizard sets up another relay on this server: the wizard also
// asks for the new instance's name.
func newInstanceWizard(a *App, prefill config.Setup) *wizard {
	ans := answersFrom(prefill)
	ans.NewInstance = true
	return newWizardFor(a, ans)
}

func newWizardFor(a *App, ans *answers) *wizard {
	w := &wizard{ans: ans}
	withMetrics := ans.setup()
	withMetrics.Relay.MetricsPort = true
	w.metrics = plan.ResolveMetricsAddress(a.opt.Host, withMetrics)
	if a.checks.FactsReady {
		w.form = w.build(a)
	}
	return w
}

// instance is the tor instance the answers configure.
func (w *wizard) instance() relay.Instance { return w.ans.setup().Instance() }

// Step labels shown in the stepper, keyed by field-key prefix.
var wizardSteps = []struct{ prefix, label string }{
	{"relay", "Relay"},
	{"contact", "Contact"},
	{"network", "Network"},
	{"exit", "Exit"},
	{"bridge", "Bridge"},
	{"family", "Family"},
	{"bandwidth", "Bandwidth"},
	{"system", "System"},
}

// stepShown reports whether the step with this prefix applies to the
// answers: exit settings for exits, bridge settings for bridges, no family
// for bridges and no network step for WebTunnel (nginx is the public side).
func (w *wizard) stepShown(prefix string) bool {
	a := w.ans
	switch prefix {
	case "exit":
		return a.Mode == string(relay.ModeExit)
	case "bridge":
		return a.isBridge()
	case "family":
		return !a.isBridge()
	case "network":
		return !a.isWebTunnel()
	}
	return true
}

func (w *wizard) stepLabels() []string {
	var out []string
	for _, s := range wizardSteps {
		if !w.stepShown(s.prefix) {
			continue
		}
		out = append(out, s.label)
	}
	return append(out, "Review")
}

func (w *wizard) currentStep() int {
	f := w.form.GetFocusedField()
	if f == nil {
		return 0
	}
	prefix, _, _ := strings.Cut(f.GetKey(), ".")
	if prefix == "" {
		return w.last
	}
	i := 0
	for _, s := range wizardSteps {
		if !w.stepShown(s.prefix) {
			continue
		}
		if s.prefix == prefix {
			w.last = i
			return i
		}
		i++
	}
	return 0
}

func (w *wizard) build(app *App) *huh.Form {
	a := w.ans
	isExit := func() bool { return a.Mode == string(relay.ModeExit) }

	// IPv6 is opt-in: Tor asks operators to enable it only when it works,
	// so "No IPv6" comes first and detected addresses show the outbound test.
	ipv6Options := func() []huh.Option[string] {
		opts := []huh.Option[string]{huh.NewOption("No IPv6", "none")}
		for _, addr := range app.checks.Facts.IPv6 {
			label := "Use " + addr
			if c := app.checks; c.IPv6Done && c.IPv6Total > 0 {
				label += fmt.Sprintf("  (%d/%d directory authorities reachable)", c.IPv6Reachable, c.IPv6Total)
			}
			opts = append(opts, huh.NewOption(label, addr))
		}
		return append(opts, huh.NewOption("Enter an address…", "manual"))
	}

	firewallDesc := func() string {
		fw := app.checks.Facts.Firewall
		switch fw.Kind {
		case "", "none":
			return "No firewall detected: UFW will be installed with your SSH ports allowed first."
		case "ufw":
			if fw.Active {
				return "UFW is active: only the ORPort rule is added."
			}
			return "UFW is installed but inactive: SSH and the ORPort are allowed, then UFW is enabled if you choose."
		default:
			return "Detected " + fw.Kind + " (" + fw.Detail + "): an ORPort rule is added."
		}
	}

	// Adding another relay to the server first asks for its instance name.
	var relayFields []huh.Field
	if a.NewInstance {
		relayFields = append(relayFields, huh.NewInput().Key("relay.instance").Title("Name of the new relay instance").
			Description("Debian runs each extra relay as its own tor instance: tor-instance-create NAME, unit tor@NAME. Letters and digits only.").
			Value(&a.Instance).CharLimit(27).Validate(func(s string) error {
			s = strings.TrimSpace(s)
			if !relay.ValidInstanceName(s) {
				return errors.New("1–27 letters or digits, not \"default\"")
			}
			if found, _ := relay.Discover(app.opt.Host); slices.ContainsFunc(found, func(i relay.Instance) bool { return i.Name == s }) {
				return errors.New("a relay with this name already runs here; pick another name")
			}
			return nil
		}))
	}
	relayFields = append(relayFields,
		huh.NewSelect[string]().Key("relay.mode").Title("What kind of relay?").
			Description("Guard/middle and exit relays are listed publicly. A bridge is unlisted: people in countries that block Tor use it to get in.").
			Options(
				huh.NewOption("Guard / middle relay — forwards traffic inside Tor (recommended)", string(relay.ModeGuard)),
				huh.NewOption("Exit relay — connects Tor users to the Internet (needs provider permission)", string(relay.ModeExit)),
				huh.NewOption("Bridge — helps censored users reach Tor (obfs4 or WebTunnel)", string(relay.ModeBridge)),
			).Value(&a.Mode),
		huh.NewInput().Key("relay.nickname").Title("Relay nickname").
			Description("Public. 1–19 letters or digits; it doesn't have to be unique.").
			Placeholder("MyRelay").Value(&a.Nickname).CharLimit(19).
			Validate(func(s string) error {
				if !relay.ValidNickname(strings.TrimSpace(s)) {
					return errors.New("use 1–19 letters or digits")
				}
				return nil
			}),
	)

	f := huh.NewForm(
		huh.NewGroup(relayFields...),

		huh.NewGroup(
			huh.NewSelect[string]().Key("contact.format").Title("ContactInfo").
				Description("Public in the relay directory. Tor expects an address that reaches you.").
				Options(
					huh.NewOption("Guided CIISS v3 string (recommended)", "ciiss"),
					huh.NewOption("Free-form text", "free"),
				).Value(&a.ContactFormat),
		),
		huh.NewGroup(
			huh.NewInput().Key("contact.email").Title("Operator email").
				Description("Published with @ written as [] to reduce spam.").Placeholder("tor-ops@example.org").
				Value(&a.Email).Validate(func(s string) error {
				if !relay.ValidEmail(strings.TrimSpace(s)) {
					return errors.New("enter an email address")
				}
				return nil
			}),
			huh.NewInput().Key("contact.url").Title("Website (optional)").
				Description("Adds url: and a proof:uri-familyid-ed25519 entry.").Placeholder("https://example.org").
				Value(&a.URL).Validate(func(s string) error {
				if s = strings.TrimSpace(s); s != "" && !relay.ValidHTTPSURL(s) {
					return errors.New("use an https:// URL, or leave it empty")
				}
				return nil
			}),
			huh.NewInput().Key("contact.hoster").Title("Hosting provider domain (optional)").
				Placeholder("hetzner.com").Value(&a.Hoster).Validate(func(s string) error {
				if s = strings.TrimSpace(s); s != "" && !relay.ValidHosterDomain(s) {
					return errors.New("a bare domain like hetzner.com")
				}
				return nil
			}),
		).WithHideFunc(func() bool { return a.ContactFormat != "ciiss" }),
		huh.NewGroup(
			huh.NewInput().Key("contact.free").Title("ContactInfo").
				Value(&a.ContactFree).Validate(func(s string) error {
				if !relay.ValidContactInfo(strings.TrimSpace(s)) {
					return errors.New("required, at most 250 characters, no '#'")
				}
				return nil
			}),
		).WithHideFunc(func() bool { return a.ContactFormat != "free" }),

		huh.NewGroup(
			huh.NewInput().Key("network.orport").Title("ORPort").
				Description("Inbound TCP port for relay traffic. 9001 is common; 443 passes more networks.").
				Value(&a.ORPort).Validate(func(s string) error {
				if !relay.ValidPort(atoi(s)) {
					return errors.New("a TCP port from 1 to 65535")
				}
				if a.isBridge() && atoi(s) == 9001 {
					return errors.New("bridges should avoid 9001: censors scan for it (9443 or 443 work well)")
				}
				// Another relay instance on this server may hold it.
				for _, o := range plan.OtherInstances(app.opt.Host, a.setup().Instance()) {
					if slices.Contains(o.Doc.ORPortNumbers(), atoi(s)) {
						return fmt.Errorf("tor instance %s already uses port %d; every relay needs its own", o.Name, atoi(s))
					}
				}
				return nil
			}),
			huh.NewSelect[string]().Key("network.ipv6").Title("IPv6 ORPort").
				Description("Only enable IPv6 if the server really has working IPv6.").
				Options(ipv6Options()...).Value(&a.IPv6Choice),
		).WithHideFunc(a.isWebTunnel),
		huh.NewGroup(
			huh.NewInput().Key("network.ipv6manual").Title("IPv6 address").
				Placeholder("2001:db8::10").Value(&a.IPv6Manual).Validate(func(s string) error {
				if !relay.ValidIPv6(strings.TrimSpace(s)) {
					return errors.New("a global IPv6 address, without brackets or /prefix")
				}
				return nil
			}),
		).WithHideFunc(func() bool { return a.IPv6Choice != "manual" || a.isWebTunnel() }),

		huh.NewGroup(
			newConfirm().Key("exit.permission").
				Title("Does your provider allow Tor exits, and are you ready to handle abuse complaints?").
				Description("Exit operators receive complaints about their users' traffic. Get written permission first.").
				Affirmative("Yes, confirmed").Negative("No").
				Value(&a.ExitPermission).Validate(func(v bool) error {
				if !v {
					return errors.New("exits need provider permission — go back (shift+tab) and choose a guard relay instead")
				}
				return nil
			}),
			huh.NewSelect[string]().Key("exit.policy").Title("Exit policy").
				Options(exitPolicyOptions()...).Value(&a.ExitPolicy),
		).WithHideFunc(func() bool { return !isExit() }),
		huh.NewGroup(
			huh.NewText().Key("exit.custom").Title("Custom exit policy").
				Description("One rule per line, first match wins: accept|reject ADDR:PORT (*, *4, *6, private, 10.0.0.0/8, [2001:db8::]/32; ports 443, 6660-6669 or *). End with reject *:*.").
				Value(&a.ExitCustom).Lines(8).Validate(validExitPolicyText),
			huh.NewNote().Title("torrc").DescriptionFunc(func() string { return exitPolicyPreview(a) }, a),
		).WithHideFunc(func() bool { return !isExit() || a.ExitPolicy != string(relay.PolicyCustom) }),
		huh.NewGroup(
			newConfirm().Key("exit.ipv6exit").Title("Allow IPv6 exit traffic?").
				Description("Only used when an IPv6 ORPort is configured.").Value(&a.IPv6Exit),
			newConfirm().Key("exit.notice").Title("Serve an exit notice page on port 80?").
				Description("Tor's exit guidelines recommend a page explaining that this address is a Tor exit. tor serves it itself (DirPort 80, DirPortFrontPage); edit the page next to torrc afterwards.").
				Value(&a.ExitNotice),
			newConfirm().Key("exit.unbound").Title("Use a local Unbound resolver for exit DNS?").
				Description("Tor recommends a local caching, DNSSEC-validating resolver instead of public DNS.").Value(&a.Unbound),
			newConfirm().Key("exit.lock").Title("Lock /etc/resolv.conf with chattr +i afterwards?").Value(&a.LockResolv),
		).WithHideFunc(func() bool { return !isExit() }),

		huh.NewGroup(
			huh.NewSelect[string]().Key("bridge.transport").Title("Bridge transport").
				Description("Censors block bridges they can recognise. obfs4 makes the traffic look random; WebTunnel makes it look like visits to an ordinary HTTPS website.").
				Options(
					huh.NewOption("obfs4 — two open ports, nothing else needed (simplest)", string(relay.TransportObfs4)),
					huh.NewOption("WebTunnel — behind a website; needs a domain and a TLS certificate", string(relay.TransportWebTunnel)),
				).Value(&a.BridgeTransport),
		).WithHideFunc(func() bool { return !a.isBridge() }),
		huh.NewGroup(
			huh.NewInput().Key("bridge.obfs4port").Title("obfs4 port").
				Description("Must be reachable and differ from the ORPort; avoid 9001. Ports below 1024 (e.g. 443) pass more firewalls but need an extra capability.").
				Value(&a.Obfs4Port).Validate(func(s string) error {
				p := atoi(s)
				switch {
				case !relay.ValidPort(p):
					return errors.New("a TCP port from 1 to 65535")
				case p == atoi(a.ORPort):
					return errors.New("use a different port than the ORPort")
				case p == 9001:
					return errors.New("avoid 9001: censors scan for it")
				}
				return portFree(app, a, p)
			}),
			huh.NewSelect[string]().Key("bridge.obfs4dist").Title("How should Tor hand the bridge out?").
				Options(distributionOptions(false)...).Value(&a.Obfs4Dist),
		).WithHideFunc(func() bool { return !a.isBridge() || a.isWebTunnel() }),
		huh.NewGroup(
			huh.NewInput().Key("bridge.domain").Title("Domain for the WebTunnel website").
				Description("A DNS name whose A/AAAA records point at this server, e.g. bridge.example.org.").
				Placeholder("bridge.example.org").Value(&a.Domain).Validate(func(s string) error {
				if !relay.ValidDomain(strings.ToLower(strings.TrimSpace(s))) {
					return errors.New("a DNS name such as bridge.example.org")
				}
				return nil
			}),
			huh.NewInput().Key("bridge.path").Title("Secret path").
				Description("Only clients with this path reach the bridge; generated at random. Keep it secret.").
				Value(&a.WTPath).Validate(func(s string) error {
				if !relay.ValidWebTunnelPath(strings.TrimSpace(s)) {
					return errors.New("8–128 letters, digits, '.', '_', '~' or '-'")
				}
				return nil
			}),
			huh.NewSelect[string]().Key("bridge.webserver").Title("Web server").
				Options(
					huh.NewOption("Install and configure nginx for me", config.WebServerNginx),
					huh.NewOption("I run my own web server (show me the snippet)", config.WebServerManual),
				).Value(&a.WebServer),
			huh.NewSelect[string]().Key("bridge.wtdist").Title("How should Tor hand the bridge out?").
				Description("WebTunnel bridges are only given out through the https distributor (bridges.torproject.org).").
				Options(distributionOptions(true)...).Value(&a.WTDist),
		).WithHideFunc(func() bool { return !a.isWebTunnel() }),
		huh.NewGroup(
			huh.NewSelect[string]().Key("bridge.cert").Title("TLS certificate for nginx").
				Options(
					huh.NewOption("Request one from Let's Encrypt with certbot", config.CertCertbot),
					huh.NewOption("Use a certificate I already have", config.CertExisting),
				).Value(&a.Certificate),
		).WithHideFunc(func() bool { return !a.isWebTunnel() || a.WebServer != config.WebServerNginx }),
		huh.NewGroup(
			huh.NewInput().Key("bridge.certfile").Title("Certificate chain (PEM)").Placeholder("/etc/ssl/certs/bridge.pem").
				Value(&a.CertFile).Validate(func(s string) error { return existingFile(app, s) }),
			huh.NewInput().Key("bridge.keyfile").Title("Private key (PEM)").Placeholder("/etc/ssl/private/bridge.key").
				Value(&a.KeyFile).Validate(func(s string) error { return existingFile(app, s) }),
		).WithHideFunc(func() bool {
			return !a.isWebTunnel() || a.WebServer != config.WebServerNginx || a.Certificate != config.CertExisting
		}),
		huh.NewGroup(
			huh.NewInput().Key("bridge.certbotemail").Title("Email for Let's Encrypt (optional)").
				Description("Expiry and account notices. Leave it empty to register without one.").
				Value(&a.CertbotEmail).Validate(func(s string) error {
				if s = strings.TrimSpace(s); s != "" && !relay.ValidEmail(s) {
					return errors.New("an email address, or empty")
				}
				return nil
			}),
			newConfirm().Key("bridge.certbotagree").Title("Let certbot request the certificate and accept the Let's Encrypt Subscriber Agreement for you?").
				Description("certbot certonly --nginx contacts Let's Encrypt during apply; the domain must already point here and port 80 must be reachable. Terms: https://letsencrypt.org/repository/").
				Affirmative("Yes, I agree").Negative("No").Value(&a.CertbotAgree).Validate(func(v bool) error {
				if !v {
					return errors.New("without agreeing, go back (shift+tab) and use an existing certificate")
				}
				return nil
			}),
		).WithHideFunc(func() bool {
			return !a.isWebTunnel() || a.WebServer != config.WebServerNginx || a.Certificate != config.CertCertbot
		}),

		huh.NewGroup(
			huh.NewSelect[string]().Key("family.mode").Title("Relay family").
				Description("Relays run by the same operator share one family key (Tor 0.4.9 FamilyId).").
				Options(
					huh.NewOption(noFamilyLabel(a.Keep), "none"),
					huh.NewOption("Create a new family key — first relay of a family", "generate"),
					huh.NewOption("Import a family key copied from another relay", "import"),
				).Value(&a.FamilyMode),
		).WithHideFunc(a.isBridge),
		huh.NewGroup(
			huh.NewInput().Key("family.key").Title("Family key name").Value(&a.FamilyKey).
				Validate(func(s string) error {
					s = strings.TrimSpace(s)
					if !relay.ValidFamilyKeyName(s) {
						return errors.New("letters, digits, '.', '_' or '-' (max 64)")
					}
					// Existing keys are never overwritten, and all relays on
					// a server share one family: say so now rather than
					// failing halfway through the apply.
					check := a.setup()
					check.Family.KeyName = s
					if err := plan.CheckFamily(app.opt.Host, check); err != nil {
						if strings.Contains(err.Error(), "already exists") {
							return errors.New("a key with this name already exists on this server; choose another name, or import it instead")
						}
						return err
					}
					return nil
				}),
		).WithHideFunc(func() bool { return a.FamilyMode != "generate" || a.isBridge() }),
		huh.NewGroup(
			huh.NewInput().Key("family.import").Title("Path to NAME.secret_family_key").
				Placeholder("/root/relay-family.secret_family_key").Value(&a.FamilyImport).
				Validate(func(s string) error {
					data, err := os.ReadFile(strings.TrimSpace(s))
					if err != nil {
						return errors.New("cannot read that file")
					}
					if !strings.HasSuffix(s, ".secret_family_key") || !family.ValidKey(data) {
						return errors.New("not a Tor family key (96 bytes, *.secret_family_key)")
					}
					return nil
				}),
			huh.NewInput().Key("family.id").Title("FamilyId (only if no .public_family_id sits next to the key)").
				Value(&a.FamilyID).Validate(func(s string) error {
				s = strings.TrimSpace(s)
				pub := strings.TrimSuffix(strings.TrimSpace(a.FamilyImport), ".secret_family_key") + ".public_family_id"
				if _, err := os.Stat(pub); err == nil && s == "" {
					return nil
				}
				if !relay.ValidFamilyID(s) {
					return errors.New("43 base64 characters, as printed by tor --keygen-family")
				}
				return nil
			}),
		).WithHideFunc(func() bool { return a.FamilyMode != "import" || a.isBridge() }),

		huh.NewGroup(
			huh.NewSelect[string]().Key("bandwidth.mode").Title("Bandwidth").
				Options(bandwidthOptions(a.BandwidthMode)...).Value(&a.BandwidthMode),
		),
		huh.NewGroup(
			huh.NewInput().Key("bandwidth.quota").Title("Monthly traffic quota").
				Description("Decimal, as providers bill it: 10TB, 2.5TB, 5000GB. Use TiB/GiB for binary.").
				Placeholder("10TB").Value(&a.Quota).Validate(func(s string) error {
				if _, err := relay.ParseQuota(s); err != nil {
					return errors.New("a quota with a unit, e.g. 10TB or 5000GB (at least 1 GB)")
				}
				if a.BandwidthMode == string(relay.BandwidthSteady) {
					if _, err := a.setup().Bandwidth.Resolve(); errors.Is(err, relay.ErrBelowMinimum) {
						return errors.New("too small for Tor's 10 Mbit/s minimum when paced over a month")
					}
				}
				return nil
			}),
			huh.NewInput().Key("bandwidth.headroom").Title("Safety headroom (%)").
				Description("Kept free for provider overhead and other traffic.").Value(&a.Headroom).
				Validate(func(s string) error {
					if n := atoi(s); strings.TrimSpace(s) == "" || n < 0 || n > 50 {
						return errors.New("0 to 50")
					}
					return nil
				}),
			huh.NewSelect[string]().Key("bandwidth.billing").Title("How does your provider count traffic?").
				Options(
					huh.NewOption("Inbound + outbound combined (safest)", string(relay.RuleSum)),
					huh.NewOption("Outbound only", string(relay.RuleOut)),
					huh.NewOption("Each direction separately", string(relay.RuleMax)),
				).Value(&a.Billing),
			huh.NewNote().Title("Result").
				DescriptionFunc(a.budgetSummary, a),
		).WithHideFunc(func() bool {
			return a.BandwidthMode != string(relay.BandwidthSteady) && a.BandwidthMode != string(relay.BandwidthAccounting)
		}),
		huh.NewGroup(
			huh.NewInput().Key("bandwidth.rate").Title("Average rate (Mbit/s)").
				Description("Tor needs at least 10 Mbit/s; 16 or more is recommended.").Placeholder("16").
				Value(&a.RateMbit).Validate(func(s string) error {
				if atoi(s) < 1 {
					return errors.New("a whole number of Mbit/s")
				}
				return nil
			}),
			huh.NewInput().Key("bandwidth.burst").Title("Burst (Mbit/s, empty = 2× rate)").
				Value(&a.BurstMbit).Validate(func(s string) error {
				if strings.TrimSpace(s) != "" && atoi(s) < atoi(a.RateMbit) {
					return errors.New("at least the average rate")
				}
				return nil
			}),
		).WithHideFunc(func() bool { return a.BandwidthMode != string(relay.BandwidthManual) }),

		huh.NewGroup(
			huh.NewInput().Key("system.hostname").Title("Server hostname (empty keeps the current one)").
				Placeholder(app.checks.Facts.Hostname).
				Value(&a.Hostname).Validate(func(s string) error {
				if s = strings.TrimSpace(s); s != "" && !relay.ValidHostname(s) {
					return errors.New("letters, digits, hyphens and dots")
				}
				return nil
			}),
			newConfirm().Key("system.unattended").Title("Install security and Tor updates automatically?").
				Description("Strongly recommended for relays.").Value(&a.Unattended),
			newConfirm().Key("system.nyx").Title("Install Nyx, the terminal relay monitor?").Value(&a.Nyx),
			newConfirm().Key("system.metrics").Title("Enable MetricsPort on "+w.metrics+"?").
				Description("Local-only Prometheus metrics (overload, DNS errors). Never exposed publicly.").Value(&a.Metrics),
		),
		huh.NewGroup(
			newConfirm().Key("system.tuning").Title("Tune the kernel for a fast relay?").
				Description("For relays above ~100 Mbit/s: a wider ephemeral port range and a larger conntrack table (sysctl), and the open-file limit checked. Conservative values from Tor's documentation; nothing security-related is touched.").
				Value(&a.Tuning),
		).WithHideFunc(func() bool { return !plan.SuggestTuning(a.setup()) }),
		huh.NewGroup(
			huh.NewSelect[string]().Key("system.firewall").Title("Firewall").
				Description(firewallDesc()).
				Options(huh.NewOption("Configure it for me", "auto"), huh.NewOption("Leave the firewall alone", "none")).
				Value(&a.Firewall),
		),
		huh.NewGroup(
			newConfirm().Key("system.enableufw").Title("Enable UFW after adding the rules?").
				Description("SSH is allowed before UFW is switched on.").Value(&a.EnableUFW),
		).WithHideFunc(func() bool {
			fw := app.checks.Facts.Firewall
			return a.Firewall != "auto" || (fw.Kind != "" && fw.Kind != "none" && (fw.Kind != "ufw" || fw.Active))
		}),
		huh.NewGroup(
			newConfirm().Key("system.sandbox").Title("Enable Tor's syscall sandbox (Sandbox 1)?").
				Description("Extra hardening on Linux; supported on amd64 and arm64.").Value(&a.Sandbox),
		).WithHideFunc(a.isBridge), // tor refuses pluggable transports with Sandbox 1
	).WithTheme(app.theme.Form()).WithShowHelp(false).WithShowErrors(true)
	return f
}

// exitPolicyOptions lists the exit policy choices.
func exitPolicyOptions() []huh.Option[string] {
	return []huh.Option[string]{
		huh.NewOption("ReducedExitPolicy — tor's list of ~70 common services (recommended)", string(relay.PolicyReduced)),
		huh.NewOption("Web only — ports 80 and 443", string(relay.PolicyWeb)),
		huh.NewOption("Tor's default exit policy — everything but a few abuse-prone ports", string(relay.PolicyDefault)),
		huh.NewOption("Custom — write your own accept/reject rules", string(relay.PolicyCustom)),
	}
}

// validExitPolicyText validates the custom policy editor's text.
func validExitPolicyText(s string) error {
	_, err := relay.NormalizePolicy(relay.SplitPolicy(s))
	return err
}

// exitPolicyPreview shows the torrc lines a custom policy produces.
func exitPolicyPreview(a *answers) string {
	norm, err := relay.NormalizePolicy(relay.SplitPolicy(a.ExitCustom))
	if err != nil {
		return "…"
	}
	lines := make([]string, len(norm))
	for i, e := range norm {
		lines[i] = "ExitPolicy " + e
	}
	return strings.Join(lines, "\n")
}

// distributionOptions lists the BridgeDistribution choices; WebTunnel puts
// https first.
func distributionOptions(webTunnel bool) []huh.Option[string] {
	labels := map[string]string{
		"any":      "Let the Tor Project decide (any)",
		"https":    "bridges.torproject.org website (https)",
		"email":    "Email autoresponder (email)",
		"settings": "Tor Browser's built-in request (settings)",
		"telegram": "Telegram bot (telegram)",
		"none":     "Nobody — I share the bridge line myself (none)",
	}
	order := relay.Distributions
	if webTunnel {
		order = []string{"https", "none", "any", "email", "settings", "telegram"}
	}
	opts := make([]huh.Option[string], 0, len(order))
	for _, d := range order {
		opts = append(opts, huh.NewOption(labels[d], d))
	}
	return opts
}

// portFree reports an error when another relay instance on this server
// already uses port p.
func portFree(app *App, a *answers, p int) error {
	for _, o := range plan.OtherInstances(app.opt.Host, a.setup().Instance()) {
		if slices.Contains(o.Doc.ORPortNumbers(), p) || slices.Contains(o.Doc.BridgePorts(), p) {
			return fmt.Errorf("tor instance %s already uses port %d", o.Name, p)
		}
	}
	return nil
}

// existingFile checks that an absolute path names an existing file.
func existingFile(app *App, s string) error {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "/") {
		return errors.New("an absolute path")
	}
	if _, err := app.opt.Host.Stat(s); err != nil {
		return errors.New("no such file on this server")
	}
	return nil
}

func (w *wizard) init(a *App) tea.Cmd {
	if w.form == nil {
		return nil
	}
	return w.form.Init()
}

func (w *wizard) layout(a *App) (formWidth, sideWidth int) {
	total := a.contentWidth()
	if total < 110 {
		return total, 0
	}
	side := clamp(total*2/5, 44, 70)
	return total - side - 1, side
}

func (w *wizard) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	if w.form == nil {
		if !a.checks.FactsReady {
			return w, nil
		}
		w.form = w.build(a)
		fw, _ := w.layout(a)
		w.form = w.form.WithWidth(fw - 4)
		return w, w.form.Init()
	}
	switch msg.(type) {
	case tea.WindowSizeMsg:
		fw, _ := w.layout(a)
		w.form = w.form.WithWidth(fw - 4)
	case tea.BackgroundColorMsg:
		w.form = w.form.WithTheme(a.theme.Form())
	}
	m, cmd := w.form.Update(msg)
	if f, ok := m.(*huh.Form); ok {
		w.form = f
	}
	switch w.form.State {
	case huh.StateCompleted:
		s := w.ans.setup()
		return newReview(a, s, w), cmd
	case huh.StateAborted:
		return w, quit(ErrAborted)
	}
	return w, cmd
}

func (w *wizard) view(a *App) string {
	t := a.theme
	fw, sw := w.layout(a)
	if w.form == nil {
		return "\n " + a.spin.View() + " " + t.Subtle.Render("Inspecting this server…")
	}
	labels, cur := w.stepLabels(), w.currentStep()
	top := stepper(t, a.contentWidth(), labels, cur)
	left := panel(t, labels[cur]+instanceTitle(w.instance()), w.form.View(), fw, true)
	if sw == 0 {
		return top + "\n\n" + left
	}
	s := w.ans.setup()
	s.Relay.MetricsAddress = w.metrics
	cfg := s.RelayConfig(nil)
	preview := highlightTorrc(t, string(cfg.Render(program(a.opt.Version), time.Now())), sw-4)
	// Skip the generated-by header comment; it adds nothing here.
	preview = trimHeader(preview, 3)
	side := lipgloss.JoinVertical(lipgloss.Left,
		panel(t, "torrc preview", preview, sw, false),
		panel(t, "This server", a.checks.view(t, a.spin.View()), sw, false),
	)
	return top + "\n\n" + lipgloss.JoinHorizontal(lipgloss.Top, left, " ", side)
}

func (w *wizard) keys(a *App) []string {
	return []string{"enter", "next", "shift+tab", "back", "←/→", "choose", "ctrl+c", "quit"}
}

func trimHeader(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[n:]
	}
	return strings.TrimLeft(strings.Join(lines, "\n"), "\n")
}

// newConfirm is a yes/no field with left-aligned buttons.
func newConfirm() *huh.Confirm {
	return huh.NewConfirm().WithButtonAlignment(lipgloss.Left)
}

// noFamilyLabel names the "no new family" choice; when reconfiguring a
// relay that already has FamilyIds, that choice keeps them.
func noFamilyLabel(keep []string) string {
	if len(keep) == 0 {
		return "This is my only relay"
	}
	return fmt.Sprintf("Keep the current family (%d FamilyId)", len(keep))
}

// bandwidthOptions lists the bandwidth modes; "custom" only appears when the
// relay already has hand-written limits worth keeping.
func bandwidthOptions(current string) []huh.Option[string] {
	opts := []huh.Option[string]{
		huh.NewOption("Steady monthly budget — pace a VPS traffic quota (recommended)", string(relay.BandwidthSteady)),
		huh.NewOption("Manual rate and burst in Mbit/s", string(relay.BandwidthManual)),
		huh.NewOption("Hard AccountingMax only — full speed, then hibernate", string(relay.BandwidthAccounting)),
		huh.NewOption("No limit", string(relay.BandwidthNone)),
	}
	if current == config.BandwidthCustom {
		opts = append([]huh.Option[string]{huh.NewOption("Keep the current limits from torrc", config.BandwidthCustom)}, opts...)
	}
	return opts
}

// describeBandwidth summarises resolved limits in one line.
func describeBandwidth(bw relay.Bandwidth) string {
	var parts []string
	switch {
	case bw.RateKBytes > 0:
		parts = append(parts, fmt.Sprintf("RelayBandwidthRate %d KBytes (≈ %.1f Mbit/s), burst %d KBytes", bw.RateKBytes, relay.MbitFromKBytes(bw.RateKBytes), bw.BurstKBytes))
	case bw.RateMbit > 0:
		parts = append(parts, fmt.Sprintf("%d Mbit/s, burst %d", bw.RateMbit, bw.BurstMbit))
	}
	if bw.AccountingMaxGBytes > 0 {
		parts = append(parts, fmt.Sprintf("AccountingMax %d GBytes/month (%s)", bw.AccountingMaxGBytes, bw.AccountingRule))
	}
	if len(parts) == 0 {
		return "no limit"
	}
	return strings.Join(parts, " · ")
}
