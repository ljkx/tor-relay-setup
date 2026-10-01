package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
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
	IPv6Exit       bool
	Unbound        bool
	LockResolv     bool

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
}

func answersFrom(s config.Setup) *answers {
	a := &answers{
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
	}
	s.Exit = config.Exit{
		ProviderPermission: a.ExitPermission,
		Policy:             a.ExitPolicy,
		IPv6Exit:           a.IPv6Exit,
		Unbound:            a.Unbound,
		LockResolvConf:     a.LockResolv,
	}
	s.Family = config.Family{
		Mode: a.FamilyMode, KeyName: strings.TrimSpace(a.FamilyKey), ImportKey: strings.TrimSpace(a.FamilyImport),
		FamilyID: strings.TrimSpace(a.FamilyID), Keep: append([]string(nil), a.Keep...),
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
}

func newWizard(a *App, prefill config.Setup) *wizard {
	w := &wizard{ans: answersFrom(prefill)}
	if a.checks.FactsReady {
		w.form = w.build(a)
	}
	return w
}

// Step labels shown in the stepper, keyed by field-key prefix.
var wizardSteps = []struct{ prefix, label string }{
	{"relay", "Relay"},
	{"contact", "Contact"},
	{"network", "Network"},
	{"exit", "Exit"},
	{"family", "Family"},
	{"bandwidth", "Bandwidth"},
	{"system", "System"},
}

func (w *wizard) stepLabels() []string {
	var out []string
	for _, s := range wizardSteps {
		if s.prefix == "exit" && w.ans.Mode != string(relay.ModeExit) {
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
		if s.prefix == "exit" && w.ans.Mode != string(relay.ModeExit) {
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

	f := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Key("relay.mode").Title("What kind of relay?").
				Options(
					huh.NewOption("Guard / middle relay — forwards traffic inside Tor (recommended)", string(relay.ModeGuard)),
					huh.NewOption("Exit relay — connects Tor users to the Internet (needs provider permission)", string(relay.ModeExit)),
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
		),

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
				return nil
			}),
			huh.NewSelect[string]().Key("network.ipv6").Title("IPv6 ORPort").
				Description("Only enable IPv6 if the server really has working IPv6.").
				Options(ipv6Options()...).Value(&a.IPv6Choice),
		),
		huh.NewGroup(
			huh.NewInput().Key("network.ipv6manual").Title("IPv6 address").
				Placeholder("2001:db8::10").Value(&a.IPv6Manual).Validate(func(s string) error {
				if !relay.ValidIPv6(strings.TrimSpace(s)) {
					return errors.New("a global IPv6 address, without brackets or /prefix")
				}
				return nil
			}),
		).WithHideFunc(func() bool { return a.IPv6Choice != "manual" }),

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
				Options(
					huh.NewOption("ReducedExitPolicy — common ports only (recommended)", string(relay.PolicyReduced)),
					huh.NewOption("Tor's default exit policy — broader", string(relay.PolicyDefault)),
				).Value(&a.ExitPolicy),
			newConfirm().Key("exit.ipv6exit").Title("Allow IPv6 exit traffic?").
				Description("Only used when an IPv6 ORPort is configured.").Value(&a.IPv6Exit),
			newConfirm().Key("exit.unbound").Title("Use a local Unbound resolver for exit DNS?").
				Description("Tor recommends a local caching, DNSSEC-validating resolver instead of public DNS.").Value(&a.Unbound),
			newConfirm().Key("exit.lock").Title("Lock /etc/resolv.conf with chattr +i afterwards?").Value(&a.LockResolv),
		).WithHideFunc(func() bool { return !isExit() }),

		huh.NewGroup(
			huh.NewSelect[string]().Key("family.mode").Title("Relay family").
				Description("Relays run by the same operator share one family key (Tor 0.4.9 FamilyId).").
				Options(
					huh.NewOption(noFamilyLabel(a.Keep), "none"),
					huh.NewOption("Create a new family key — first relay of a family", "generate"),
					huh.NewOption("Import a family key copied from another relay", "import"),
				).Value(&a.FamilyMode),
		),
		huh.NewGroup(
			huh.NewInput().Key("family.key").Title("Family key name").Value(&a.FamilyKey).
				Validate(func(s string) error {
					s = strings.TrimSpace(s)
					if !relay.ValidFamilyKeyName(s) {
						return errors.New("letters, digits, '.', '_' or '-' (max 64)")
					}
					// Existing keys are never overwritten, so say so now
					// rather than failing halfway through the apply.
					path := family.KeyDirectory("", "", "/var/lib/tor") + "/" + s + ".secret_family_key"
					if _, err := app.opt.Host.Stat(path); err == nil {
						return errors.New("a key with this name already exists on this server; choose another name, or import it instead")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return a.FamilyMode != "generate" }),
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
		).WithHideFunc(func() bool { return a.FamilyMode != "import" }),

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
			newConfirm().Key("system.metrics").Title("Enable MetricsPort on 127.0.0.1:9035?").
				Description("Local-only Prometheus metrics (overload, DNS errors). Never exposed publicly.").Value(&a.Metrics),
		),
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
		),
	).WithTheme(app.theme.Form()).WithShowHelp(false).WithShowErrors(true)
	return f
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
	left := panel(t, labels[cur], w.form.View(), fw, true)
	if sw == 0 {
		return top + "\n\n" + left
	}
	cfg := w.ans.setup().RelayConfig(nil)
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
