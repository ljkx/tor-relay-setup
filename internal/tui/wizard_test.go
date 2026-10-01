package tui

import (
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

func TestAnswersRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*config.Setup)
	}{
		{"default guard", func(*config.Setup) {}},
		{"exit with every exit option changed", func(s *config.Setup) {
			s.Relay.Mode, s.Relay.ORPort, s.Relay.IPv6 = "exit", 443, "2001:db8::1"
			s.Relay.MetricsPort, s.Relay.Sandbox = true, false
			s.Exit = config.Exit{ProviderPermission: true, Policy: "default", IPv6Exit: false, Unbound: false, LockResolvConf: true}
		}},
		{"family generate", func(s *config.Setup) { s.Family.Mode, s.Family.KeyName = "generate", "fam-1" }},
		{"family import", func(s *config.Setup) {
			s.Family = config.Family{Mode: "import", KeyName: "relay-family", ImportKey: "/root/x.secret_family_key", FamilyID: famID("Z")}
		}},
		{"manual bandwidth", func(s *config.Setup) {
			s.Bandwidth = config.BandwidthPlan{Mode: "manual", RateMbit: 20, BurstMbit: 50, Billing: "out"}
		}},
		{"manual bandwidth with default burst", func(s *config.Setup) {
			s.Bandwidth = config.BandwidthPlan{Mode: "manual", RateMbit: 20, HeadroomPercent: 10, Billing: "sum"}
		}},
		{"accounting", func(s *config.Setup) {
			s.Bandwidth = config.BandwidthPlan{Mode: "accounting", MonthlyQuota: "5000GB", HeadroomPercent: 25, Billing: "max"}
		}},
		{"no limit", func(s *config.Setup) { s.Bandwidth = config.BandwidthPlan{Mode: "none", Billing: "sum"} }},
		{"system choices", func(s *config.Setup) {
			s.System = config.System{Hostname: "relay.example.org", UnattendedUpgrades: false, Nyx: false, Firewall: "none", EnableUFW: false}
		}},
		{"no contact yet", func(s *config.Setup) { s.Relay.Contact = "" }},
		{"CIISS contact kept verbatim", func(s *config.Setup) {
			s.Relay.Contact = relay.BuildCIISS("ops@example.org", "https://example.org", "hetzner.com")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := testSetup()
			tt.mutate(&s)
			if got := answersFrom(s).setup(); !reflect.DeepEqual(got, s) {
				t.Errorf("answersFrom(s).setup() changed the setup:\n got %+v\nwant %+v", got, s)
			}
		})
	}
}

func TestAnswersRoundTripKeepsFamilyIDs(t *testing.T) {
	t.Parallel()
	s := testSetup()
	s.Family.Keep = []string{famID("A"), famID("B")}
	if got := answersFrom(s).setup(); !reflect.DeepEqual(got.Family.Keep, s.Family.Keep) {
		t.Errorf("Family.Keep = %v, want %v", got.Family.Keep, s.Family.Keep)
	}
}

func TestAnswersNormalisation(t *testing.T) {
	t.Parallel()
	s := testSetup()
	s.Family.Mode = ""
	a := answersFrom(s)
	if a.FamilyMode != "none" {
		t.Errorf("empty family mode became %q, want none", a.FamilyMode)
	}
	if a.ContactFormat != "free" || a.ContactFree != "tor-ops@example.org" {
		t.Errorf("existing contact should prefill free text, got %q / %q", a.ContactFormat, a.ContactFree)
	}
	if a.IPv6Choice != "none" {
		t.Errorf("IPv6Choice = %q, want none", a.IPv6Choice)
	}

	a.Nickname, a.FamilyKey, a.Quota, a.Hostname = "  Spaced  ", " k ", " 10TB ", " host.example "
	got := a.setup()
	if got.Relay.Nickname != "Spaced" || got.Family.KeyName != "k" || got.Bandwidth.MonthlyQuota != "10TB" || got.System.Hostname != "host.example" {
		t.Errorf("setup() did not trim inputs: %+v", got)
	}
	a.ORPort, a.Headroom = "not a port", ""
	if got := a.setup(); got.Relay.ORPort != 0 || got.Bandwidth.HeadroomPercent != 0 {
		t.Errorf("unparsable numbers should become 0, got port %d headroom %d", got.Relay.ORPort, got.Bandwidth.HeadroomPercent)
	}
}

func TestAnswersContact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a    answers
		want string
	}{
		{"free text is trimmed", answers{ContactFormat: "free", ContactFree: "  me at example  "}, "me at example"},
		{"CIISS email only", answers{ContactFormat: "ciiss", Email: " ops@example.org "}, "email:ops[]example.org ciissversion:3"},
		{"CIISS with url and hoster", answers{ContactFormat: "ciiss", Email: "ops@example.org", URL: "https://example.org", Hoster: "hetzner.com"},
			"email:ops[]example.org url:https://example.org proof:uri-familyid-ed25519 hoster:hetzner.com ciissversion:3"},
		{"CIISS without email is empty", answers{ContactFormat: "ciiss", URL: "https://example.org"}, ""},
	}
	for _, tt := range tests {
		if got := tt.a.contact(); got != tt.want {
			t.Errorf("%s: contact() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestAnswersIPv6(t *testing.T) {
	t.Parallel()
	tests := []struct {
		choice, manual, want string
	}{
		{"", "", ""},
		{"none", "2001:db8::9", ""},
		{"manual", " 2001:db8::9 ", "2001:db8::9"},
		{"2001:db8::5", "ignored", "2001:db8::5"},
	}
	for _, tt := range tests {
		a := answers{IPv6Choice: tt.choice, IPv6Manual: tt.manual}
		if got := a.ipv6(); got != tt.want {
			t.Errorf("ipv6(choice %q, manual %q) = %q, want %q", tt.choice, tt.manual, got, tt.want)
		}
	}
}

func TestBudgetSummary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                           string
		mode, quota, headroom, billing string
		want                           []string
		notWant                        []string
	}{
		{
			name: "steady 10TB", mode: "steady", quota: "10TB", headroom: "10", billing: "sum",
			want: []string{
				"≈ 13.4 Mbit/s steady (RelayBandwidthRate 1640 KBytes, burst 8200 KBytes)",
				"AccountingMax 8381 GBytes/month as a safety fuse · 4190 GBytes per direction",
				"Tor recommends 16 Mbit/s or more",
			},
		},
		{
			name: "steady 20TB is above the recommendation", mode: "steady", quota: "20TB", headroom: "10", billing: "sum",
			want:    []string{"≈ 26.9 Mbit/s steady", "RelayBandwidthRate 3281 KBytes"},
			notWant: []string{"recommends"},
		},
		{
			name: "steady below minimum", mode: "steady", quota: "1TB", headroom: "10", billing: "sum",
			want: []string{"≈ 1.3 Mbit/s — below Tor's 10 Mbit/s minimum"},
		},
		{
			name: "steady unreadable quota", mode: "steady", quota: "lots", headroom: "10", billing: "sum",
			want: []string{"Enter a monthly quota such as 10TB"},
		},
		{
			name: "steady bad billing rule", mode: "steady", quota: "10TB", headroom: "10", billing: "both",
			want: []string{"unknown billing rule"},
		},
		{
			name: "accounting", mode: "accounting", quota: "5000GB", headroom: "10", billing: "max",
			want: []string{"AccountingMax 4190 GBytes per month", "hibernates once the quota is used"},
		},
		{
			name: "accounting bad quota", mode: "accounting", quota: "5 apples", headroom: "10", billing: "max",
			want: []string{"monthly_quota"},
		},
		{name: "manual shows nothing", mode: "manual", quota: "10TB", headroom: "10", billing: "sum"},
		{name: "none shows nothing", mode: "none", quota: "10TB", headroom: "10", billing: "sum"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := answersFrom(testSetup())
			a.BandwidthMode, a.Quota, a.Headroom, a.Billing = tt.mode, tt.quota, tt.headroom, tt.billing
			got := a.budgetSummary()
			if len(tt.want) == 0 && got != "" {
				t.Errorf("budgetSummary() = %q, want empty", got)
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("budgetSummary() = %q, want it to contain %q", got, w)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(got, w) {
					t.Errorf("budgetSummary() = %q, should not contain %q", got, w)
				}
			}
		})
	}
}

func TestWizardStepLabels(t *testing.T) {
	t.Parallel()
	w := &wizard{ans: answersFrom(testSetup())}
	guard := w.stepLabels()
	if want := []string{"Relay", "Contact", "Network", "Family", "Bandwidth", "System", "Review"}; !reflect.DeepEqual(guard, want) {
		t.Errorf("guard labels = %v, want %v", guard, want)
	}
	w.ans.Mode = "exit"
	if exit := w.stepLabels(); len(exit) != 8 || exit[3] != "Exit" {
		t.Errorf("exit labels = %v, want Exit as the fourth step", exit)
	}
}

func TestWizardLayout(t *testing.T) {
	t.Parallel()
	a := testApp()
	w := &wizard{ans: answersFrom(testSetup())}
	a.width = 100
	if form, side := w.layout(a); side != 0 || form != a.contentWidth() {
		t.Errorf("narrow layout = %d/%d, want the full width and no side panel", form, side)
	}
	a.width = 160
	form, side := w.layout(a)
	if side < 44 || side > 70 || form+side+1 != a.contentWidth() {
		t.Errorf("wide layout = %d/%d for content width %d", form, side, a.contentWidth())
	}
}

func TestNewWizardWaitsForFacts(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.checks.FactsReady = false
	w := newWizard(a, testSetup())
	if w.form != nil {
		t.Fatal("the form was built before the server facts arrived")
	}
	if got := strip(w.view(a)); !strings.Contains(got, "Inspecting this server") {
		t.Errorf("view before facts = %q", got)
	}

	a.checks.FactsReady = true
	w = newWizard(a, testSetup())
	if w.form == nil {
		t.Fatal("the form was not built although facts are ready")
	}
	w.init(a) // the returned command only blinks the cursor
	if next, _ := w.update(a, tea.WindowSizeMsg{Width: a.width, Height: a.height}); next != w {
		t.Fatalf("a resize left the wizard for %T", next)
	}
	view := strip(w.view(a))
	for _, want := range []string{"Relay", "What kind of relay?"} {
		if !strings.Contains(view, want) {
			t.Errorf("wizard view lacks %q:\n%s", want, view)
		}
	}
	a.width = 160
	view = strip(w.view(a))
	for _, want := range []string{"torrc preview", "Nickname TestRelay", "This server", "Debian GNU/Linux 12 (bookworm)"} {
		if !strings.Contains(view, want) {
			t.Errorf("wide wizard view lacks %q:\n%s", want, view)
		}
	}
}
