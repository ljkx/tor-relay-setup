package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/relay"
)

var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// famID returns a syntactically valid FamilyId made of one repeated character.
func famID(c string) string { return strings.Repeat(c, 43) }

// validGuard returns Default() with the two answers that have no default.
func validGuard() Setup {
	s := Default()
	s.Relay.Nickname = "TestRelay"
	s.Relay.Contact = "tor-ops@example.org"
	s.Bandwidth.MonthlyQuota = "10TB"
	return s
}

func TestDefaultValidatesOnceIdentityIsSet(t *testing.T) {
	t.Parallel()

	if err := Default().Validate(); err == nil {
		t.Fatal("Default().Validate() = nil, want errors for the missing nickname and contact")
	} else {
		for _, want := range []string{"relay.nickname", "relay.contact"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Default().Validate() = %q, want it to mention %s", err, want)
			}
		}
	}

	s := Default()
	s.Relay.Nickname = "TestRelay"
	s.Relay.Contact = "tor-ops@example.org"
	// Default uses steady bandwidth, which needs a quota.
	s.Bandwidth.MonthlyQuota = "10TB"
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	d := Default()
	if d.Relay.ORPort != 9001 || d.Relay.Mode != "guard" || !d.Relay.Sandbox {
		t.Errorf("Default relay = %+v, want ORPort 9001, guard, sandbox on", d.Relay)
	}
	if d.Family.Mode != "none" || d.System.Firewall != "auto" || !d.System.UnattendedUpgrades {
		t.Errorf("Default = %+v, want family none, firewall auto, unattended upgrades", d)
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		toml string
		want string
	}{
		{"unknown key in known table", "[relay]\nnickname = \"A\"\nnickame = \"typo\"\n", "relay.nickame"},
		{"unknown table", "[relays]\nnickname = \"A\"\n", "relays"},
		{"unknown top-level key", "debug = true\n", "debug"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tt.toml))
			if err == nil {
				t.Fatal("Parse() = nil error, want unknown key error")
			}
			if !strings.Contains(err.Error(), "unknown config keys") || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Parse() error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"[relay\n", "[relay]\nor_port = \"nine\"\n"} {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), "parse config") {
			t.Errorf("Parse(%q) error = %v, want a parse config error", in, err)
		}
	}
}

func TestParseAppliesDefaultsForMissingKeys(t *testing.T) {
	t.Parallel()
	s, err := Parse([]byte("[relay]\nnickname = \"OnlyName\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.Relay.Nickname = "OnlyName"
	if !reflect.DeepEqual(s, want) {
		t.Errorf("Parse() = %+v, want defaults plus nickname: %+v", s, want)
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	t.Parallel()
	custom := Setup{
		Relay: Relay{
			Nickname: "RoundTrip", Contact: `email:ops[]example.org "quoted" \ back`, ORPort: 443,
			Mode: "exit", IPv6: "2001:db8::10", Sandbox: false, MetricsPort: true, Instance: "relay2",
		},
		Exit:      Exit{ProviderPermission: true, Policy: "default", IPv6Exit: false, Unbound: false, LockResolvConf: true},
		Family:    Family{Mode: "import", KeyName: "fam", ImportKey: "/root/fam.secret_family_key", FamilyID: famID("Q"), Keep: []string{famID("A"), famID("B")}},
		Bandwidth: BandwidthPlan{Mode: "manual", MonthlyQuota: "", HeadroomPercent: 0, Billing: "out", RateMbit: 25, BurstMbit: 60},
		System:    System{Hostname: "relay.example.org", UnattendedUpgrades: false, Nyx: false, Firewall: "none", EnableUFW: false, Tuning: true},
	}
	for name, s := range map[string]Setup{"default": Default(), "valid guard": validGuard(), "every field changed": custom} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := s.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(data), "# tor-relay-setup configuration.") {
				t.Errorf("Marshal() lacks the header comment:\n%s", data)
			}
			got, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse(Marshal()) error: %v\n%s", err, data)
			}
			if !reflect.DeepEqual(got, s) {
				t.Errorf("round trip mismatch:\n got %+v\nwant %+v\nTOML:\n%s", got, s, data)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.toml")
	data, err := validGuard().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, validGuard()) {
		t.Errorf("Load() = %+v, want %+v", got, validGuard())
	}
	if _, err := Load(filepath.Join(dir, "missing.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load(missing) error = %v, want not-exist", err)
	}
}

func TestValidateReportsEachProblem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Setup)
		want   string // substring of the error; "" means valid
	}{
		{"valid guard", func(*Setup) {}, ""},
		{"valid exit", func(s *Setup) { s.Relay.Mode = "exit"; s.Exit.ProviderPermission = true }, ""},
		{"exit without provider permission", func(s *Setup) { s.Relay.Mode = "exit" }, "exit.provider_permission"},
		{"exit with bad policy", func(s *Setup) { s.Relay.Mode = "exit"; s.Exit.ProviderPermission = true; s.Exit.Policy = "open" }, "exit.policy"},
		{"guard ignores exit settings", func(s *Setup) { s.Exit.Policy = "open" }, ""},
		{"nickname with space", func(s *Setup) { s.Relay.Nickname = "bad name" }, "relay.nickname"},
		{"nickname too long", func(s *Setup) { s.Relay.Nickname = strings.Repeat("a", 20) }, "relay.nickname"},
		{"contact with hash", func(s *Setup) { s.Relay.Contact = "ops #1" }, "relay.contact"},
		{"port zero", func(s *Setup) { s.Relay.ORPort = 0 }, "relay.or_port"},
		{"port too high", func(s *Setup) { s.Relay.ORPort = 65536 }, "relay.or_port"},
		{"bad mode", func(s *Setup) { s.Relay.Mode = "middle" }, "relay.mode"},
		{"link-local IPv6", func(s *Setup) { s.Relay.IPv6 = "fe80::1" }, "relay.ipv6"},
		{"bracketed IPv6", func(s *Setup) { s.Relay.IPv6 = "[2001:db8::1]" }, "relay.ipv6"},
		{"bad family mode", func(s *Setup) { s.Family.Mode = "join" }, "family.mode"},
		{"empty family mode is none", func(s *Setup) { s.Family.Mode = "" }, ""},
		{"generate with bad key name", func(s *Setup) { s.Family.Mode = "generate"; s.Family.KeyName = "../evil" }, "family.key_name"},
		{"import key without suffix", func(s *Setup) { s.Family.Mode = "import"; s.Family.ImportKey = "/root/fam.key" }, "family.import_key"},
		{"import with bad family id", func(s *Setup) {
			s.Family.Mode = "import"
			s.Family.ImportKey = "/root/fam.secret_family_key"
			s.Family.FamilyID = "short"
		}, "family.family_id"},
		{"import without family id is allowed", func(s *Setup) {
			s.Family.Mode = "import"
			s.Family.ImportKey = "/root/fam.secret_family_key"
		}, ""},
		{"bad bandwidth", func(s *Setup) { s.Bandwidth.MonthlyQuota = "lots" }, "bandwidth:"},
		{"bad hostname", func(s *Setup) { s.System.Hostname = "-bad-.example" }, "system.hostname"},
		{"localhost hostname", func(s *Setup) { s.System.Hostname = "localhost" }, "system.hostname"},
		{"bad firewall", func(s *Setup) { s.System.Firewall = "iptables" }, "system.firewall"},
		{"empty firewall is auto", func(s *Setup) { s.System.Firewall = "" }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := validGuard()
			tt.mutate(&s)
			err := s.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case tt.want != "" && err == nil:
				t.Fatalf("Validate() = nil, want error mentioning %q", tt.want)
			case tt.want != "" && !strings.Contains(err.Error(), tt.want):
				t.Fatalf("Validate() = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestValidateCollectsAllErrors(t *testing.T) {
	t.Parallel()
	s := validGuard()
	s.Relay.Nickname = "not valid!"
	s.Relay.Mode = "middle"
	s.Family.Mode = "join"
	s.System.Hostname = "under_score"
	s.Bandwidth.Mode = "turbo"
	err := s.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want several errors")
	}
	want := []string{"relay.nickname", "relay.mode", "family.mode", "system.hostname", "bandwidth:"}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("Validate() = %q, missing %q", err, w)
		}
	}
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) != len(want) {
		t.Errorf("Validate() should join %d separate errors, got %v", len(want), err)
	}

	// An exit and an import problem in the same config are both reported.
	s = validGuard()
	s.Relay.Mode = "exit"
	s.Family.Mode = "import"
	s.Family.ImportKey = "/root/fam.pem"
	err = s.Validate()
	for _, w := range []string{"exit.provider_permission", "family.import_key"} {
		if err == nil || !strings.Contains(err.Error(), w) {
			t.Errorf("Validate() = %v, missing %q", err, w)
		}
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		plan    BandwidthPlan
		want    relay.Bandwidth
		wantErr string
	}{
		{
			name: "steady 10TB 10% sum",
			plan: BandwidthPlan{Mode: "steady", MonthlyQuota: "10TB", HeadroomPercent: 10, Billing: "sum"},
			// 10 TB = 9313 GiB; 90% = 8381; half per direction = 4190 GiB over 31 days.
			want: relay.Bandwidth{Mode: relay.BandwidthSteady, RateKBytes: 1640, BurstKBytes: 8200, AccountingMaxGBytes: 8381, AccountingRule: relay.RuleSum},
		},
		{
			name: "steady 10TB 10% max doubles the per-direction budget",
			plan: BandwidthPlan{Mode: "steady", MonthlyQuota: "10TB", HeadroomPercent: 10, Billing: "max"},
			want: relay.Bandwidth{Mode: relay.BandwidthSteady, RateKBytes: 3281, BurstKBytes: 16405, AccountingMaxGBytes: 8381, AccountingRule: relay.RuleMax},
		},
		{name: "steady bad quota", plan: BandwidthPlan{Mode: "steady", MonthlyQuota: "ten", HeadroomPercent: 10, Billing: "sum"}, wantErr: "monthly_quota"},
		{name: "steady below minimum", plan: BandwidthPlan{Mode: "steady", MonthlyQuota: "1TB", HeadroomPercent: 10, Billing: "sum"}, wantErr: "below the relay minimum"},
		{name: "steady bad billing", plan: BandwidthPlan{Mode: "steady", MonthlyQuota: "10TB", HeadroomPercent: 10, Billing: "both"}, wantErr: "billing rule"},
		{name: "steady headroom too high", plan: BandwidthPlan{Mode: "steady", MonthlyQuota: "10TB", HeadroomPercent: 60, Billing: "sum"}, wantErr: "headroom"},
		{
			name: "manual burst defaults to twice the rate",
			plan: BandwidthPlan{Mode: "manual", RateMbit: 20},
			want: relay.Bandwidth{Mode: relay.BandwidthManual, RateMbit: 20, BurstMbit: 40},
		},
		{
			name: "manual explicit burst",
			plan: BandwidthPlan{Mode: "manual", RateMbit: 20, BurstMbit: 20},
			want: relay.Bandwidth{Mode: relay.BandwidthManual, RateMbit: 20, BurstMbit: 20},
		},
		{name: "manual burst below rate", plan: BandwidthPlan{Mode: "manual", RateMbit: 20, BurstMbit: 10}, wantErr: "burst_mbit"},
		{name: "manual zero rate", plan: BandwidthPlan{Mode: "manual"}, wantErr: "rate_mbit"},
		{
			name: "accounting applies headroom",
			plan: BandwidthPlan{Mode: "accounting", MonthlyQuota: "5000GB", HeadroomPercent: 10, Billing: "out"},
			// 5000 GB = 4656 GiB; 90% = 4190.
			want: relay.Bandwidth{Mode: relay.BandwidthAccounting, AccountingMaxGBytes: 4190, AccountingRule: relay.RuleOut},
		},
		{
			name: "accounting headroom 0",
			plan: BandwidthPlan{Mode: "accounting", MonthlyQuota: "100GiB", HeadroomPercent: 0, Billing: "max"},
			want: relay.Bandwidth{Mode: relay.BandwidthAccounting, AccountingMaxGBytes: 100, AccountingRule: relay.RuleMax},
		},
		{
			name: "accounting headroom 50",
			plan: BandwidthPlan{Mode: "accounting", MonthlyQuota: "100GiB", HeadroomPercent: 50, Billing: "sum"},
			want: relay.Bandwidth{Mode: relay.BandwidthAccounting, AccountingMaxGBytes: 50, AccountingRule: relay.RuleSum},
		},
		{name: "accounting headroom negative", plan: BandwidthPlan{Mode: "accounting", MonthlyQuota: "100GiB", HeadroomPercent: -1}, wantErr: "headroom_percent"},
		{name: "accounting headroom above 50", plan: BandwidthPlan{Mode: "accounting", MonthlyQuota: "100GiB", HeadroomPercent: 51}, wantErr: "headroom_percent"},
		{name: "accounting nothing left after headroom", plan: BandwidthPlan{Mode: "accounting", MonthlyQuota: "1GiB", HeadroomPercent: 10}, wantErr: "below 1 GByte"},
		{name: "accounting bad quota", plan: BandwidthPlan{Mode: "accounting", MonthlyQuota: "0.5GB"}, wantErr: "monthly_quota"},
		{name: "none", plan: BandwidthPlan{Mode: "none", MonthlyQuota: "garbage"}, want: relay.Bandwidth{Mode: relay.BandwidthNone}},
		{name: "empty mode means none", plan: BandwidthPlan{}, want: relay.Bandwidth{Mode: relay.BandwidthNone}},
		{name: "invalid mode", plan: BandwidthPlan{Mode: "turbo"}, wantErr: "must be steady, manual, accounting, custom or none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.plan.Resolve()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Resolve() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Resolve() = %+v, want %+v", got, tt.want)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("resolved bandwidth does not validate: %v", err)
			}
		})
	}
}

func TestRelayConfig(t *testing.T) {
	t.Parallel()
	a, b, c := famID("A"), famID("B"), famID("C")
	tests := []struct {
		name   string
		mutate func(*Setup)
		ids    []string
		check  func(t *testing.T, cfg relay.Config)
	}{
		{
			name: "IPv6Exit for exit with IPv6",
			mutate: func(s *Setup) {
				s.Relay.Mode, s.Exit.ProviderPermission, s.Relay.IPv6, s.Exit.IPv6Exit = "exit", true, "2001:db8::1", true
			},
			check: func(t *testing.T, cfg relay.Config) {
				if !cfg.IPv6Exit || cfg.Mode != relay.ModeExit || cfg.IPv6Address != "2001:db8::1" {
					t.Errorf("cfg = %+v, want exit with IPv6Exit", cfg)
				}
			},
		},
		{
			name:   "no IPv6Exit for exit without IPv6",
			mutate: func(s *Setup) { s.Relay.Mode, s.Exit.ProviderPermission, s.Exit.IPv6Exit = "exit", true, true },
			check: func(t *testing.T, cfg relay.Config) {
				if cfg.IPv6Exit {
					t.Error("IPv6Exit set without an IPv6 address")
				}
			},
		},
		{
			name:   "no IPv6Exit for guard with IPv6",
			mutate: func(s *Setup) { s.Relay.IPv6, s.Exit.IPv6Exit = "2001:db8::1", true },
			check: func(t *testing.T, cfg relay.Config) {
				if cfg.IPv6Exit || cfg.Mode != relay.ModeGuard {
					t.Errorf("cfg = %+v, want guard without IPv6Exit", cfg)
				}
			},
		},
		{
			name: "no IPv6Exit when the operator declined it",
			mutate: func(s *Setup) {
				s.Relay.Mode, s.Exit.ProviderPermission, s.Relay.IPv6, s.Exit.IPv6Exit = "exit", true, "2001:db8::1", false
			},
			check: func(t *testing.T, cfg relay.Config) {
				if cfg.IPv6Exit {
					t.Error("IPv6Exit set although exit.ipv6_exit is false")
				}
			},
		},
		{
			name:   "generate without ids renders a placeholder",
			mutate: func(s *Setup) { s.Family.Mode = "generate" },
			check: func(t *testing.T, cfg relay.Config) {
				if !cfg.FamilyPending || len(cfg.FamilyIDs) != 0 {
					t.Errorf("cfg = %+v, want FamilyPending and no ids", cfg)
				}
			},
		},
		{
			name:   "generate with the generated id",
			mutate: func(s *Setup) { s.Family.Mode = "generate" },
			ids:    []string{c},
			check: func(t *testing.T, cfg relay.Config) {
				if cfg.FamilyPending || !reflect.DeepEqual(cfg.FamilyIDs, []string{c}) {
					t.Errorf("cfg = %+v, want FamilyIDs [C] without placeholder", cfg)
				}
			},
		},
		{
			name:   "import uses the configured FamilyID",
			mutate: func(s *Setup) { s.Family.Mode, s.Family.FamilyID = "import", b },
			check: func(t *testing.T, cfg relay.Config) {
				if !reflect.DeepEqual(cfg.FamilyIDs, []string{b}) || cfg.FamilyPending {
					t.Errorf("FamilyIDs = %v, want [B]", cfg.FamilyIDs)
				}
			},
		},
		{
			name:   "import ignores an invalid FamilyID",
			mutate: func(s *Setup) { s.Family.Mode, s.Family.FamilyID = "import", "nope" },
			check: func(t *testing.T, cfg relay.Config) {
				if len(cfg.FamilyIDs) != 0 {
					t.Errorf("FamilyIDs = %v, want none", cfg.FamilyIDs)
				}
			},
		},
		{
			name:   "kept ids come first",
			mutate: func(s *Setup) { s.Family.Mode, s.Family.Keep = "generate", []string{a, b} },
			ids:    []string{c},
			check: func(t *testing.T, cfg relay.Config) {
				if !reflect.DeepEqual(cfg.FamilyIDs, []string{a, b, c}) {
					t.Errorf("FamilyIDs = %v, want [A B C]", cfg.FamilyIDs)
				}
			},
		},
		{
			name:   "kept ids alone",
			mutate: func(s *Setup) { s.Family.Keep = []string{a} },
			check: func(t *testing.T, cfg relay.Config) {
				if !reflect.DeepEqual(cfg.FamilyIDs, []string{a}) || cfg.FamilyPending {
					t.Errorf("cfg = %+v, want FamilyIDs [A]", cfg)
				}
			},
		},
		{
			name:   "metrics address",
			mutate: func(s *Setup) { s.Relay.MetricsPort = true },
			check: func(t *testing.T, cfg relay.Config) {
				if cfg.MetricsPort != DefaultMetricsPort {
					t.Errorf("MetricsPort = %q, want %q", cfg.MetricsPort, DefaultMetricsPort)
				}
			},
		},
		{
			name:   "metrics off",
			mutate: func(*Setup) {},
			check: func(t *testing.T, cfg relay.Config) {
				if cfg.MetricsPort != "" {
					t.Errorf("MetricsPort = %q, want empty", cfg.MetricsPort)
				}
				if cfg.Bandwidth.RateKBytes != 1640 || cfg.Nickname != "TestRelay" || cfg.ContactInfo != "tor-ops@example.org" || !cfg.Sandbox {
					t.Errorf("cfg = %+v, want the setup's identity, sandbox and steady bandwidth", cfg)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := validGuard()
			tt.mutate(&s)
			keep := append([]string(nil), s.Family.Keep...)
			cfg := s.RelayConfig(tt.ids)
			tt.check(t, cfg)
			if err := cfg.Validate(); err != nil {
				t.Errorf("RelayConfig().Validate() = %v", err)
			}
			if !reflect.DeepEqual(s.Family.Keep, keep) && len(keep) > 0 {
				t.Errorf("RelayConfig modified Family.Keep: %v", s.Family.Keep)
			}
		})
	}
}

// TestRelayConfigDoesNotAliasKeep guards against append reusing Keep's
// backing array.
func TestRelayConfigDoesNotAliasKeep(t *testing.T) {
	t.Parallel()
	s := validGuard()
	s.Family.Keep = make([]string, 1, 4)
	s.Family.Keep[0] = famID("A")
	cfg1 := s.RelayConfig([]string{famID("B")})
	cfg2 := s.RelayConfig([]string{famID("C")})
	if cfg1.FamilyIDs[1] != famID("B") || cfg2.FamilyIDs[1] != famID("C") {
		t.Errorf("FamilyIDs alias each other: %v / %v", cfg1.FamilyIDs, cfg2.FamilyIDs)
	}
}

func TestFromDocumentRoundTrip(t *testing.T) {
	t.Parallel()
	a, b := famID("A"), famID("b")
	tests := []struct {
		name   string
		mutate func(*Setup)
		ids    []string
		skip   string
	}{
		{name: "default guard with steady budget", mutate: func(*Setup) {}},
		{name: "steady with max rule (no AccountingRule line)", mutate: func(s *Setup) { s.Bandwidth.Billing = "max" }},
		{name: "steady with out rule", mutate: func(s *Setup) { s.Bandwidth.Billing = "out"; s.Bandwidth.MonthlyQuota = "20TB" }},
		{name: "steady odd quota and headroom", mutate: func(s *Setup) { s.Bandwidth.MonthlyQuota = "17TB"; s.Bandwidth.HeadroomPercent = 17 }},
		{name: "manual MBits", mutate: func(s *Setup) { s.Bandwidth = BandwidthPlan{Mode: "manual", RateMbit: 30, BurstMbit: 75} }},
		{name: "manual default burst", mutate: func(s *Setup) { s.Bandwidth = BandwidthPlan{Mode: "manual", RateMbit: 30} }},
		{name: "accounting only", mutate: func(s *Setup) {
			s.Bandwidth = BandwidthPlan{Mode: "accounting", MonthlyQuota: "5000GB", HeadroomPercent: 10, Billing: "sum"}
		}},
		{name: "accounting with max rule", mutate: func(s *Setup) {
			s.Bandwidth = BandwidthPlan{Mode: "accounting", MonthlyQuota: "2TiB", HeadroomPercent: 5, Billing: "max"}
		}},
		{name: "no limits", mutate: func(s *Setup) { s.Bandwidth = BandwidthPlan{Mode: "none"} }},
		{name: "custom port, IPv6, metrics", mutate: func(s *Setup) {
			s.Relay.ORPort, s.Relay.IPv6, s.Relay.MetricsPort = 443, "2001:db8::77", true
		}},
		{name: "contact with quotes and backslashes", mutate: func(s *Setup) {
			s.Relay.Contact = `Jane "JD" Doe <jane AT example dot org> C:\tor`
		}},
		{name: "exit reduced policy with IPv6 exit", mutate: func(s *Setup) {
			s.Relay.Mode, s.Exit.ProviderPermission, s.Relay.IPv6 = "exit", true, "2001:db8::1"
			s.Exit.Policy, s.Exit.IPv6Exit = "reduced", true
		}},
		{name: "exit default policy without IPv6 exit", mutate: func(s *Setup) {
			s.Relay.Mode, s.Exit.ProviderPermission, s.Relay.IPv6 = "exit", true, "2001:db8::1"
			s.Exit.Policy, s.Exit.IPv6Exit = "default", false
		}},
		{name: "family ids are kept", mutate: func(s *Setup) { s.Family.Keep = []string{a} }, ids: []string{b}},
		{
			name:   "sandbox off",
			mutate: func(s *Setup) { s.Relay.Sandbox = false },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.skip != "" {
				t.Skip(tt.skip)
			}
			s := validGuard()
			tt.mutate(&s)
			if err := s.Validate(); err != nil {
				t.Fatalf("fixture does not validate: %v", err)
			}
			orig := s.RelayConfig(tt.ids)
			torrc := orig.Render("test", testTime)

			back := FromDocument(relay.ParseDocument(torrc))
			if err := back.Validate(); err != nil {
				t.Fatalf("FromDocument() does not validate: %v\n%s", err, torrc)
			}
			got := back.RelayConfig(nil)
			if !reflect.DeepEqual(got, orig) {
				t.Errorf("relay config changed across the torrc round trip:\n got %+v\nwant %+v\ntorrc:\n%s", got, orig, torrc)
			}
			if again := got.Render("test", testTime); string(again) != string(torrc) {
				t.Errorf("re-rendered torrc differs:\n--- got\n%s\n--- want\n%s", again, torrc)
			}
		})
	}
}

func TestFromDocumentHandWrittenTorrc(t *testing.T) {
	t.Parallel()
	torrc := `# hand-written
Nickname  OldRelay
ContactInfo plain contact
ORPort 0.0.0.0:9050
ORPort [2001:db8::5]:9050 NoListen
ExitRelay 1
FamilyId ` + famID("Z") + ` # trailing comment
RelayBandwidthRate 5000 KBytes
AccountingMax 2 TBytes
Sandbox 0
`
	s := FromDocument(relay.ParseDocument([]byte(torrc)))
	if s.Relay.Nickname != "OldRelay" || s.Relay.Contact != "plain contact" {
		t.Errorf("identity = %q / %q", s.Relay.Nickname, s.Relay.Contact)
	}
	if s.Relay.ORPort != 9050 || s.Relay.IPv6 != "2001:db8::5" {
		t.Errorf("ORPort = %d, IPv6 = %q; want 9050 and 2001:db8::5", s.Relay.ORPort, s.Relay.IPv6)
	}
	if !s.IsExit() || !s.Exit.ProviderPermission || s.Exit.Policy != "default" || s.Exit.IPv6Exit {
		t.Errorf("exit = %+v, want a running exit with the default policy and no IPv6 exit", s.Exit)
	}
	if s.Relay.Sandbox {
		t.Error("Sandbox 0 read as enabled")
	}
	if !reflect.DeepEqual(s.Family.Keep, []string{famID("Z")}) {
		t.Errorf("Keep = %v", s.Family.Keep)
	}
	// A hand-written KBytes rate is kept verbatim (custom), not re-derived.
	want := BandwidthPlan{Mode: "custom", HeadroomPercent: 10, Billing: "max", RateKBytes: 5000, BurstKBytes: 5000, AccountingGBytes: 2048}
	if s.Bandwidth != want {
		t.Errorf("Bandwidth = %+v, want %+v", s.Bandwidth, want)
	}
}

// TestFromDocumentKeepsHandWrittenRates checks the documented promise that
// "bandwidth limits are reproduced exactly" for torrcs this tool did not write.
func TestFromDocumentKeepsHandWrittenRates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, torrc string
		wantRate    int
	}{
		{"rate with accounting", "ORPort 9001\nRelayBandwidthRate 5000 KBytes\nRelayBandwidthBurst 10000 KBytes\nAccountingMax 2 TBytes\n", 5000},
		{"rate without accounting", "ORPort 9001\nRelayBandwidthRate 5000 KBytes\nRelayBandwidthBurst 10000 KBytes\n", 5000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bw, err := FromDocument(relay.ParseDocument([]byte(tt.torrc))).Bandwidth.Resolve()
			if err != nil || bw.RateKBytes != tt.wantRate {
				t.Errorf("Resolve() = %+v, %v; want RateKBytes %d", bw, err, tt.wantRate)
			}
		})
	}
}

func TestFromDocumentEmpty(t *testing.T) {
	t.Parallel()
	s := FromDocument(relay.ParseDocument(nil))
	want := Default()
	want.Relay.Sandbox = false // no Sandbox line means Tor's default, off
	want.Bandwidth = BandwidthPlan{Mode: "none", HeadroomPercent: 10, Billing: "max"}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("FromDocument(empty) = %+v, want %+v", s, want)
	}
}

func TestInstance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, instance string
		valid          bool
		unit           string
	}{
		{"empty is the default instance", "", true, "tor@default"},
		{"default by name", "default", true, "tor@default"},
		{"named", "relay2", true, "tor@relay2"},
		{"dash rejected like tor-instance-create", "relay-2", false, "tor@default"},
		{"path rejected", "../x", false, "tor@default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := validGuard()
			s.Relay.Instance = tt.instance
			err := s.Validate()
			if (err == nil) != tt.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tt.valid)
			}
			if err != nil && !strings.Contains(err.Error(), "relay.instance") {
				t.Errorf("Validate() = %v, want it to name relay.instance", err)
			}
			if got := s.Instance().Unit; got != tt.unit {
				t.Errorf("Instance().Unit = %q, want %q", got, tt.unit)
			}
		})
	}
}

func TestRelayConfigMetricsAddress(t *testing.T) {
	t.Parallel()
	s := validGuard()
	s.Relay.MetricsPort = true
	if got := s.RelayConfig(nil).MetricsPort; got != DefaultMetricsPort {
		t.Errorf("MetricsPort = %q, want %q", got, DefaultMetricsPort)
	}
	s.Relay.MetricsAddress = "127.0.0.1:9036"
	if got := s.RelayConfig(nil).MetricsPort; got != "127.0.0.1:9036" {
		t.Errorf("MetricsPort = %q, want the picked address", got)
	}
	s.Relay.MetricsPort = false
	if got := s.RelayConfig(nil).MetricsPort; got != "" {
		t.Errorf("MetricsPort = %q with metrics off", got)
	}
	data, err := s.Marshal()
	if err != nil || strings.Contains(string(data), "9036") {
		t.Errorf("the per-host MetricsAddress must not be saved:\n%s", data)
	}
	if !strings.Contains(string(data), "instance = \"\"") || !strings.Contains(string(data), "tuning = false") {
		t.Errorf("Marshal lacks instance/tuning:\n%s", data)
	}
}
