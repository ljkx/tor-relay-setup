package relay

import (
	"slices"
	"strings"
	"testing"
)

func TestParsePolicyRule(t *testing.T) {
	tests := []struct {
		in, want string
		err      string
	}{
		{"accept *:443", "accept *:443", ""},
		{"ACCEPT *:443", "accept *:443", ""},
		{"reject *:*", "reject *:*", ""},
		{"reject *", "reject *:*", ""},
		{"accept *4:80-81", "accept *4:80-81", ""},
		{"accept6 *6:22", "accept6 *6:22", ""},
		{"reject 18.0.0.0/8:*", "reject 18.0.0.0/8:*", ""},
		{"accept 18.7.22.69:*", "accept 18.7.22.69:*", ""},
		{"reject6 [FC00::]/7:*", "reject6 [fc00::]/7:*", ""},
		{"accept [2001:db8::1]:443", "accept [2001:db8::1]:443", ""},
		{"accept [2001:db8::1]", "accept [2001:db8::1]:*", ""},
		{"reject private:*", "reject private:*", ""},
		{"accept *:1-65535", "accept *:*", ""},
		{"allow *:80", "", "start with accept"},
		{"accept", "", "want"},
		{"accept *:80 extra", "", "want"},
		{"accept *:0", "", "1-65535"},
		{"accept *:99999", "", "1-65535"},
		{"accept *:90-80", "", "backwards"},
		{"accept *:http", "", "use a number"},
		{"accept 2001:db8::1:443", "", "brackets"},
		{"accept [10.0.0.1]:80", "", "only IPv6"},
		{"accept [2001:db8::1:443", "", "unclosed"},
		{"reject 10.0.0.0/33:*", "", "prefix length"},
		{"reject *:/8", "", "port"},
		{"reject */8:*", "", "takes no /MASK"},
		{"accept6 10.0.0.1:80", "", "accept6/reject6"},
		{"accept example.com:80", "", "not an address"},
	}
	for _, tt := range tests {
		r, err := ParsePolicyRule(tt.in)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("ParsePolicyRule(%q) error = %v, want %q", tt.in, err, tt.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePolicyRule(%q): %v", tt.in, err)
			continue
		}
		if got := r.String(); got != tt.want {
			t.Errorf("ParsePolicyRule(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizePolicy(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
		err  string
	}{
		{"web", []string{"accept *:80", "accept *:443", "reject *:*"}, WebExitPolicy, ""},
		{"accept all", []string{"reject *:25", "accept *:*"}, []string{"reject *:25", "accept *:*"}, ""},
		{"split families", []string{"accept *4:443", "reject *4:*", "accept6 *6:443", "reject6 *6:*"},
			[]string{"accept *4:443", "reject *4:*", "accept6 *6:443", "reject6 *6:*"}, ""},
		{"empty", nil, nil, "empty"},
		{"no catch-all", []string{"accept *:443"}, nil, "end the policy with reject *:*"},
		{"only IPv4 closed", []string{"accept *:443", "reject *4:*"}, nil, "end the policy"},
		{"dead rule", []string{"reject *:*", "accept *:443"}, nil, "never matches"},
		{"bad line numbered", []string{"accept *:80", "nonsense", "reject *:*"}, nil, "line 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizePolicy(tt.in)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("error = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSplitPolicy(t *testing.T) {
	got := SplitPolicy("accept *:80, accept *:443\n\n  # a comment\nreject   *:*  # trailing\n")
	want := []string{"accept *:80", "accept *:443", "reject *:*"}
	if !slices.Equal(got, want) {
		t.Errorf("SplitPolicy = %q, want %q", got, want)
	}
}

// Rendered exit policies; every variant was accepted by tor 0.4.9.13
// --verify-config.
func TestRenderExitPolicies(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		want    []string
		notWant []string
	}{
		{"reduced", func(c *Config) { c.ExitPolicy = PolicyReduced }, []string{"ExitRelay 1\nReducedExitPolicy 1\n"}, []string{"\nExitPolicy "}},
		{"default", func(c *Config) { c.ExitPolicy = PolicyDefault }, []string{"ExitRelay 1\n\n"}, []string{"ExitPolicy", "Reduced"}},
		{"web", func(c *Config) { c.ExitPolicy = PolicyWeb; c.IPv6Exit = true },
			[]string{"ExitRelay 1\nExitPolicy accept *:80\nExitPolicy accept *:443\nExitPolicy reject *:*\nIPv6Exit 1\n"}, []string{"Reduced"}},
		{"custom", func(c *Config) {
			c.ExitPolicy, c.ExitPolicyLines = PolicyCustom, []string{"accept *:22", "reject *:*"}
		}, []string{"ExitPolicy accept *:22\nExitPolicy reject *:*\n"}, nil},
		{"notice", func(c *Config) { c.ExitPolicy, c.ExitNotice = PolicyReduced, "/etc/tor/tor-exit-notice.html" },
			[]string{"\n" + exitNoticeComment + "\nDirPort 80\nDirPortFrontPage /etc/tor/tor-exit-notice.html\n"}, nil},
		{"offline key", func(c *Config) { c.ExitPolicy, c.OfflineMasterKey = PolicyReduced, true },
			[]string{"ContactInfo \"email:ops[]example.org ciissversion:3\"\n\n" + offlineKeyComment + "\nOfflineMasterKey 1\n\nORPort 9001\n"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseConfig()
			c.Mode = ModeExit
			tt.mutate(&c)
			if err := c.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			got := string(c.Render("trs", testNow))
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("render lacks %q:\n%s", w, got)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(got, w) {
					t.Errorf("render has %q:\n%s", w, got)
				}
			}
		})
	}

	c := baseConfig()
	c.Mode, c.ExitPolicy, c.ExitPolicyLines = ModeExit, PolicyCustom, []string{"accept *:443"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ExitPolicyLines") {
		t.Errorf("custom policy without catch-all: %v", err)
	}
	c.ExitPolicy, c.ExitNotice, c.ORPort = PolicyReduced, "/etc/tor/n.html", 80
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ExitNotice") {
		t.Errorf("notice on the ORPort: %v", err)
	}
}
