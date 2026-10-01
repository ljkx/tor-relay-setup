package relay

import (
	"strings"
	"testing"
)

func TestStringValidators(t *testing.T) {
	fp := "0123456789ABCDEF0123456789abcdef01234567"
	tests := []struct {
		name string
		fn   func(string) bool
		ok   []string
		bad  []string
	}{
		{"ValidNickname", ValidNickname,
			[]string{"a", "MyRelay01", strings.Repeat("x", 19)},
			[]string{"", strings.Repeat("x", 20), "my-relay", "my relay", "relé"}},
		{"ValidContactInfo", ValidContactInfo,
			[]string{"x", "email:ops[]example.org ciissversion:3", strings.Repeat("é", 250)},
			[]string{"", strings.Repeat("a", 251), "a\nb", "a\rb", "ops #1"}},
		{"ValidHostname", ValidHostname,
			[]string{"relay", "relay-1.example.org", "a.b.c", strings.Repeat("a", 63) + ".org"},
			[]string{"", "localhost", "LOCALHOST", "localhost.localdomain", "-a.org", "a-.org", ".a", "a.", "a..b", "a_b", strings.Repeat("a", 64) + ".org", strings.Repeat("a.", 127) + "ab"}},
		{"ValidIPv6", ValidIPv6,
			[]string{"2001:db8::1", "2a01:4f8:1:2::3", "fd00::1"},
			[]string{"", "::1", "::", "fe80::1", "ff02::1", "::ffff:192.0.2.1", "192.0.2.1", "[2001:db8::1]", "2001:db8::/32", "2001:db8::1%eth0", "2001:db8::1 ", "nonsense"}},
		{"ValidFingerprint", ValidFingerprint,
			[]string{fp, "$" + fp},
			[]string{"", fp[:39], fp + "0", "$$" + fp, strings.Replace(fp, "0", "G", 1)}},
		{"ValidFamilyID", ValidFamilyID,
			[]string{testFamilyID},
			[]string{"", testFamilyID[:42], testFamilyID + "A", testFamilyID[:42] + "="}},
		{"ValidFamilyKeyName", ValidFamilyKeyName,
			[]string{"a", "relay_family.v2-1", strings.Repeat("k", 64)},
			[]string{"", ".hidden", "-x", "a/b", "a b", strings.Repeat("k", 65)}},
		{"ValidEmail", ValidEmail,
			[]string{"ops@example.org", "tor+relay@mail.example.co.uk"},
			[]string{"", "ops", "ops@example", "a b@example.org", "ops@@example.org", "ops#1@example.org"}},
		{"ValidHTTPSURL", ValidHTTPSURL,
			[]string{"https://example.org", "https://relays.example.org/tor/list"},
			[]string{"", "http://example.org", "https://example", "https://example.org/a b", "https://example.org/#x", "example.org"}},
		{"ValidHosterDomain", ValidHosterDomain,
			[]string{"hetzner.com", "my-host.co.uk"},
			[]string{"", "hetzner", "https://hetzner.com", "hetzner.com/x", "a..b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, s := range tt.ok {
				if !tt.fn(s) {
					t.Errorf("%s(%q) = false, want true", tt.name, s)
				}
			}
			for _, s := range tt.bad {
				if tt.fn(s) {
					t.Errorf("%s(%q) = true, want false", tt.name, s)
				}
			}
		})
	}
}

func TestValidPort(t *testing.T) {
	for p, want := range map[int]bool{-1: false, 0: false, 1: true, 443: true, 65535: true, 65536: false} {
		if got := ValidPort(p); got != want {
			t.Errorf("ValidPort(%d) = %v, want %v", p, got, want)
		}
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	if got := NormalizeFingerprint("$0123456789abcdef0123456789abcdef01234567"); got != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Errorf("got %q", got)
	}
}
