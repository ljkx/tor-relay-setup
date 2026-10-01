package relay

import "testing"

func TestBuildCIISS(t *testing.T) {
	tests := []struct {
		email, url, hoster, want string
	}{
		{"ops@example.org", "https://example.org", "hetzner.com",
			"email:ops[]example.org url:https://example.org proof:uri-familyid-ed25519 hoster:hetzner.com ciissversion:3"},
		{"ops@example.org", "", "", "email:ops[]example.org ciissversion:3"},
		{"ops@example.org", "", "ovh.net", "email:ops[]example.org hoster:ovh.net ciissversion:3"},
		{"", "https://x.org/r", "", "url:https://x.org/r proof:uri-familyid-ed25519 ciissversion:3"},
		{"", "", "", "ciissversion:3"},
	}
	for _, tt := range tests {
		got := BuildCIISS(tt.email, tt.url, tt.hoster)
		if got != tt.want {
			t.Errorf("BuildCIISS(%q, %q, %q) = %q, want %q", tt.email, tt.url, tt.hoster, got, tt.want)
		}
		if !ValidContactInfo(got) {
			t.Errorf("BuildCIISS result %q is not valid ContactInfo", got)
		}
	}
}

func TestURLDomain(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.org":            "example.org",
		"https://relays.example.org/a/b": "relays.example.org",
		"example.org/x":                  "example.org",
		"":                               "",
	} {
		if got := URLDomain(in); got != want {
			t.Errorf("URLDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSelfTest(t *testing.T) {
	const (
		legacy   = "Jan 01 00:00:00.000 [notice] Self-testing indicates your ORPort is reachable from the outside. Excellent.\n"
		modern4  = "Oct 01 12:00:00.000 [notice] Self-testing indicates your ORPort 203.0.113.5:9001 is reachable from the outside. Excellent. Publishing server descriptor.\n"
		modern6  = "Oct 01 12:00:01.000 [notice] Self-testing indicates your ORPort [2001:db8::5]:9001 is reachable from the outside. Excellent.\n"
		failNew  = "Oct 01 13:00:00.000 [warn] Your server has not managed to confirm reachability for its ORPort(s) at 203.0.113.5:9001.\n"
		failOld  = "Jan 01 01:00:00.000 [warn] Your server (203.0.113.5:9001) has not managed to confirm that its ORPort is reachable.\n"
		failOld2 = "Jan 01 01:00:00.000 [warn] Your server has not managed to confirm that its ORPort is reachable. Please check your firewalls.\n"
		noise    = "Oct 01 12:00:00.000 [notice] Bootstrapped 100% (done): Done\n"
	)
	tests := []struct {
		name string
		log  string
		want SelfTest
	}{
		{"empty", "", SelfTest{}},
		{"noise only", noise, SelfTest{}},
		{"legacy", noise + legacy, SelfTest{IPv4: true}},
		{"modern v4", modern4, SelfTest{IPv4: true}},
		{"modern v6 only", modern6, SelfTest{IPv6: true}},
		{"both", modern4 + noise + modern6, SelfTest{IPv4: true, IPv6: true}},
		{"new failure", failNew, SelfTest{Failed: true}},
		{"old failure", failOld2, SelfTest{Failed: true}},
		{"old failure with address", failOld, SelfTest{Failed: true}},
		{"v6 ok, v4 failed", modern6 + failNew, SelfTest{IPv6: true, Failed: true}},
		{"no trailing newline", "x Self-testing indicates your ORPort 198.51.100.1:443 is reachable from the outside. Excellent.", SelfTest{IPv4: true}},
		{"truncated notice", "Self-testing indicates your ORPort 198.51.100.1:443 is reachable from the outside.", SelfTest{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseSelfTest(tt.log); got != tt.want {
				t.Errorf("ParseSelfTest = %+v, want %+v", got, tt.want)
			}
		})
	}
}
