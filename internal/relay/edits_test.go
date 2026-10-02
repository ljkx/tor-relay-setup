package relay

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func exitDoc(policy ExitPolicy, lines []string) *Document {
	c := baseConfig()
	c.Mode, c.ExitPolicy, c.ExitPolicyLines, c.IPv6Exit = ModeExit, policy, lines, true
	return ParseDocument(c.Render("trs", testNow))
}

func TestExitPolicySettingsRoundTrip(t *testing.T) {
	custom := []string{"accept *:22", "accept *:443", "reject *:*"}
	tests := []struct {
		policy ExitPolicy
		lines  []string
	}{
		{PolicyReduced, nil}, {PolicyDefault, nil}, {PolicyWeb, nil}, {PolicyCustom, custom},
	}
	for _, tt := range tests {
		p, lines := exitDoc(tt.policy, tt.lines).ExitPolicySettings()
		if p != tt.policy || !slices.Equal(lines, tt.lines) {
			t.Errorf("%s: ExitPolicySettings = %s %q", tt.policy, p, lines)
		}
	}
	doc := ParseDocument([]byte("ExitRelay 1\nExitPolicy accept *:80, accept *:443, reject *:*\n"))
	if p, _ := doc.ExitPolicySettings(); p != PolicyWeb {
		t.Errorf("comma-separated web policy reads as %s", p)
	}
}

func TestActsAsExit(t *testing.T) {
	for torrc, want := range map[string]bool{
		"ORPort 9001\n":                                                   false,
		"ORPort 9001\nExitRelay 0\n":                                      false,
		"ORPort 9001\nExitRelay 0\nExitPolicy accept *:80\n":              false,
		"ORPort 9001\nExitPolicy reject *:*\n":                            false,
		"ORPort 9001\nExitPolicy reject *:25, reject *:*\n":               false,
		"ORPort 9001\nExitRelay 1\n":                                      true,
		"ORPort 9001\nExitRelay 1 # yes\nExitPolicy reject *:*\n":         true,
		"ORPort 9001\nExitRelay auto\nExitPolicy accept *:443\n":          true,
		"ORPort 9001\nExitPolicy reject *:25\nExitPolicy accept *:*\n":    true,
		"ORPort 9001\nReducedExitPolicy 1\n":                              true,
		"ORPort 9001\n# ExitRelay 1\n#ExitPolicy accept *:*\n":            false,
		"ORPort 9001\nexitrelay 1\n":                                      true,
		"ORPort 9001\nExitPolicy ACCEPT6 [2001:db8::]/32:*, reject *:*\n": true,
	} {
		if got := ParseDocument([]byte(torrc)).ActsAsExit(); got != want {
			t.Errorf("ActsAsExit(%q) = %v, want %v", torrc, got, want)
		}
	}
	for _, p := range []ExitPolicy{PolicyReduced, PolicyDefault, PolicyWeb} {
		if !exitDoc(p, nil).ActsAsExit() {
			t.Errorf("rendered %s exit not detected", p)
		}
	}
}

func TestSetExitPolicyInPlace(t *testing.T) {
	doc := exitDoc(PolicyReduced, nil)
	doc.SetExitPolicy(PolicyCustom, []string{"accept *:443", "reject *:*"}, false)
	got := string(doc.Bytes())
	want := "# Exit relay mode.\nExitRelay 1\nExitPolicy accept *:443\nExitPolicy reject *:*\n\n# Keep"
	if !strings.Contains(got, want) {
		t.Fatalf("custom policy not in place:\n%s", got)
	}
	again := string(doc.Bytes())
	doc.SetExitPolicy(PolicyCustom, []string{"accept *:443", "reject *:*"}, false)
	if string(doc.Bytes()) != again {
		t.Error("repeating SetExitPolicy changed the document")
	}
	doc.SetExitPolicy(PolicyReduced, nil, true)
	if got := string(doc.Bytes()); !strings.Contains(got, "ExitRelay 1\nReducedExitPolicy 1\nIPv6Exit 1\n\n# Keep") || strings.Contains(got, "\nExitPolicy ") {
		t.Errorf("back to reduced:\n%s", got)
	}
	doc.SetExitPolicy(PolicyDefault, nil, false)
	if got := string(doc.Bytes()); strings.Contains(got, "Reduced") || strings.Contains(got, "IPv6Exit") {
		t.Errorf("default policy leaves lines:\n%s", got)
	}

	// No exit block at all: the lines are appended.
	bare := ParseDocument([]byte("Nickname X\n"))
	bare.SetExitPolicy(PolicyWeb, nil, false)
	if got := string(bare.Bytes()); got != "Nickname X\n\nExitPolicy accept *:80\nExitPolicy accept *:443\nExitPolicy reject *:*\n" {
		t.Errorf("appended policy:\n%q", got)
	}
}

func TestSetExitNotice(t *testing.T) {
	doc := exitDoc(PolicyReduced, nil)
	doc.SetExitNotice("/etc/tor/tor-exit-notice.html")
	if doc.ExitNotice() != "/etc/tor/tor-exit-notice.html" || !slices.Equal(doc.DirPortNumbers(), []int{80}) {
		t.Fatalf("notice not set:\n%s", doc.Bytes())
	}
	once := string(doc.Bytes())
	doc.SetExitNotice("/etc/tor/tor-exit-notice.html")
	if string(doc.Bytes()) != once {
		t.Error("SetExitNotice is not idempotent")
	}
	doc.SetExitNotice("")
	if doc.ExitNotice() != "" || len(doc.DirPortNumbers()) != 0 || strings.Contains(string(doc.Bytes()), "exit notice") {
		t.Errorf("notice not removed:\n%s", doc.Bytes())
	}
}

func TestSetOfflineMasterKey(t *testing.T) {
	c := baseConfig()
	c.FamilyIDs = []string{testFamilyID}
	doc := ParseDocument(c.Render("trs", testNow))
	doc.SetOfflineMasterKey(true)
	if !doc.OfflineMasterKey() {
		t.Fatal("OfflineMasterKey not set")
	}
	got := string(doc.Bytes())
	if !strings.Contains(got, "FamilyId "+testFamilyID+"\n\n"+offlineKeyComment+"\nOfflineMasterKey 1\n\nORPort 9001") {
		t.Errorf("block not after the family:\n%s", got)
	}
	// Rendering with OfflineMasterKey gives the same layout as the edit.
	c.OfflineMasterKey = true
	if want := string(c.Render("trs", testNow)); got != want {
		t.Errorf("edit and render differ\n--- edit ---\n%s--- render ---\n%s", got, want)
	}
	doc.SetOfflineMasterKey(true)
	if string(doc.Bytes()) != got {
		t.Error("not idempotent")
	}
	doc.SetOfflineMasterKey(false)
	if doc.OfflineMasterKey() || strings.Contains(string(doc.Bytes()), "offline") {
		t.Errorf("not removed:\n%s", doc.Bytes())
	}
}

func TestExitNoticeRender(t *testing.T) {
	page := string(RenderExitNotice("MyRelay01", `email:ops[]example.org url:https://example.org proof:uri-familyid-ed25519 ciissversion:3`))
	if !strings.Contains(ExitNoticeTemplate(), "3-clause BSD") {
		t.Error("the template no longer credits tor's sample notice")
	}
	for _, want := range []string{"<title>This is a Tor exit relay</title>", "<strong>MyRelay01</strong>", `href="mailto:ops@example.org"`, "rs.html#search/MyRelay01"} {
		if !strings.Contains(page, want) {
			t.Errorf("notice lacks %q", want)
		}
	}
	page = string(RenderExitNotice("R", `<script>alert(1)</script>`))
	if strings.Contains(page, "<script>") || !strings.Contains(page, "the operator (") {
		t.Error("contact is not escaped, or the no-email fallback is missing")
	}
	// docs/examples carries the same template for operators who serve it
	// with their own web server.
	docs, err := os.ReadFile("../../docs/examples/tor-exit-notice.html")
	if err != nil {
		t.Fatal(err)
	}
	if string(docs) != ExitNoticeTemplate() {
		t.Error("docs/examples/tor-exit-notice.html differs from internal/relay/exitnotice.html; copy it over")
	}
}

func TestContactEmail(t *testing.T) {
	for in, want := range map[string]string{
		"email:ops[]example.org ciissversion:3": "ops@example.org",
		"Jane <jane@example.org>":               "jane@example.org",
		"no address here":                       "",
	} {
		if got := ContactEmail(in); got != want {
			t.Errorf("ContactEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
