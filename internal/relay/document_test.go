package relay

import (
	"slices"
	"strings"
	"testing"
)

const sampleTorrc = `## Configuration file for a typical Tor user
#ORPort 9999
  # indented comment
Nickname  OldName
contactinfo "ops \"at\" example.org"
UnknownOption some value # keep me
ORPort 0.0.0.0:9001 NoAdvertise
ORPort [::]:443
DataDirectory /srv/tor
Log notice file /var/log/tor/notices.log
`

func TestDocumentRoundTrip(t *testing.T) {
	for _, in := range []string{"", "\n", sampleTorrc, "Nickname A", "a\n\n\nb\n", "Nickname A\r\nORPort 1\r\n"} {
		if got := string(ParseDocument([]byte(in)).Bytes()); got != in {
			t.Errorf("round trip %q -> %q", in, got)
		}
	}
}

func TestDocumentGet(t *testing.T) {
	d := ParseDocument([]byte(sampleTorrc))
	tests := []struct {
		key, want string
		ok        bool
	}{
		{"Nickname", "OldName", true},
		{"NICKNAME", "OldName", true},
		{"ContactInfo", `"ops \"at\" example.org"`, true},
		{"UnknownOption", "some value # keep me", true},
		{"ORPort", "0.0.0.0:9001 NoAdvertise", true},
		{"SocksPort", "", false},
	}
	for _, tt := range tests {
		got, ok := d.Get(tt.key)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Get(%q) = %q, %v; want %q, %v", tt.key, got, ok, tt.want, tt.ok)
		}
	}
	if got := d.GetAll("orport"); !slices.Equal(got, []string{"0.0.0.0:9001 NoAdvertise", "[::]:443"}) {
		t.Errorf("GetAll(orport) = %q", got)
	}
	if got := d.ORPorts(); len(got) != 2 {
		t.Errorf("ORPorts = %q", got)
	}
	if ci, _ := d.Get("ContactInfo"); Unquote(ci) != `ops "at" example.org` {
		t.Errorf("Unquote(ContactInfo) = %q", Unquote(ci))
	}
}

func TestDocumentSet(t *testing.T) {
	d := ParseDocument([]byte(sampleTorrc))
	d.Set("Nickname", "NewName")
	d.Set("ORPort", "9002", "[2001:db8::1]:9002")
	d.Set("SocksPort", "0")
	d.Set("Log") // removes
	want := `## Configuration file for a typical Tor user
#ORPort 9999
  # indented comment
Nickname NewName
contactinfo "ops \"at\" example.org"
UnknownOption some value # keep me
ORPort 9002
ORPort [2001:db8::1]:9002
DataDirectory /srv/tor
SocksPort 0
`
	if got := string(d.Bytes()); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// Idempotent.
	d.Set("ORPort", "9002", "[2001:db8::1]:9002")
	d.Set("SocksPort", "0")
	if got := string(d.Bytes()); got != want {
		t.Fatalf("second Set changed the document:\n%s", got)
	}
	d.Remove("socksport", "UNKNOWNOPTION", "missing")
	got := string(d.Bytes())
	if strings.Contains(got, "SocksPort") || strings.Contains(got, "UnknownOption") {
		t.Errorf("Remove left lines:\n%s", got)
	}
	if !strings.Contains(got, "#ORPort 9999") {
		t.Errorf("Remove touched a comment:\n%s", got)
	}
}

func TestDocumentSetNoTrailingNewline(t *testing.T) {
	d := ParseDocument([]byte("Nickname A"))
	d.Set("SocksPort", "0")
	if got := string(d.Bytes()); got != "Nickname A\nSocksPort 0" {
		t.Errorf("got %q", got)
	}
	d = ParseDocument(nil)
	d.Set("SocksPort", "0")
	if got := string(d.Bytes()); got != "SocksPort 0\n" {
		t.Errorf("empty doc got %q", got)
	}
}

func TestFirstORPortAndDataDirectory(t *testing.T) {
	tests := []struct {
		torrc   string
		port    int
		dataDir string
	}{
		{"ORPort 9001\n", 9001, "/var/lib/tor"},
		{"ORPort 0.0.0.0:9001\n", 9001, "/var/lib/tor"},
		{"ORPort [::]:443\nORPort 9001\n", 443, "/var/lib/tor"},
		{"ORPort auto\nORPort 127.0.0.1:9050 NoAdvertise\n", 9050, "/var/lib/tor"},
		{"#ORPort 9001\n", 0, "/var/lib/tor"},
		{"", 0, "/var/lib/tor"},
		{"DataDirectory /srv/tor\n", 0, "/srv/tor"},
		{`DataDirectory "/srv/my tor"` + "\n", 0, "/srv/my tor"},
		{"datadirectory /x # comment\n", 0, "/x"},
		{"DataDirectory\n", 0, "/var/lib/tor"},
	}
	for _, tt := range tests {
		d := ParseDocument([]byte(tt.torrc))
		if got := d.FirstORPort(); got != tt.port {
			t.Errorf("%q: FirstORPort = %d, want %d", tt.torrc, got, tt.port)
		}
		if got := d.DataDirectory(); got != tt.dataDir {
			t.Errorf("%q: DataDirectory = %q, want %q", tt.torrc, got, tt.dataDir)
		}
	}
}

func TestSetFamilyIDs(t *testing.T) {
	in := "# header\nNickname A\nContactInfo \"x\"\n\nORPort 9001\n# FamilyId old-commented-out\nfamilyid " + testFamilyID2 + "\n"
	d := ParseDocument([]byte(in))
	if got := d.FamilyIDs(); !slices.Equal(got, []string{testFamilyID2}) {
		t.Fatalf("FamilyIDs = %v", got)
	}
	d.SetFamilyIDs([]string{testFamilyID, testFamilyID, ""})
	want := "# header\nNickname A\nContactInfo \"x\"\n\n" + familyComment + "\nFamilyId " + testFamilyID +
		"\n\nORPort 9001\n# FamilyId old-commented-out\n"
	if got := string(d.Bytes()); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	d.SetFamilyIDs([]string{testFamilyID})
	if got := string(d.Bytes()); got != want {
		t.Fatalf("not idempotent:\n%s", got)
	}
	d.SetFamilyIDs([]string{testFamilyID, testFamilyID2})
	if got := d.FamilyIDs(); !slices.Equal(got, []string{testFamilyID, testFamilyID2}) {
		t.Fatalf("FamilyIDs = %v", got)
	}
	d.SetFamilyIDs(nil)
	want = "# header\nNickname A\nContactInfo \"x\"\n\nORPort 9001\n# FamilyId old-commented-out\n"
	if got := string(d.Bytes()); got != want {
		t.Fatalf("removal got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSetFamilyIDsReplacesPlaceholderAndAppends(t *testing.T) {
	c := baseConfig()
	c.FamilyPending = true
	d := ParseDocument(c.Render("trs", testNow))
	d.SetFamilyIDs([]string{testFamilyID})
	c.FamilyPending, c.FamilyIDs = false, []string{testFamilyID}
	if got, want := string(d.Bytes()), string(c.Render("trs", testNow)); got != want {
		t.Fatalf("placeholder not replaced:\n%s\nwant:\n%s", got, want)
	}

	// No ContactInfo: the block is appended with one separating blank line.
	d = ParseDocument([]byte("ORPort 9001\n"))
	d.SetFamilyIDs([]string{testFamilyID})
	if got, want := string(d.Bytes()), "ORPort 9001\n\n"+familyComment+"\nFamilyId "+testFamilyID+"\n"; got != want {
		t.Fatalf("append got %q, want %q", got, want)
	}
	d.SetFamilyIDs([]string{testFamilyID})
	if got, want := string(d.Bytes()), "ORPort 9001\n\n"+familyComment+"\nFamilyId "+testFamilyID+"\n"; got != want {
		t.Fatalf("append not idempotent: %q", got)
	}
}

func TestMyFamily(t *testing.T) {
	a := "0123456789ABCDEF0123456789ABCDEF01234567"
	b := "89ABCDEF0123456789ABCDEF0123456789ABCDEF"
	in := "Nickname A\nContactInfo x\n# Managed MyFamily: relays controlled by this operator. Keep synced on every family member.\n" +
		"MyFamily $" + strings.ToLower(a) + ", bogus " + b + " # trailing " + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n" +
		"#MyFamily $FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n" +
		"myfamily " + a + "\n"
	d := ParseDocument([]byte(in))
	if got := d.MyFamily(); !slices.Equal(got, []string{a, b}) {
		t.Fatalf("MyFamily = %v", got)
	}
	d.SetMyFamily([]string{"$" + a, strings.ToLower(b), "junk", a})
	want := "Nickname A\nContactInfo x\n\n" + myFamilyComment + "\nMyFamily $" + a + ",$" + b + "\n" +
		"#MyFamily $FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n"
	if got := string(d.Bytes()); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	d.SetMyFamily([]string{a, b})
	if got := string(d.Bytes()); got != want {
		t.Fatalf("not idempotent:\n%s", got)
	}
	d.SetMyFamily(nil)
	if got, want := string(d.Bytes()), "Nickname A\nContactInfo x\n#MyFamily $FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n"; got != want {
		t.Fatalf("removal got %q, want %q", got, want)
	}
}

func TestSetMetricsPort(t *testing.T) {
	d := ParseDocument([]byte("Nickname A\nmetricsport 0.0.0.0:9035\nMetricsPortPolicy accept *\nSocksPort 0\n"))
	d.SetMetricsPort("127.0.0.1:9035")
	want := "Nickname A\n\n" + metricsComment + "\nMetricsPort 127.0.0.1:9035\nMetricsPortPolicy accept 127.0.0.1\n\nSocksPort 0\n"
	if got := string(d.Bytes()); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	d.SetMetricsPort("127.0.0.1:9035")
	if got := string(d.Bytes()); got != want {
		t.Fatalf("not idempotent:\n%s", got)
	}
	d.SetMetricsPort("[::1]:9035")
	if v, _ := d.Get("MetricsPortPolicy"); v != "accept [::1]" {
		t.Errorf("policy = %q", v)
	}
	d.SetMetricsPort("")
	if got, want := string(d.Bytes()), "Nickname A\n\nSocksPort 0\n"; got != want {
		t.Fatalf("removal got %q, want %q", got, want)
	}
	// Absent block: appended at the end.
	d = ParseDocument([]byte("Nickname A\n"))
	d.SetMetricsPort("127.0.0.1:9035")
	if got, want := string(d.Bytes()), "Nickname A\n\n"+metricsComment+"\nMetricsPort 127.0.0.1:9035\nMetricsPortPolicy accept 127.0.0.1\n"; got != want {
		t.Fatalf("append got %q", got)
	}
}

func TestSetBandwidth(t *testing.T) {
	in := "Nickname A\nRelayBandwidthRate 100 KBytes\n# user note\nrelaybandwidthburst 200 KBytes\nAccountingMax 5 GBytes\n"
	d := ParseDocument([]byte(in))
	steady := Bandwidth{Mode: BandwidthSteady, RateKBytes: 1640, BurstKBytes: 8200, AccountingMaxGBytes: 8381, AccountingRule: RuleSum}
	d.SetBandwidth(steady)
	want := "Nickname A\n\n" + bandwidthComment + "\nRelayBandwidthRate 1640 KBytes\nRelayBandwidthBurst 8200 KBytes\n" +
		"AccountingStart month 1 00:00\nAccountingRule sum\nAccountingMax 8381 GBytes\n\n# user note\n"
	if got := string(d.Bytes()); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	d.SetBandwidth(steady)
	if got := string(d.Bytes()); got != want {
		t.Fatalf("not idempotent:\n%s", got)
	}
	d.SetBandwidth(Bandwidth{Mode: BandwidthManual, RateMbit: 16, BurstMbit: 32})
	if got := d.GetAll("RelayBandwidthRate"); !slices.Equal(got, []string{"16 MBits"}) {
		t.Errorf("rate = %q", got)
	}
	if _, ok := d.Get("AccountingMax"); ok {
		t.Error("manual mode kept AccountingMax")
	}
	d.SetBandwidth(Bandwidth{Mode: BandwidthNone})
	if got, want := string(d.Bytes()), "Nickname A\n\n# user note\n"; got != want {
		t.Fatalf("none got %q, want %q", got, want)
	}
}

func TestQuoteUnquote(t *testing.T) {
	tests := []struct{ raw, quoted string }{
		{"plain", `"plain"`},
		{`a "b"`, `"a \"b\""`},
		{`back\slash`, `"back\\slash"`},
		{`\"`, `"\\\""`},
		{"", `""`},
	}
	for _, tt := range tests {
		if got := Quote(tt.raw); got != tt.quoted {
			t.Errorf("Quote(%q) = %q, want %q", tt.raw, got, tt.quoted)
		}
		if got := Unquote(tt.quoted); got != tt.raw {
			t.Errorf("Unquote(%q) = %q, want %q", tt.quoted, got, tt.raw)
		}
	}
	for in, want := range map[string]string{
		"unquoted": "unquoted",
		`"`:        `"`,
		`"a\nb"`:   "a\nb",
		`"a\qb"`:   `a\qb`,
		`"x" y`:    `"x" y`,
		`"trail\"`: `trail\`,
	} {
		if got := Unquote(in); got != want {
			t.Errorf("Unquote(%q) = %q, want %q", in, got, want)
		}
	}
}
