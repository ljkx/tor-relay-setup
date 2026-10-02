package proof

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

var (
	famA = strings.Repeat("A", 42) + "a"
	famB = strings.Repeat("B", 42) + "b"
	fp1  = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
	fp2  = "0123456789012345678901234567890123456789"
)

func TestFiles(t *testing.T) {
	t.Parallel()
	got := string(FamilyIDFile([]string{famA, "bogus", famA, " " + famB + " "}))
	want := "# Tor relay family ID(s) of this operator (CIISS proof:uri-familyid-ed25519).\n" + famA + "\n" + famB + "\n"
	if got != want {
		t.Errorf("FamilyIDFile =\n%s\nwant\n%s", got, want)
	}
	got = string(RSAFingerprintFile([]string{"$" + strings.ToLower(fp1), fp1, fp2, "short"}))
	want = "# Tor relay RSA fingerprints of this operator (legacy CIISS v2 proof:uri-rsa).\n" + fp1 + "\n" + fp2 + "\n"
	if got != want {
		t.Errorf("RSAFingerprintFile =\n%s\nwant\n%s", got, want)
	}
	if FamilyIDs.FileName() != "ed25519-family-id.txt" || Fingerprints.FileName() != "rsa-fingerprint.txt" {
		t.Error("file names")
	}
}

func TestDomain(t *testing.T) {
	t.Parallel()
	for contact, want := range map[string]string{
		"email:ops[]example.org url:https://Relays.Example.org/tor proof:uri-familyid-ed25519 ciissversion:3": "relays.example.org",
		"url:example.org ciissversion:3":            "example.org",
		"url:http://example.org:8080/x":             "example.org",
		"email:ops[]example.org ciissversion:3":     "",
		"plain text without fields https://foo.org": "",
	} {
		if got := Domain(contact); got != want {
			t.Errorf("Domain(%q) = %q, want %q", contact, got, want)
		}
	}
}

func TestSites(t *testing.T) {
	t.Parallel()
	contact := "email:ops[]example.org url:https://example.org proof:uri-familyid-ed25519 ciissversion:3"
	sites := Sites([]Relay{
		{Name: "One", Contact: contact, FamilyIDs: []string{famA}, Fingerprint: fp1},
		{Name: "Two", Contact: contact, FamilyIDs: []string{famA, famB}, Fingerprint: fp2},
		{Name: "Bridge", Contact: contact, Fingerprint: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", Bridge: true},
		{Name: "Elsewhere", Contact: "email:x[]y.org ciissversion:3", Fingerprint: fp2},
	})
	if len(sites) != 2 {
		t.Fatalf("Sites = %+v", sites)
	}
	s := sites[0]
	if s.Domain != "example.org" || !slices.Equal(s.Relays, []string{"One", "Two"}) || s.Proof != "uri-familyid-ed25519" {
		t.Errorf("site = %+v", s)
	}
	if s.Files[0].URL != "https://example.org/.well-known/tor-relay/ed25519-family-id.txt" || !slices.Equal(s.Files[0].Entries, []string{famA, famB}) {
		t.Errorf("family file = %+v", s.Files[0])
	}
	if s.Files[1].URL != "https://example.org/.well-known/tor-relay/rsa-fingerprint.txt" || !slices.Equal(s.Files[1].Entries, []string{fp1, fp2}) {
		t.Errorf("rsa file = %+v", s.Files[1])
	}
	if strings.Contains(string(s.Files[1].Content), "FFFF") {
		t.Error("a bridge fingerprint was published")
	}
	if sites[1].Domain != "" || sites[1].Files[0].URL != "" {
		t.Errorf("no-url site = %+v", sites[1])
	}
	if a := strings.Join(Advice(sites[1]), " "); !strings.Contains(a, "no url: field") || !strings.Contains(a, "no FamilyId") {
		t.Errorf("Advice = %q", a)
	}
	if a := Advice(Site{Domain: "x.org", Proof: "uri-rsa", Files: s.Files}); len(a) != 1 || !strings.Contains(a[0], "CIISS v2") {
		t.Errorf("Advice(uri-rsa) = %q", a)
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/tor-relay/ed25519-family-id.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("# ours\n" + famA + "\n\n"))
	})
	mux.HandleFunc("/.well-known/tor-relay/rsa-fingerprint.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(strings.ToLower(fp1) + "\n"))
	})
	mux.HandleFunc("/same-domain", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/.well-known/tor-relay/ed25519-family-id.txt", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/other-domain", func(w http.ResponseWriter, r *http.Request) {
		// httptest serves 127.0.0.1; "localhost" is another domain.
		http.Redirect(w, r, "https://localhost"+r.Host[strings.LastIndex(r.Host, ":"):]+"/.well-known/tor-relay/ed25519-family-id.txt", http.StatusFound)
	})
	mux.HandleFunc("/leak", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("== ed25519v1-secret: fmly-id ==\x00\x00..."))
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("#", MaxSize+10)))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	c := Client(srv.Client())
	ctx := context.Background()

	r := Check(ctx, c, FamilyIDs, srv.URL+FamilyIDPath, []string{famA})
	if !r.OK || !slices.Equal(r.Found, []string{famA}) || r.Error != "" || len(r.Notes) != 0 {
		t.Errorf("family file: %+v", r)
	}
	r = Check(ctx, c, FamilyIDs, srv.URL+FamilyIDPath, []string{famA, famB})
	if r.OK || !slices.Equal(r.Missing, []string{famB}) {
		t.Errorf("missing ID not reported: %+v", r)
	}
	// FamilyIds are case-sensitive.
	r = Check(ctx, c, FamilyIDs, srv.URL+FamilyIDPath, []string{strings.ToLower(famA)})
	if r.OK {
		t.Errorf("case-insensitive FamilyId match: %+v", r)
	}
	r = Check(ctx, c, Fingerprints, srv.URL+RSAPath, []string{"$" + fp1})
	if !r.OK || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "text/plain") {
		t.Errorf("rsa file: %+v", r)
	}
	if r := Check(ctx, c, FamilyIDs, srv.URL+"/same-domain", []string{famA}); !r.OK {
		t.Errorf("same-domain redirect refused: %+v", r)
	}
	if r := Check(ctx, c, FamilyIDs, srv.URL+"/other-domain", []string{famA}); r.OK || !strings.Contains(r.Error, "another domain") {
		t.Errorf("cross-domain redirect: %+v", r)
	}
	if r := Check(ctx, c, FamilyIDs, srv.URL+"/leak", []string{famA}); r.OK || !strings.Contains(r.Error, "SECRET") {
		t.Errorf("leaked secret: %+v", r)
	}
	if r := Check(ctx, c, FamilyIDs, srv.URL+"/big", []string{famA}); r.OK || !strings.Contains(r.Error, "1 MByte") {
		t.Errorf("oversized: %+v", r)
	}
	if r := Check(ctx, c, FamilyIDs, srv.URL+"/nothing", []string{famA}); r.OK || !strings.Contains(r.Error, "404") {
		t.Errorf("404: %+v", r)
	}
	if r := Check(ctx, c, FamilyIDs, strings.Replace(srv.URL, "https", "http", 1)+FamilyIDPath, nil); r.Error != "not an https:// URL" {
		t.Errorf("http URL: %+v", r)
	}
	// A server without a trusted certificate fails with the default client.
	if r := Check(ctx, Client(nil), FamilyIDs, srv.URL+FamilyIDPath, []string{famA}); r.OK || r.Error == "" {
		t.Errorf("untrusted certificate accepted: %+v", r)
	}

	site := Site{Domain: "x", Files: []File{
		{Kind: FamilyIDs, URL: srv.URL + FamilyIDPath, Entries: []string{famA}},
		{Kind: Fingerprints, URL: srv.URL + RSAPath},
	}}
	if res := CheckSite(ctx, c, site); len(res) != 1 || !res[0].OK {
		t.Errorf("CheckSite = %+v", res)
	}
}

func TestLocal(t *testing.T) {
	t.Parallel()
	h := host.NewFake()
	relayTorrc := "Nickname One\nContactInfo \"url:https://example.org proof:uri-familyid-ed25519 ciissversion:3\"\nFamilyId " + famA + "\nORPort 9001\n"
	bridgeTorrc := "Nickname Br\nContactInfo x\nBridgeRelay 1\nORPort 9443\nServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n"
	h.Files["/etc/tor/torrc"] = []byte(relayTorrc)
	h.Files["/var/lib/tor/fingerprint"] = []byte("One " + fp1 + "\n")
	h.Files["/etc/tor/instances/br/torrc"] = []byte(bridgeTorrc)
	configs, err := relay.DiscoverConfigs(h)
	if err != nil {
		t.Fatal(err)
	}
	got := Local(h, configs)
	if len(got) != 2 || got[0].Name != "One" || got[0].Fingerprint != fp1 || !slices.Equal(got[0].FamilyIDs, []string{famA}) || got[0].Bridge {
		t.Errorf("relay = %+v", got[0])
	}
	if !got[1].Bridge {
		t.Errorf("bridge not marked: %+v", got[1])
	}
}
