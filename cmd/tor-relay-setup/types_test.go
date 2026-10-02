package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/keys"
)

func TestHelpListsProofAndKeys(t *testing.T) {
	clearRoot(t)
	code, out, _ := runCLI(t, "--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"tor-relay-setup proof [--instance NAME|--all] [--check]",
		"tor-relay-setup keys status|offline|renew [--instance NAME]",
		"tor-relay-setup keys offline [--remove-master]",
		`tor-relay-setup keys renew [--master DIR | --from DIR] [--lifetime "30 days"]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

func TestProofAndKeysUsageErrors(t *testing.T) {
	clearRoot(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown keys action", []string{"keys", "rotate"}, `unknown keys action "rotate"`},
		{"--remove-master outside keys offline", []string{"keys", "renew", "--remove-master"}, "--remove-master is only used with keys offline"},
		{"--from outside keys renew", []string{"keys", "status", "--from", "/root"}, "only used with keys renew"},
		{"--master with status", []string{"status", "--master", "/root"}, "only used with keys"},
		{"--check with status", []string{"status", "--check"}, "--check is only used with self-update and proof"},
		{"--all with keys", []string{"keys", "--all"}, "--all is only used with status and proof"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := runCLI(t, tt.args...)
			if code != 2 || !strings.Contains(errOut, tt.want) {
				t.Errorf("exit %d, stderr %q; want 2 and %q", code, errOut, tt.want)
			}
		})
	}
}

// keyRoot is a fixture relay with the real test keys made by tor 0.4.9.13.
func keyRoot(t *testing.T, torrc string, master bool) string {
	t.Helper()
	root := fixtureRoot(t, torrc)
	files := map[string]string{
		"var/lib/tor/keys/" + keys.SigningCert:  "../../internal/keys/testdata/ed25519_signing_cert",
		"var/lib/tor/keys/" + keys.MasterPublic: "../../internal/keys/testdata/ed25519_master_id_public_key",
	}
	for dst, src := range files {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dst), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if master {
		if err := os.WriteFile(filepath.Join(root, "var/lib/tor/keys/"+keys.MasterSecret), []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestKeysStatusFromFixture(t *testing.T) {
	stubPath(t)
	t.Setenv("TOR_RELAY_SETUP_ROOT", keyRoot(t, strings.Replace(fixtureTorrc, "FAMILY", famA, 1), true))
	code, out, errOut := runCLI(t, "keys", "status", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"Identity          QpJApfAfoAk4z/5dtmI+JDu4PrrlaWv3URaAZeMrLxM", "Master key        on this server", "OfflineMasterKey  false", "valid until 2036-10-01 23:00 UTC"} {
		if !strings.Contains(out, want) {
			t.Errorf("keys status lacks %q:\n%s", want, out)
		}
	}

	// Without the master key and without OfflineMasterKey 1: exit 1.
	t.Setenv("TOR_RELAY_SETUP_ROOT", keyRoot(t, strings.Replace(fixtureTorrc, "FAMILY", famA, 1), false))
	code, out, _ = runCLI(t, "keys", "--dry-run")
	if code != 1 || !strings.Contains(out, "lacks OfflineMasterKey 1") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	code, out, _ = runCLI(t, "keys", "renew", "--dry-run")
	if code != 0 || !strings.Contains(out, "tor --keygen --DataDirectory ~/tor-master --SigningKeyLifetime '30 days'") {
		t.Errorf("renew without flags: exit %d\n%s", code, out)
	}
}

func fakeKeyHost(t *testing.T) *host.Fake {
	t.Helper()
	f := host.NewFake()
	f.Paths["tor"] = true
	f.Files["/etc/tor/torrc"] = []byte("Nickname R\nContactInfo x\nORPort 9001\n")
	for name, src := range map[string]string{keys.SigningCert: "ed25519_signing_cert", keys.MasterPublic: "ed25519_master_id_public_key"} {
		data, err := os.ReadFile("../../internal/keys/testdata/" + src)
		if err != nil {
			t.Fatal(err)
		}
		f.Files["/var/lib/tor/keys/"+name] = data
	}
	f.Files["/var/lib/tor/keys/"+keys.MasterSecret] = []byte("secret")
	return f
}

func TestKeysOfflineFlow(t *testing.T) {
	f := fakeKeyHost(t)
	var out bytes.Buffer
	if err := keysCmd(f, keysRequest{Action: "offline", Out: &out, In: strings.NewReader("")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.Files["/etc/tor/torrc"]), "OfflineMasterKey 1") || !strings.Contains(out.String(), "sha256sum") {
		t.Fatalf("step 1:\n%s\n%s", f.Files["/etc/tor/torrc"], out.String())
	}
	if !f.Ran("systemctl", "reload", "tor@default") {
		t.Errorf("tor not reloaded: %q", f.CommandLines())
	}

	digest := keys.Digest([]byte("secret"))
	out.Reset()
	err := keysCmd(f, keysRequest{Action: "offline", RemoveMaster: true, Out: &out, In: strings.NewReader("deadbeefdeadbeef\n")})
	if err == nil || !strings.Contains(err.Error(), "nothing was removed") {
		t.Fatalf("wrong hash: %v", err)
	}
	if _, ok := f.Files["/var/lib/tor/keys/"+keys.MasterSecret]; !ok {
		t.Fatal("removed with a wrong hash")
	}
	out.Reset()
	if err := keysCmd(f, keysRequest{Action: "offline", RemoveMaster: true, Out: &out, In: strings.NewReader(digest[:20] + "\n")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Files["/var/lib/tor/keys/"+keys.MasterSecret]; ok {
		t.Error("master key still there")
	}
	if !strings.Contains(out.String(), "Removed the master key") || !strings.Contains(out.String(), "keys renew --from") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestKeysRenewFrom(t *testing.T) {
	f := fakeKeyHost(t)
	cert := f.Files["/var/lib/tor/keys/"+keys.SigningCert]
	f.Files["/root/tor-signing/"+keys.SigningCert] = cert
	f.Files["/root/tor-signing/"+keys.SigningSecret] = append([]byte("== ed25519v1-secret: type4 ==\x00\x00\x00"), bytes.Repeat([]byte{2}, 64)...)
	var out bytes.Buffer
	if err := keysCmd(f, keysRequest{Action: "renew", From: "/root/tor-signing", Out: &out}); err != nil {
		t.Fatal(err)
	}
	if f.Owners["/var/lib/tor/keys/"+keys.SigningSecret] != "debian-tor" || !strings.Contains(out.String(), "valid until") {
		t.Errorf("owner %q\n%s", f.Owners["/var/lib/tor/keys/"+keys.SigningSecret], out.String())
	}
	if err := keysCmd(f, keysRequest{Action: "renew", From: "/nowhere", Out: &out}); err == nil {
		t.Error("missing upload accepted")
	}
	if err := keysCmd(f, keysRequest{Action: "renew", From: "/a", Master: "/b", Out: &out}); err == nil {
		t.Error("--from and --master together accepted")
	}
}

func TestProofCommand(t *testing.T) {
	ids := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if strings.HasSuffix(r.URL.Path, "ed25519-family-id.txt") {
			_, _ = w.Write([]byte(ids + "\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	// Every request goes to the test server, whatever the domain.
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com"}
	client := &http.Client{Transport: tr}

	f := host.NewFake()
	f.Files["/etc/tor/torrc"] = []byte("Nickname R1\nContactInfo \"email:ops[]example.com url:https://example.com proof:uri-familyid-ed25519 ciissversion:3\"\nFamilyId " + ids + "\nORPort 9001\n")
	f.Files["/var/lib/tor/fingerprint"] = []byte("R1 ABCDEF0123456789ABCDEF0123456789ABCDEF01\n")
	var out bytes.Buffer
	if err := proofCmd(f, proofRequest{}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"== https://example.com/.well-known/tor-relay/ed25519-family-id.txt", ids, "rsa-fingerprint.txt", "ABCDEF0123456789ABCDEF0123456789ABCDEF01"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("proof lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	err := proofCmd(f, proofRequest{Check: true, HTTP: client}, &out)
	if err == nil || !strings.Contains(out.String(), "check: ok, lists every entry") || !strings.Contains(out.String(), "check: FAILED: HTTP 404") {
		t.Errorf("check: %v\n%s", err, out.String())
	}
}
