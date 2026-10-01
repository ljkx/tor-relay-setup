package torproject

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func readTorKey(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "tor-signing-key.asc"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// newEntity generates a throwaway key pair.
func newEntity(t *testing.T, name string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", name+"@example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// armorPublic armors the concatenated binary public keys.
func armorPublic(t *testing.T, binaries ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range binaries {
		if _, err := w.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func publicBinary(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dearmor(t *testing.T, armored []byte) []byte {
	t.Helper()
	block, err := armor.Decode(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(block.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestKeyURL(t *testing.T) {
	want := "https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc"
	if got := KeyURL(); got != want {
		t.Errorf("KeyURL() = %q, want %q", got, want)
	}
}

func TestVerifySigningKeyAcceptsRealKey(t *testing.T) {
	out, err := VerifySigningKey(readTorKey(t))
	if err != nil {
		t.Fatalf("VerifySigningKey: %v", err)
	}
	if bytes.HasPrefix(out, []byte("-----BEGIN")) {
		t.Fatal("output is armored, want binary")
	}
	// go-crypto must read the binary keyring back with the right fingerprint.
	el, err := openpgp.ReadKeyRing(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("re-read binary keyring: %v", err)
	}
	if len(el) != 1 {
		t.Fatalf("re-read %d entities, want 1", len(el))
	}
	if fp := strings.ToUpper(hex.EncodeToString(el[0].PrimaryKey.Fingerprint)); fp != SigningKeyFingerprint {
		t.Errorf("fingerprint = %s, want %s", fp, SigningKeyFingerprint)
	}
	if len(el[0].Subkeys) == 0 {
		t.Error("signing subkey was dropped")
	}

	// When gpg is available, it must accept the file as apt's gpgv would.
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Log("gpg not installed; skipping gpg --show-keys check")
		return
	}
	path := filepath.Join(t.TempDir(), "keyring.gpg")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gpg, "--homedir", t.TempDir(), "--batch", "--show-keys", "--with-colons", path)
	colons, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gpg --show-keys: %v\n%s", err, colons)
	}
	if !strings.Contains(string(colons), "fpr:::::::::"+SigningKeyFingerprint+":") {
		t.Errorf("gpg did not report the Tor fingerprint:\n%s", colons)
	}
}

func TestVerifySigningKeyAlsoAcceptsBinaryRoundTrip(t *testing.T) {
	// Re-armoring our own output must verify again (idempotence).
	out, err := VerifySigningKey(readTorKey(t))
	if err != nil {
		t.Fatal(err)
	}
	again, err := VerifySigningKey(armorPublic(t, out))
	if err != nil {
		t.Fatalf("second verification: %v", err)
	}
	if !bytes.Equal(out, again) {
		t.Error("re-verification changed the keyring")
	}
}

func TestVerifySigningKeyRejects(t *testing.T) {
	torBinary := dearmor(t, readTorKey(t))
	other := newEntity(t, "impostor")
	otherFP := strings.ToUpper(hex.EncodeToString(other.PrimaryKey.Fingerprint))

	tests := []struct {
		name    string
		input   []byte
		wantMsg string
	}{
		{"wrong key", armorPublic(t, publicBinary(t, other)), otherFP},
		{"tor key plus injected key", armorPublic(t, torBinary, publicBinary(t, other)), otherFP},
		{"injected key before tor key", armorPublic(t, publicBinary(t, other), torBinary), SigningKeyFingerprint},
		{"garbage", []byte("this is not a key"), "unreadable"},
		{"empty", nil, "unreadable"},
		{"armored garbage", armorPublic(t, []byte("\x00\x01\x02garbage")), "unexpected"},
		{"html error page", []byte("<html><body>502 Bad Gateway</body></html>"), "unreadable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := VerifySigningKey(tt.input)
			if err == nil {
				t.Fatalf("accepted, returned %d bytes", len(out))
			}
			if !errors.Is(err, ErrUnexpectedKey) {
				t.Errorf("error %v does not wrap ErrUnexpectedKey", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
		})
	}
}

func TestSources(t *testing.T) {
	want := "Types: deb deb-src\n" +
		"URIs: https://deb.torproject.org/torproject.org/\n" +
		"Suites: bookworm\n" +
		"Components: main\n" +
		"Signed-By: /usr/share/keyrings/deb.torproject.org-keyring.gpg\n"
	if got := string(Sources("bookworm")); got != want {
		t.Errorf("Sources() =\n%s\nwant\n%s", got, want)
	}
}

func TestUnattendedConfig(t *testing.T) {
	debian := "// Managed by tor-relay-setup. Enables unattended upgrades for Tor Project packages.\n" +
		"Unattended-Upgrade::Origins-Pattern {\n" +
		`    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";` + "\n" +
		`    "origin=TorProject";` + "\n" +
		"};\n"
	ubuntu := "// Managed by tor-relay-setup. Enables unattended upgrades for Tor Project packages.\n" +
		"Unattended-Upgrade::Allowed-Origins {\n" +
		`    "${distro_id}:${distro_codename}-security";` + "\n" +
		`    "TorProject:${distro_codename}";` + "\n" +
		"};\n"
	for _, tt := range []struct{ osID, want string }{
		{"debian", debian},
		{"ubuntu", ubuntu},
		{"linuxmint", ubuntu},
		{"", ubuntu},
	} {
		if got := string(UnattendedConfig(tt.osID)); got != tt.want {
			t.Errorf("UnattendedConfig(%q) =\n%s\nwant\n%s", tt.osID, got, tt.want)
		}
	}
}

func TestAutoUpgradesConfig(t *testing.T) {
	want := "APT::Periodic::Update-Package-Lists \"1\";\n" +
		"APT::Periodic::AutocleanInterval \"5\";\n" +
		"APT::Periodic::Unattended-Upgrade \"1\";\n" +
		"APT::Periodic::Verbose \"1\";\n"
	if got := string(AutoUpgradesConfig()); got != want {
		t.Errorf("AutoUpgradesConfig() =\n%s\nwant\n%s", got, want)
	}
}

const policyTor = `tor:
  Installed: (none)
  Candidate: 0.4.9.13-1~noble+1
  Version table:
     0.4.9.13-1~noble+1 500
        500 https://deb.torproject.org/torproject.org noble/main amd64 Packages
     0.4.8.10-1build2 500
        500 http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages
`

const policyInstalledTor = `tor:
  Installed: 0.4.9.13-1~bookworm+1
  Candidate: 0.4.9.13-1~bookworm+1
  Version table:
 *** 0.4.9.13-1~bookworm+1 500
        500 https://deb.torproject.org/torproject.org bookworm/main amd64 Packages
        100 /var/lib/dpkg/status
     0.4.7.16-1 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
`

// An attacker-controlled repository pinned higher offers a newer tor; the
// Tor Project still offers an older version further down the table.
const policyEvilPinned = `tor:
  Installed: (none)
  Candidate: 9.9.9-1
  Version table:
     9.9.9-1 990
        990 https://evil.example/debian stable/main amd64 Packages
     0.4.9.13-1~noble+1 500
        500 https://deb.torproject.org/torproject.org noble/main amd64 Packages
`

// A look-alike URI embeds the Tor Project path.
const policyLookAlike = `tor:
  Installed: (none)
  Candidate: 0.4.9.99-1
  Version table:
     0.4.9.99-1 500
        500 https://evil.example/deb.torproject.org/torproject.org noble/main amd64 Packages
`

const policyNone = `tor:
  Installed: (none)
  Candidate: (none)
  Version table:
`

// Candidate from the distribution although the Tor repo is configured.
const policyDistroWins = `tor:
  Installed: (none)
  Candidate: 0.4.8.10-1build2
  Version table:
     0.4.9.13-1~noble+1 100
        100 https://deb.torproject.org/torproject.org noble/main amd64 Packages
     0.4.8.10-1build2 500
        500 http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages
`

const policyOnion = `tor:
  Installed: (none)
  Candidate: 1:0.4.9.13-1~noble+1
  Version table:
     1:0.4.9.13-1~noble+1 500
        500 tor+https://deb.torproject.org/torproject.org/ noble/main amd64 Packages
`

func TestCandidateFromTorProject(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   bool
	}{
		{"tor candidate", policyTor, true},
		{"installed tor candidate", policyInstalledTor, true},
		{"evil higher-priority candidate", policyEvilPinned, false},
		{"look-alike uri", policyLookAlike, false},
		{"no candidate", policyNone, false},
		{"distribution candidate", policyDistroWins, false},
		{"tor+https transport with epoch", policyOnion, true},
		{"empty output", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CandidateFromTorProject(tt.policy); got != tt.want {
				t.Errorf("CandidateFromTorProject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTorVersion(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"Tor version 0.4.9.13.\n", "0.4.9.13", false},
		{"Tor version 0.4.9.13.\nTor is running on Linux with Libevent 2.1.12-stable.\n", "0.4.9.13", false},
		{"Tor version 0.4.9.4-rc (git-abc123).", "0.4.9.4-rc", false},
		{"Tor version 0.5.0.1-alpha-dev.", "0.5.0.1-alpha-dev", false},
		{"tor: command not found", "", true},
		{"", "", true},
		{"Tor version .\n", "", true},
		{"Something\nTor version 0.4.9.13.\n", "", true},
	}
	for _, tt := range tests {
		got, err := ParseTorVersion(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseTorVersion(%q) = %q, %v; want %q, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	tests := []struct {
		version, min string
		want         bool
	}{
		{"0.4.9.13", "0.4.9", true},
		{"0.4.9", "0.4.9", true},
		{"0.4.9.4-rc", "0.4.9", true},
		{"0.5.0.1-alpha", "0.4.9", true},
		{"0.4.8.25", "0.4.9", false},
		{"0.4.10.1", "0.4.9", true},
		{"0.3.5.20", "0.4.9", false},
		{"1.0", "0.4.9", true},
		{"0.4.9.4-rc", "0.4.9.4", false},
		{"0.4.9.4", "0.4.9.4-rc", true},
		{"0.4.9.4-rc", "0.4.9.4-alpha", true},
		{"0.4.9.4-alpha", "0.4.9.4-rc", false},
		{"0.4", "0.4.9", false},
		{"", "0.4.9", false},
		{"garbage", "0.4.9", false},
		{"0.4.9", "", false},
	}
	for _, tt := range tests {
		if got := VersionAtLeast(tt.version, tt.min); got != tt.want {
			t.Errorf("VersionAtLeast(%q, %q) = %v, want %v", tt.version, tt.min, got, tt.want)
		}
	}
}

// redirectClient sends every request to srv, keeping the path, and records
// the paths requested.
func redirectClient(t *testing.T, srv *httptest.Server) (*http.Client, *[]string) {
	t.Helper()
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	base := srv.Client().Transport
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Host+r.URL.Path)
		r = r.Clone(r.Context())
		r.URL.Scheme = target.Scheme
		r.URL.Host = target.Host
		return base.RoundTrip(r)
	})}, &paths
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSuiteAvailable(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		want    bool
		wantErr bool
	}{
		{"published", http.StatusOK, true, false},
		{"not published", http.StatusNotFound, false, false},
		{"server error", http.StatusInternalServerError, false, true},
		{"forbidden", http.StatusForbidden, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, "Origin: TorProject\n")
			}))
			defer srv.Close()
			client, paths := redirectClient(t, srv)
			got, err := SuiteAvailable(context.Background(), client, "noble")
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Errorf("SuiteAvailable() = %v, %v; want %v, err=%v", got, err, tt.want, tt.wantErr)
			}
			want := []string{"deb.torproject.org/torproject.org/dists/noble/Release"}
			if strings.Join(*paths, ",") != want[0] {
				t.Errorf("requested %v, want %v", *paths, want)
			}
		})
	}
}

func TestSuiteAvailableTransportError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	client, _ := redirectClient(t, srv)
	srv.Close() // connection refused from now on
	if ok, err := SuiteAvailable(context.Background(), client, "noble"); ok || err == nil {
		t.Errorf("SuiteAvailable() = %v, %v; want false and an error", ok, err)
	}
}

func TestSuiteAvailableRejectsBadCodename(t *testing.T) {
	for _, codename := range []string{"", "Noble", "../../etc", "noble/updates", "noble?x=1", "1noble", "noble bookworm"} {
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			t.Errorf("request sent for codename %q", codename)
			return nil, errors.New("unreachable")
		})}
		if ok, err := SuiteAvailable(context.Background(), client, codename); ok || err == nil {
			t.Errorf("SuiteAvailable(%q) = %v, %v; want an error", codename, ok, err)
		}
	}
}

func TestFetchSigningKey(t *testing.T) {
	key := readTorKey(t)
	tests := []struct {
		name    string
		status  int
		body    []byte
		wantErr string
	}{
		{"ok", http.StatusOK, key, ""},
		{"exactly the limit", http.StatusOK, bytes.Repeat([]byte("a"), maxKeySize), ""},
		{"too large", http.StatusOK, bytes.Repeat([]byte("a"), maxKeySize+1), "larger than"},
		{"not found", http.StatusNotFound, []byte("nope"), "404"},
		{"server error", http.StatusBadGateway, nil, "502"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write(tt.body)
			}))
			defer srv.Close()
			client, paths := redirectClient(t, srv)
			got, err := FetchSigningKey(context.Background(), client)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("FetchSigningKey() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FetchSigningKey(): %v", err)
			}
			if !bytes.Equal(got, tt.body) {
				t.Errorf("body mismatch: got %d bytes, want %d", len(got), len(tt.body))
			}
			if want := "deb.torproject.org/torproject.org/" + SigningKeyFingerprint + ".asc"; (*paths)[0] != want {
				t.Errorf("requested %s, want %s", (*paths)[0], want)
			}
		})
	}
}

func TestFetchSigningKeyHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	client, _ := redirectClient(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FetchSigningKey(ctx, client); !errors.Is(err, context.Canceled) {
		t.Errorf("FetchSigningKey() error = %v, want context.Canceled", err)
	}
}
