package keys

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// testdata holds a signing certificate and master public key made with
// tor 0.4.9.13 (`tor --keygen --no-passphrase --SigningKeyLifetime "120 months"`
// in a throw-away DataDirectory), plus what tor-print-ed-signing-cert and
// `tor --key-expiration sign --format timestamp` printed for it.
func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

const keyDir = "/var/lib/tor/keys"

// expiry is when the test certificate expires.
var expiry = time.Unix(2106514800, 0).UTC()

func TestParseCertMatchesTor(t *testing.T) {
	t.Parallel()
	c, err := ParseCert(readTestdata(t, SigningCert))
	if err != nil {
		t.Fatal(err)
	}
	// tor-print-ed-signing-cert: "UNIX timestamp: 2106514800".
	m := regexp.MustCompile(`UNIX timestamp: (\d+)`).FindSubmatch(readTestdata(t, "tor-print-ed-signing-cert.txt"))
	if m == nil {
		t.Fatal("no timestamp in tor-print-ed-signing-cert.txt")
	}
	helper, _ := strconv.ParseInt(string(m[1]), 10, 64)
	if c.Expires.Unix() != helper {
		t.Errorf("Expires = %d, tor-print-ed-signing-cert says %d", c.Expires.Unix(), helper)
	}
	// tor --key-expiration sign --format timestamp: "... valid until 2106514800."
	if want := strconv.FormatInt(c.Expires.Unix(), 10); !strings.Contains(string(readTestdata(t, "key-expiration.txt")), want) {
		t.Errorf("tor --key-expiration does not report %s", want)
	}
	if !strings.Contains(string(readTestdata(t, "tor-print-ed-signing-cert.txt")), "RFC 1123 timestamp: "+c.Expires.Format(time.RFC1123)[:len("Sun, 01 Nov 2026 13:00:00")]) {
		t.Errorf("RFC 1123 time differs from %s", c.Expires.Format(time.RFC1123))
	}
	if c.Type != certTypeSigning || len(c.Key) != 32 {
		t.Errorf("Type %d, key %d bytes", c.Type, len(c.Key))
	}
	master, err := ParsePublicKey(readTestdata(t, MasterPublic))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Signed || !c.Signer.Equal(master) {
		t.Errorf("signature %v, signer matches master %v", c.Signed, c.Signer.Equal(master))
	}
	if len(Identity(master)) != 43 {
		t.Errorf("Identity = %q", Identity(master))
	}
}

func TestParseCertRejectsDamage(t *testing.T) {
	t.Parallel()
	good := readTestdata(t, SigningCert)
	tampered := bytes.Clone(good)
	tampered[headerLen+10] ^= 0xff // inside the certified key
	if c, err := ParseCert(tampered); err != nil || c.Signed {
		t.Errorf("tampered cert: err %v, signed %v", err, c.Signed)
	}
	tests := map[string][]byte{
		"short":       good[:40],
		"bad header":  append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), good[headerLen:]...),
		"bad version": append(append(bytes.Clone(good[:headerLen]), 2), good[headerLen+1:]...),
		"truncated":   good[:len(good)-10],
		"trailing":    append(bytes.Clone(good), 0),
	}
	for name, data := range tests {
		if _, err := ParseCert(data); err == nil {
			t.Errorf("%s: ParseCert accepted it", name)
		}
	}
	// The bare certificate without tor's file header parses too.
	if _, err := ParseCert(good[headerLen:]); err != nil {
		t.Errorf("bare cert: %v", err)
	}
	if _, err := ParsePublicKey(good); err == nil {
		t.Error("a certificate parsed as a public key")
	}
}

func fakeKeys(t *testing.T, withMaster bool) *host.Fake {
	t.Helper()
	h := host.NewFake()
	h.Files[keyDir+"/"+SigningCert] = readTestdata(t, SigningCert)
	h.Files[keyDir+"/"+MasterPublic] = readTestdata(t, MasterPublic)
	h.Files[keyDir+"/"+RSAIdentity] = []byte("rsa-identity")
	if withMaster {
		h.Files[keyDir+"/"+MasterSecret] = []byte("master-secret-bytes")
	}
	return h
}

func TestInspectAndWarnings(t *testing.T) {
	t.Parallel()
	week := expiry.Add(-5 * 24 * time.Hour)
	tests := []struct {
		name    string
		master  bool
		offline bool
		now     time.Time
		want    []string
	}{
		{"master on disk: tor renews itself", true, false, expiry.Add(time.Hour), nil},
		{"offline, far from expiry", false, true, expiry.Add(-20 * 24 * time.Hour), nil},
		{"offline, expiring", false, true, week, []string{"expires in 5 days"}},
		{"offline, expired", false, true, expiry.Add(time.Hour), []string{"expired on 2036-10-01 23:00 UTC"}},
		{"master gone without OfflineMasterKey", false, false, week, []string{"lacks OfflineMasterKey 1", "expires in 5 days"}},
		{"offline flag with master still on disk", true, true, week, []string{"expires in 5 days"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := Inspect(fakeKeys(t, tt.master), keyDir, tt.offline)
			if !st.CertExpires.Equal(expiry) || st.CertProblem != "" || st.MasterOnDisk != tt.master {
				t.Fatalf("Inspect = %+v", st)
			}
			w := st.Warnings(tt.now, 0)
			if len(w) != len(tt.want) {
				t.Fatalf("Warnings = %q, want %d", w, len(tt.want))
			}
			for i, want := range tt.want {
				if !strings.Contains(w[i], want) {
					t.Errorf("warning %q lacks %q", w[i], want)
				}
			}
		})
	}

	h := fakeKeys(t, false)
	h.Files[keyDir+"/"+MasterPublic] = append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), bytes.Repeat([]byte{7}, 32)...)
	if st := Inspect(h, keyDir, true); !strings.Contains(st.CertProblem, "different master key") {
		t.Errorf("mismatched master: %q", st.CertProblem)
	}
	delete(h.Files, keyDir+"/"+SigningCert)
	if st := Inspect(h, keyDir, true); !strings.Contains(strings.Join(st.Warnings(expiry, 7), " "), "no ed25519_signing_cert") {
		t.Errorf("missing cert not reported: %+v", st)
	}
	h.Files[keyDir+"/"+MasterSecretEncrypted] = []byte("x")
	if st := Inspect(h, keyDir, true); !st.MasterOnDisk || !st.MasterEncrypted {
		t.Errorf("encrypted master: %+v", st)
	}
}

func TestExportAndRemoveMaster(t *testing.T) {
	t.Parallel()
	now := expiry.Add(-10 * 24 * time.Hour)
	h := fakeKeys(t, true)
	dir := ExportDir("relay2", now)
	if !strings.HasPrefix(dir, "/root/tor-master-key-relay2-2036") {
		t.Errorf("ExportDir = %q", dir)
	}
	ex, err := ExportMaster(h, keyDir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Files) != 3 || ex.Digest != Digest([]byte("master-secret-bytes")) {
		t.Fatalf("Export = %+v", ex)
	}
	if string(h.Files[dir+"/"+MasterSecret]) != "master-secret-bytes" || h.Modes[dir+"/"+MasterSecret] != 0o600 {
		t.Error("export copy wrong")
	}
	steps := DownloadSteps(ex, "relay2")
	for _, want := range []string{dir, ex.Digest[:MinConfirm], "--remove-master --instance relay2", "sha256sum"} {
		if !strings.Contains(steps, want) {
			t.Errorf("DownloadSteps lacks %q:\n%s", want, steps)
		}
	}

	// Every precondition is enforced before anything is deleted.
	refusals := []struct {
		name    string
		offline bool
		typed   string
		now     time.Time
		want    string
	}{
		{"no OfflineMasterKey", false, ex.Digest, now, "OfflineMasterKey 1"},
		{"wrong hash", true, strings.Repeat("0", 16), now, "does not match"},
		{"too short", true, ex.Digest[:8], now, "does not match"},
		{"cert expiring", true, ex.Digest, expiry.Add(-time.Hour), "renew it before"},
	}
	for _, r := range refusals {
		if err := RemoveMaster(h, keyDir, r.offline, r.typed, dir, r.now); err == nil || !strings.Contains(err.Error(), r.want) {
			t.Errorf("%s: err = %v, want %q", r.name, err, r.want)
		}
		if _, ok := h.Files[keyDir+"/"+MasterSecret]; !ok {
			t.Fatalf("%s: the master key was deleted", r.name)
		}
	}
	if err := RemoveMaster(h, keyDir, true, " "+strings.ToUpper(ex.Digest[:MinConfirm])+"\n", dir, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Files[keyDir+"/"+MasterSecret]; ok {
		t.Error("master key still in the key directory")
	}
	if _, ok := h.Files[dir+"/"+MasterSecret]; ok {
		t.Error("export copy still on the server")
	}
	for _, keep := range []string{RSAIdentity, MasterPublic, SigningCert} {
		if _, ok := h.Files[keyDir+"/"+keep]; !ok {
			t.Errorf("%s was removed", keep)
		}
	}
	if _, err := ExportMaster(h, keyDir, dir); err == nil {
		t.Error("Export without a master key succeeded")
	}
}

func TestInstallSigning(t *testing.T) {
	t.Parallel()
	secret := append([]byte("== ed25519v1-secret: type4 ==\x00\x00\x00"), bytes.Repeat([]byte{1}, 64)...)
	cert := readTestdata(t, SigningCert)
	now := expiry.Add(-24 * time.Hour)

	h := fakeKeys(t, false)
	h.Files[keyDir+"/"+SigningCert] = []byte("old cert")
	c, err := InstallSigning(h, keyDir, "_tor-relay2", secret, cert, now)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Expires.Equal(expiry) || !bytes.Equal(h.Files[keyDir+"/"+SigningCert], cert) {
		t.Error("certificate not installed")
	}
	if h.Owners[keyDir+"/"+SigningSecret] != "_tor-relay2" || h.Modes[keyDir+"/"+SigningSecret] != 0o600 {
		t.Errorf("owner %q mode %o", h.Owners[keyDir+"/"+SigningSecret], h.Modes[keyDir+"/"+SigningSecret])
	}
	if string(h.Files[keyDir+"/"+SigningCert+".bak.test"]) != "old cert" {
		t.Error("previous certificate not backed up")
	}

	other := fakeKeys(t, false)
	other.Files[keyDir+"/"+MasterPublic] = append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), bytes.Repeat([]byte{7}, 32)...)
	refusals := []struct {
		name   string
		h      *host.Fake
		secret []byte
		cert   []byte
		now    time.Time
		want   string
	}{
		{"other relay", other, secret, cert, now, "another relay"},
		{"expired", fakeKeys(t, false), secret, cert, expiry.Add(time.Hour), "already expired"},
		{"bad secret", fakeKeys(t, false), []byte("nope"), cert, now, "not an ed25519 signing key"},
		{"bad cert", fakeKeys(t, false), secret, []byte("nope"), now, SigningCert},
	}
	for _, r := range refusals {
		before := string(r.h.Files[keyDir+"/"+SigningCert])
		if _, err := InstallSigning(r.h, keyDir, "debian-tor", r.secret, r.cert, r.now); err == nil || !strings.Contains(err.Error(), r.want) {
			t.Errorf("%s: err = %v, want %q", r.name, err, r.want)
		}
		if string(r.h.Files[keyDir+"/"+SigningCert]) != before {
			t.Errorf("%s: the certificate was replaced", r.name)
		}
	}
}

func TestRenew(t *testing.T) {
	t.Parallel()
	h := fakeKeys(t, true)
	cert := readTestdata(t, SigningCert)
	var ran []string
	h.Handler = func(c host.Command) (host.Result, error) {
		ran = c.Args
		// Stand in for tor --keygen: write the signing files.
		for i, a := range c.Args {
			if a == "--DataDirectory" {
				dir := filepath.Join(c.Args[i+1], "keys")
				if master, err := os.ReadFile(filepath.Join(dir, MasterSecret)); err != nil || string(master) != "master-secret-bytes" {
					t.Errorf("master key not copied for tor: %v", err)
				}
				_ = os.WriteFile(filepath.Join(dir, SigningSecret), []byte("new-secret"), 0o600)
				_ = os.WriteFile(filepath.Join(dir, SigningCert), cert, 0o600)
			}
		}
		return host.Result{}, nil
	}
	secret, got, err := Renew(context.Background(), h, keyDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "new-secret" || !bytes.Equal(got, cert) {
		t.Errorf("Renew = %q, %d bytes", secret, len(got))
	}
	line := strings.Join(ran, " ")
	for _, want := range []string{"--keygen --no-passphrase", "--SigningKeyLifetime 30 days", "-f "} {
		if !strings.Contains(line, want) {
			t.Errorf("tor args %q lack %q", line, want)
		}
	}
	if strings.Contains(line, keyDir) {
		t.Error("tor ran in the live key directory")
	}

	if _, _, err := Renew(context.Background(), h, keyDir, "forever"); err == nil {
		t.Error("bad lifetime accepted")
	}
	enc := fakeKeys(t, false)
	enc.Files[keyDir+"/"+MasterSecretEncrypted] = []byte("x")
	if _, _, err := Renew(context.Background(), enc, keyDir, ""); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("encrypted master: %v", err)
	}
	dry := fakeKeys(t, true)
	dry.Dry = true
	if s, c, err := Renew(context.Background(), dry, keyDir, "2 weeks"); err != nil || s != nil || c != nil {
		t.Errorf("dry run: %v", err)
	}
	if !strings.Contains(RenewSteps("relay2", ""), "keys renew --from /root/tor-signing-relay2 --instance relay2") {
		t.Errorf("RenewSteps:\n%s", RenewSteps("relay2", ""))
	}
}

func TestConfirmAndLifetime(t *testing.T) {
	t.Parallel()
	d := Digest([]byte("x"))
	if !ConfirmMatches(d[:12], d) || !ConfirmMatches(strings.ToUpper(d), d) || ConfirmMatches(d[:11], d) || ConfirmMatches("", d) {
		t.Error("ConfirmMatches")
	}
	for s, want := range map[string]bool{"30 days": true, "2 weeks": true, "3 months": true, "0 days": false, "30days": false, "1 year": false} {
		if ValidLifetime(s) != want {
			t.Errorf("ValidLifetime(%q) = %v", s, !want)
		}
	}
}
