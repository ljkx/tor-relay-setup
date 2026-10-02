package family

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

const (
	testID  = "hQ3yMkBnCdE4F5g6H7i8J9k0LmNoPqRsTuVwXyZ+/ab"
	testID2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// makeKey returns a syntactically valid 96-byte secret key.
func makeKey(fill byte) []byte {
	k := bytes.Repeat([]byte{fill}, keySize)
	copy(k, KeyHeader)
	return k
}

func TestValidKey(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"valid", makeKey(1), true},
		{"too short", makeKey(1)[:95], false},
		{"too long", append(makeKey(1), 0), false},
		{"wrong header", append([]byte("== ed25519v1-secret: type0 ====="), make([]byte, 64)...), false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		if got := ValidKey(tt.data); got != tt.want {
			t.Errorf("%s: ValidKey = %v", tt.name, got)
		}
	}
}

func TestValidIDAndName(t *testing.T) {
	ids := map[string]bool{
		testID:            true,
		testID2:           true,
		testID[:42]:       false,
		testID + "A":      false,
		testID[:42] + "=": false,
		testID[:42] + "-": false,
		"":                false,
	}
	for id, want := range ids {
		if ValidID(id) != want {
			t.Errorf("ValidID(%q) = %v", id, !want)
		}
	}
	names := map[string]bool{
		"relayfamily":           true,
		"my-family_1.key":       true,
		"a":                     true,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
		".hidden":               false,
		"-flag":                 false,
		"a/b":                   false,
		"a b":                   false,
		"":                      false,
	}
	for n, want := range names {
		if ValidName(n) != want {
			t.Errorf("ValidName(%q) = %v", n, !want)
		}
	}
}

func TestKeyDirectory(t *testing.T) {
	tests := []struct {
		fam, key, data, want string
	}{
		{"/etc/tor/family/", "/var/lib/tor/keys", "/srv/tor", "/etc/tor/family"},
		{"", "/srv/keys//", "/srv/tor", "/srv/keys"},
		{"", "", "/srv/tor/", "/srv/tor/keys"},
		{"", "", "", "/var/lib/tor/keys"},
		{"/", "", "", "/"},
	}
	for _, tt := range tests {
		if got := KeyDirectory(tt.fam, tt.key, tt.data); got != tt.want {
			t.Errorf("KeyDirectory(%q, %q, %q) = %q, want %q", tt.fam, tt.key, tt.data, got, tt.want)
		}
	}
}

// TestIDFromSecret checks the FamilyId derivation against crypto/ed25519:
// tor stores the expanded secret key (SHA-512 of the seed, clamped) after
// a 32-byte header, and the FamilyId is the public key in unpadded base64.
func TestIDFromSecret(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	key := make([]byte, keySize)
	copy(key, KeyHeader)
	copy(key[32:], h[:])
	want := base64.RawStdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if got := IDFromSecret(key); got != want || !ValidID(got) {
		t.Errorf("IDFromSecret = %q, want %q", got, want)
	}
	if IDFromSecret([]byte("short")) != "" {
		t.Error("an invalid key got an ID")
	}
}

func TestInstalledAndHasKeyFor(t *testing.T) {
	const dir = "/var/lib/tor/keys"
	f := host.NewFake()
	f.Files[dir+"/alpha.secret_family_key"] = makeKey(1)
	f.Files[dir+"/alpha.public_family_id"] = []byte("  " + testID + "\n")
	f.Files[dir+"/beta.secret_family_key"] = makeKey(2)            // no public id, as tor needs none
	f.Files[dir+"/gamma.secret_family_key"] = makeKey(3)           // bad public id
	f.Files[dir+"/gamma.public_family_id"] = []byte("not-an-id\n") //
	f.Files[dir+"/broken.secret_family_key"] = []byte("short")     // invalid key
	f.Files[dir+"/secret_id_ed25519"] = makeKey(4)                 // not a family key
	f.Files["/other/zeta.secret_family_key"] = makeKey(5)          // other directory

	keys, err := Installed(f, dir)
	if err != nil {
		t.Fatal(err)
	}
	betaID := IDFromSecret(makeKey(2))
	want := []Key{
		{Name: "alpha", Path: dir + "/alpha.secret_family_key", ID: testID},
		{Name: "beta", Path: dir + "/beta.secret_family_key", ID: betaID},
		{Name: "gamma", Path: dir + "/gamma.secret_family_key", ID: IDFromSecret(makeKey(3))},
	}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("Installed =\n%+v\nwant\n%+v", keys, want)
	}

	tests := []struct {
		keys []Key
		id   string
		want bool
	}{
		{keys, testID, true},
		{keys, betaID, true},
		{keys, testID2, false},
		{keys, "*", true},
		{keys, "", false},
		{nil, "*", false},
	}
	for _, tt := range tests {
		if got := HasKeyFor(tt.keys, tt.id); got != tt.want {
			t.Errorf("HasKeyFor(%d keys, %q) = %v", len(tt.keys), tt.id, got)
		}
	}

	if keys, err := Installed(f, "/empty"); err != nil || keys != nil {
		t.Errorf("empty dir: %v, %v", keys, err)
	}
}

func TestInstall(t *testing.T) {
	const dir = "/var/lib/tor/keys"
	secret := makeKey(7)

	t.Run("fresh", func(t *testing.T) {
		f := host.NewFake()
		if err := Install(f, dir, "fam", secret, testID, "debian-tor"); err != nil {
			t.Fatal(err)
		}
		if !f.Dirs[dir] || f.Modes[dir] != fs.ModeDir|0o700 || f.Owners[dir] != "debian-tor" {
			t.Errorf("dir: %v %v %q", f.Dirs[dir], f.Modes[dir], f.Owners[dir])
		}
		sp, ip := dir+"/fam.secret_family_key", dir+"/fam.public_family_id"
		if !bytes.Equal(f.Files[sp], secret) || f.Modes[sp] != 0o600 || f.Owners[sp] != "debian-tor" {
			t.Errorf("secret: mode %v owner %q", f.Modes[sp], f.Owners[sp])
		}
		if string(f.Files[ip]) != testID+"\n" || f.Modes[ip] != 0o600 || f.Owners[ip] != "debian-tor" {
			t.Errorf("id: %q mode %v owner %q", f.Files[ip], f.Modes[ip], f.Owners[ip])
		}
		keys, _ := Installed(f, dir)
		if !HasKeyFor(keys, testID) {
			t.Errorf("installed key not found: %+v", keys)
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		f := host.NewFake()
		for i := 0; i < 2; i++ {
			if err := Install(f, dir, "fam", secret, testID, "debian-tor"); err != nil {
				t.Fatalf("install %d: %v", i, err)
			}
		}
		delete(f.Files, dir+"/fam.public_family_id")
		if err := Install(f, dir, "fam", secret, testID, "debian-tor"); err != nil {
			t.Fatal(err)
		}
		if string(f.Files[dir+"/fam.public_family_id"]) != testID+"\n" {
			t.Error("missing public id not restored")
		}
	})

	t.Run("refuses overwrite", func(t *testing.T) {
		f := host.NewFake()
		other := makeKey(8)
		f.Files[dir+"/fam.secret_family_key"] = other
		err := Install(f, dir, "fam", secret, testID, "debian-tor")
		if err == nil || !strings.Contains(err.Error(), "never overwritten") {
			t.Fatalf("err = %v", err)
		}
		if !bytes.Equal(f.Files[dir+"/fam.secret_family_key"], other) {
			t.Error("existing key was modified")
		}
		if _, ok := f.Files[dir+"/fam.public_family_id"]; ok {
			t.Error("public id written despite conflict")
		}
	})

	t.Run("validation", func(t *testing.T) {
		f := host.NewFake()
		cases := []struct {
			name   string
			secret []byte
			id     string
		}{
			{"../evil", secret, testID},
			{"fam", []byte("short"), testID},
			{"fam", nil, testID},
			{"fam", secret, "bad"},
		}
		for _, c := range cases {
			if err := Install(f, dir, c.name, c.secret, c.id, ""); err == nil {
				t.Errorf("Install(%q, %d bytes, %q) succeeded", c.name, len(c.secret), c.id)
			}
		}
		if len(f.Files) != 0 {
			t.Errorf("files written: %v", f.Files)
		}
	})
}

// recordingHost records the writes a dry-run host is asked to report.
type recordingHost struct {
	*host.Fake
	mu     sync.Mutex
	writes []string
}

func (r *recordingHost) WriteFile(p string, data []byte, opt host.FileOptions) (host.Change, error) {
	r.mu.Lock()
	r.writes = append(r.writes, p)
	r.mu.Unlock()
	return r.Fake.WriteFile(p, data, opt)
}

func (r *recordingHost) MkdirAll(p string, perm fs.FileMode, owner string) error {
	r.mu.Lock()
	r.writes = append(r.writes, p+"/")
	r.mu.Unlock()
	return r.Fake.MkdirAll(p, perm, owner)
}

func TestInstallDryRun(t *testing.T) {
	f := host.NewFake()
	f.Dry = true
	r := &recordingHost{Fake: f}
	if err := Install(r, "/var/lib/tor/keys", "fam", nil, "", "debian-tor"); err != nil {
		t.Fatal(err)
	}
	want := []string{"/var/lib/tor/keys/", "/var/lib/tor/keys/fam.secret_family_key", "/var/lib/tor/keys/fam.public_family_id"}
	if !reflect.DeepEqual(r.writes, want) {
		t.Errorf("writes = %q", r.writes)
	}
	if len(f.Files) != 0 || len(f.Dirs) != 0 {
		t.Error("dry run changed the fake")
	}

	// A conflicting key is still reported in a dry run.
	f.Files["/var/lib/tor/keys/fam.secret_family_key"] = makeKey(9)
	if err := Install(r, "/var/lib/tor/keys", "fam", nil, "", "debian-tor"); err == nil {
		t.Error("dry run ignored an existing different key")
	}
}

// fakeTor simulates `tor --keygen-family NAME` by writing key files into
// the command's working directory.
func fakeTor(t *testing.T, secret []byte, id string) func(host.Command) (host.Result, error) {
	return func(c host.Command) (host.Result, error) {
		if c.Name != "tor" || !c.Mutates || len(c.Args) != 6 || c.Args[4] != "--keygen-family" {
			return host.Result{}, errors.New("unexpected " + c.String())
		}
		name := c.Args[5]
		if secret != nil {
			if err := os.WriteFile(filepath.Join(c.Dir, name+".secret_family_key"), secret, 0o600); err != nil {
				t.Error(err)
			}
		}
		if id != "" {
			if err := os.WriteFile(filepath.Join(c.Dir, name+".public_family_id"), []byte(id+"\n"), 0o600); err != nil {
				t.Error(err)
			}
		}
		return host.Result{Output: "Generated family key\n"}, nil
	}
}

func TestGenerate(t *testing.T) {
	secret := makeKey(6)

	t.Run("success", func(t *testing.T) {
		dir := t.TempDir()
		f := host.NewFake()
		f.Handler = fakeTor(t, secret, testID)
		gotSecret, gotID, err := Generate(context.Background(), f, dir, "myfamily")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotSecret, secret) || gotID != testID {
			t.Errorf("got %d bytes, id %q", len(gotSecret), gotID)
		}
		empty := filepath.Join(dir, "empty.torrc")
		want := host.Command{
			Name:    "tor",
			Args:    []string{"--defaults-torrc", empty, "-f", empty, "--keygen-family", "myfamily"},
			Dir:     dir,
			Mutates: true,
		}
		if len(f.Commands) != 1 || !reflect.DeepEqual(f.Commands[0], want) {
			t.Errorf("commands = %+v", f.Commands)
		}
		if data, err := os.ReadFile(empty); err != nil || len(data) != 0 {
			t.Errorf("empty torrc: %q, %v", data, err)
		}
	})

	failures := []struct {
		name    string
		secret  []byte
		id      string
		handler func(host.Command) (host.Result, error)
		want    string
	}{
		{name: "tor fails", handler: func(c host.Command) (host.Result, error) {
			return host.Result{ExitCode: 1}, &host.ExitError{Command: c.String(), ExitCode: 1}
		}, want: "generate family key"},
		{name: "no secret", id: testID, want: "did not produce myfamily.secret_family_key"},
		{name: "invalid secret", secret: []byte("junk"), id: testID, want: "invalid myfamily.secret_family_key"},
		{name: "no id", secret: secret, want: "did not produce myfamily.public_family_id"},
		{name: "invalid id", secret: secret, id: "nope", want: "invalid FamilyId"},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			f := host.NewFake()
			f.Handler = tt.handler
			if f.Handler == nil {
				f.Handler = fakeTor(t, tt.secret, tt.id)
			}
			_, _, err := Generate(context.Background(), f, t.TempDir(), "myfamily")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}

	t.Run("invalid name", func(t *testing.T) {
		f := host.NewFake()
		if _, _, err := Generate(context.Background(), f, t.TempDir(), "../x"); err == nil {
			t.Error("accepted invalid name")
		}
		if len(f.Commands) != 0 {
			t.Error("ran tor for an invalid name")
		}
	})

	t.Run("dry run", func(t *testing.T) {
		f := host.NewFake()
		f.Dry = true
		f.Handler = func(host.Command) (host.Result, error) {
			t.Error("tor must not run in a dry run")
			return host.Result{}, nil
		}
		s, id, err := Generate(context.Background(), f, t.TempDir(), "myfamily")
		if s != nil || id != "" || err != nil {
			t.Errorf("got %v, %q, %v", s, id, err)
		}
		if !f.Ran("tor", "--keygen-family", "myfamily") {
			t.Error("dry run did not report the tor command")
		}
	})
}

func TestShareInstructions(t *testing.T) {
	keys := []Key{
		{Name: "fam", Path: "/var/lib/tor/keys/fam.secret_family_key", ID: testID},
		{Name: "old", Path: "/var/lib/tor/keys/old.secret_family_key"},
	}
	got := ShareInstructions(keys, "relay2.example.org")
	for _, want := range []string{
		"scp /var/lib/tor/keys/fam.secret_family_key /var/lib/tor/keys/fam.public_family_id root@relay2.example.org:/root/",
		"scp /var/lib/tor/keys/old.secret_family_key /var/lib/tor/keys/old.public_family_id root@relay2.example.org:/root/",
		"FamilyId " + testID,
		"Import an existing family key",
		"Delete the copies",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !strings.Contains(ShareInstructions(keys, ""), "root@NEW-RELAY:/root/") {
		t.Error("default target missing")
	}
	if !strings.Contains(ShareInstructions(nil, "x"), "No family key") {
		t.Error("empty key list not explained")
	}
	spaced := ShareInstructions([]Key{{Path: "/srv/my keys/a.secret_family_key"}}, "h")
	if !strings.Contains(spaced, "'/srv/my keys/a.secret_family_key'") {
		t.Errorf("paths not shell-quoted:\n%s", spaced)
	}
}
