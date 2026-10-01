package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

type entry struct {
	name     string
	body     string
	typeflag byte
}

func makeArchive(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.body)), Typeflag: e.typeflag}
		if e.typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Typeflag == tar.TypeSymlink {
			hdr.Size, hdr.Linkname = 0, "/bin/sh"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// release is a fake GitHub: the API and the release download host.
type release struct {
	mu      sync.Mutex
	latest  string // body of /api/releases/latest
	files   map[string][]byte
	hits    map[string]int
	srv     *httptest.Server
	tagPath string
}

func newRelease(t *testing.T, tag string, archive []byte, sums string) *release {
	t.Helper()
	r := &release{
		latest:  fmt.Sprintf(`{"tag_name":%q,"draft":false,"prerelease":false}`, tag),
		files:   map[string][]byte{},
		hits:    map[string]int{},
		tagPath: "/dl/" + tag + "/",
	}
	name := ArchiveName(tag, "amd64")
	r.files[r.tagPath+name] = archive
	r.files[r.tagPath+"SHA256SUMS"] = []byte(sums)
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hits[req.URL.Path]++
		latest := r.latest
		data, ok := r.files[req.URL.Path]
		r.mu.Unlock()
		switch {
		case req.URL.Path == "/api/releases/latest":
			_, _ = io.WriteString(w, latest)
		case req.URL.Path == "/api/releases":
			// The full list starts with a pre-release; /latest skips it.
			_, _ = io.WriteString(w, `[{"tag_name":"v9.0.0-rc.1","prerelease":true},`+latest+`]`)
		case ok:
			_, _ = w.Write(data)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *release) hit(p string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[p]
}

type fakeRun struct {
	mu       sync.Mutex
	commands []string
	dpkgOwns bool
	ghFails  bool
}

func (f *fakeRun) run(_ context.Context, c host.Command) (host.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, c.String())
	switch c.Name {
	case "dpkg-query":
		if f.dpkgOwns {
			return host.Result{Output: "tor-relay-setup: " + c.Args[1] + "\n"}, nil
		}
		return host.Result{ExitCode: 1}, &host.ExitError{Command: c.String(), ExitCode: 1}
	case "gh":
		if f.ghFails {
			return host.Result{ExitCode: 1}, &host.ExitError{Command: c.String(), ExitCode: 1, Output: "verification failed"}
		}
		return host.Result{}, nil
	}
	return host.Result{}, fmt.Errorf("unexpected command %s", c.String())
}

type fixture struct {
	u       *Updater
	rel     *release
	run     *fakeRun
	out     *bytes.Buffer
	exe     string // the real file
	link    string // symlink the "running" executable is started from
	archive string
	newBin  string
}

const oldBin = "#!/bin/sh\necho old\n"

func newFixture(t *testing.T, mutate func(archive []byte, sums *string)) *fixture {
	t.Helper()
	f := &fixture{newBin: "#!/bin/sh\necho tor-relay-setup v3.1.0\n", out: &bytes.Buffer{}, run: &fakeRun{}}
	archive := makeArchive(t,
		entry{name: "LICENSE", body: "MIT\n"},
		entry{name: "../tor-relay-setup", body: "traversal"},
		entry{name: "tor-relay-setup", body: f.newBin},
		entry{name: "README.md", body: "readme\n"},
	)
	f.archive = ArchiveName("v3.1.0", "amd64")
	// The SBOM line comes first: a prefix match on the archive name would
	// pick it.
	sums := sum([]byte("sbom")) + "  " + f.archive + ".sbom.json\n" +
		sum(archive) + "  " + f.archive + "\n" +
		sum([]byte("deb")) + "  tor-relay-setup_3.1.0_amd64.deb\n"
	if mutate != nil {
		mutate(archive, &sums)
	}
	f.rel = newRelease(t, "v3.1.0", archive, sums)

	dir := t.TempDir()
	f.exe = filepath.Join(dir, "bin", "tor-relay-setup")
	if err := os.MkdirAll(filepath.Dir(f.exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.exe, []byte(oldBin), 0o755); err != nil {
		t.Fatal(err)
	}
	f.link = filepath.Join(dir, "tor-relay-setup")
	if err := os.Symlink(f.exe, f.link); err != nil {
		t.Fatal(err)
	}

	u := New("v3.0.0", f.out, false)
	u.HTTP = f.rel.srv.Client()
	u.BaseAPI = f.rel.srv.URL + "/api"
	u.BaseDownload = f.rel.srv.URL + "/dl"
	u.GOOS, u.GOARCH = "linux", "amd64"
	u.Executable = func() (string, error) { return f.link, nil }
	u.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	u.Run = f.run.run
	f.u = u
	return f
}

func (f *fixture) binary(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.exe)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestUpdateReplacesBinaryAtomically(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.u.Update(context.Background()); err != nil {
		t.Fatalf("Update: %v\n%s", err, f.out)
	}
	if got := f.binary(t); got != f.newBin {
		t.Errorf("binary = %q, want the release binary", got)
	}
	info, err := os.Stat(f.exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, want 0755", info.Mode().Perm())
	}
	if target, err := os.Readlink(f.link); err != nil || target != f.exe {
		t.Errorf("the symlink was replaced instead of its target: %q, %v", target, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(f.exe))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
	for _, want := range []string{"Updating tor-relay-setup v3.0.0 → v3.1.0", "Verified SHA-256", "only the checksum was verified", "Updated " + f.exe + " to v3.1.0"} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, f.out)
		}
	}
	if len(f.run.commands) != 1 || f.run.commands[0] != "dpkg-query -S "+f.exe {
		t.Errorf("commands = %q, want only the dpkg ownership check", f.run.commands)
	}
}

func TestUpdateChecksumMismatch(t *testing.T) {
	f := newFixture(t, func(archive []byte, sums *string) {
		*sums = strings.Replace(*sums, sum(archive), sum([]byte("tampered")), 1)
	})
	err := f.u.Update(context.Background())
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch for "+f.archive) {
		t.Fatalf("err = %v, want a checksum mismatch", err)
	}
	if f.binary(t) != oldBin {
		t.Error("a mismatching archive was installed")
	}
}

func TestUpdateMissingChecksumLine(t *testing.T) {
	f := newFixture(t, func(archive []byte, sums *string) {
		// Only the SBOM line is left; its name starts with the archive name.
		*sums = sum(archive) + "  " + ArchiveName("v3.1.0", "amd64") + ".sbom.json\n"
	})
	err := f.u.Update(context.Background())
	if err == nil || !strings.Contains(err.Error(), "is not listed in SHA256SUMS") {
		t.Fatalf("err = %v, want the missing-line error", err)
	}
	if f.binary(t) != oldBin {
		t.Error("an unlisted archive was installed")
	}
	if f.rel.hit(f.rel.tagPath+f.archive) != 0 {
		t.Error("the archive was downloaded although it is not listed")
	}
}

func TestChecksumForSelectsExactName(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("B", 64)
	sums := []byte(a + "  x.tar.gz.sbom.json\n" + b + " *x.tar.gz\nnot a line\n")
	got, err := ChecksumFor(sums, "x.tar.gz")
	if err != nil || got != strings.ToLower(b) {
		t.Errorf("ChecksumFor = %q, %v; want the exact-name line", got, err)
	}
	if _, err := ChecksumFor([]byte("abc  x.tar.gz\n"), "x.tar.gz"); err == nil {
		t.Error("a malformed checksum was accepted")
	}
	if _, err := ChecksumFor(sums, "x.tar"); err == nil {
		t.Error("a prefix of a listed name matched")
	}
}

func TestUpdateRefusesDebianPackage(t *testing.T) {
	f := newFixture(t, nil)
	f.run.dpkgOwns = true
	err := f.u.Update(context.Background())
	var pe *PackagedError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a PackagedError", err)
	}
	want := "installed from the .deb package — update with: sudo apt install ./tor-relay-setup_3.1.0_amd64.deb (or apt upgrade when using the apt repository)"
	if err.Error() != want {
		t.Errorf("message = %q\nwant      %q", err, want)
	}
	if f.binary(t) != oldBin || f.rel.hit(f.rel.tagPath+f.archive) != 0 {
		t.Error("a package-owned binary was downloaded or replaced")
	}
}

func TestUpdateUpToDate(t *testing.T) {
	for _, current := range []string{"v3.1.0", "v3.2.0"} {
		f := newFixture(t, nil)
		f.u.Current = current
		if err := f.u.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(f.out.String(), "is up to date") || f.binary(t) != oldBin {
			t.Errorf("%s: output %q", current, f.out)
		}
		if f.rel.hit(f.rel.tagPath+"SHA256SUMS") != 0 || len(f.run.commands) != 0 {
			t.Errorf("%s: an up-to-date binary started an update", current)
		}
	}
}

func TestUpdateFromDevBuild(t *testing.T) {
	f := newFixture(t, nil)
	f.u.Current = "dev"
	if err := f.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), `"dev" is not a release`) || f.binary(t) != f.newBin {
		t.Errorf("output %q", f.out)
	}
}

func TestUpdateDryRunVerifiesWithoutReplacing(t *testing.T) {
	f := newFixture(t, nil)
	f.u.DryRun = true
	if err := f.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.binary(t) != oldBin {
		t.Error("a dry run replaced the binary")
	}
	if f.rel.hit(f.rel.tagPath+f.archive) != 1 || !strings.Contains(f.out.String(), "Dry run: would replace "+f.exe) {
		t.Errorf("dry run should download and verify:\n%s", f.out)
	}
}

func TestUpdateAttestation(t *testing.T) {
	f := newFixture(t, nil)
	f.u.LookPath = func(string) (string, error) { return "/usr/bin/gh", nil }
	f.run.ghFails = true
	if err := f.u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "attestation verification failed") {
		t.Fatalf("err = %v, want the attestation failure", err)
	}
	if f.binary(t) != oldBin {
		t.Error("installed despite a failed attestation")
	}

	f.run.ghFails = false
	f.run.commands = nil
	if err := f.u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.run.commands) != 2 || !strings.HasPrefix(f.run.commands[1], "gh attestation verify ") || !strings.HasSuffix(f.run.commands[1], f.archive+" --repo ljkx/tor-relay-setup") {
		t.Errorf("commands = %q", f.run.commands)
	}
	if f.binary(t) != f.newBin {
		t.Error("not installed after a good attestation")
	}
}

func TestUpdateUnsupportedPlatform(t *testing.T) {
	f := newFixture(t, nil)
	f.u.GOARCH = "riscv64"
	if err := f.u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "riscv64") {
		t.Errorf("err = %v", err)
	}
}

func TestLatest(t *testing.T) {
	f := newFixture(t, nil)
	tag, err := f.u.Latest(context.Background())
	if err != nil || tag != "v3.1.0" {
		t.Fatalf("Latest = %q, %v; want the /releases/latest tag, not the pre-release", tag, err)
	}
	if f.rel.hit("/api/releases") != 0 {
		t.Error("Latest listed all releases (which include pre-releases)")
	}
	tag, err = Latest(context.Background(), &http.Client{Transport: rewrite{f.rel.srv.URL}})
	if err != nil || tag != "v3.1.0" {
		t.Errorf("package Latest = %q, %v", tag, err)
	}

	for _, body := range []string{
		`{"tag_name":"v3.2.0","prerelease":true}`,
		`{"tag_name":"v3.2.0-rc.1"}`,
		`{"tag_name":"v3.2.0","draft":true}`,
		`{"tag_name":"$(reboot)"}`,
		`not json`,
	} {
		f.rel.mu.Lock()
		f.rel.latest = body
		f.rel.mu.Unlock()
		if tag, err := f.u.Latest(context.Background()); err == nil {
			t.Errorf("%s: accepted %q", body, tag)
		}
	}
}

// rewrite sends api.github.com requests to the test server.
type rewrite struct{ base string }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme, u.Host = "http", strings.TrimPrefix(r.base, "http://")
	u.Path = strings.Replace(u.Path, "/repos/"+Repository, "/api", 1)
	out := req.Clone(req.Context())
	out.URL = &u
	return http.DefaultTransport.RoundTrip(out)
}

func TestCheck(t *testing.T) {
	f := newFixture(t, nil)
	tests := []struct {
		current          string
		known, available bool
	}{
		{"v3.0.0", true, true},
		{"v3.1.0-rc.2", true, true},
		{"v3.1.0", true, false},
		{"v3.1.1", true, false},
		{"dev", false, true},
		{"(devel)", false, true},
	}
	for _, tt := range tests {
		f.u.Current = tt.current
		res, err := f.u.Check(context.Background())
		if err != nil || res.Latest != "v3.1.0" || res.Known != tt.known || res.Available != tt.available {
			t.Errorf("%s: %+v, %v", tt.current, res, err)
		}
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v1.2.3", "v1.2.3", 0, true},
		{"1.2.3", "v1.2.4", -1, true},
		{"v1.10.0", "v1.9.9", 1, true},
		{"v2.0.0-rc.1", "v2.0.0", -1, true},
		{"v2.0.0-rc.2", "v2.0.0-rc.10", -1, true},
		{"v2.0.0-alpha", "v2.0.0-1", 1, true},
		{"v2.0.0-rc", "v2.0.0-rc.1", -1, true},
		{"v3.0.1-0.20260101000000-abcdef123456", "v3.0.1", -1, true},
		{"v3.0.0+dirty", "v3.0.0", 0, true},
		{"dev", "v1.0.0", 0, false},
		{"v1.0", "v1.0.0", 0, false},
		{"v01.0.0", "v1.0.0", 0, false},
	}
	for _, tt := range tests {
		got, ok := Compare(tt.a, tt.b)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d, %v", tt.a, tt.b, got, ok, tt.want, tt.ok)
		}
	}
	if !UpdateAvailable("dev", "v1.0.0") || UpdateAvailable("v1.0.0", "v1.0.0") || UpdateAvailable("dev", "") {
		t.Error("UpdateAvailable")
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name    string
		entries []entry
		want    string
	}{
		{"traversal only", []entry{{name: "../tor-relay-setup", body: "x"}, {name: "/abs/tor-relay-setup", body: "x"}}, "has no tor-relay-setup"},
		{"symlink", []entry{{name: "tor-relay-setup", typeflag: tar.TypeSymlink}}, "not a regular file"},
		{"nested", []entry{{name: "dir/tor-relay-setup", body: "x"}}, "has no tor-relay-setup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extract(bytes.NewReader(makeArchive(t, tt.entries...)), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
	var out bytes.Buffer
	if n, err := extract(bytes.NewReader(makeArchive(t, entry{name: "./tor-relay-setup", body: "ok"})), &out); err != nil || n != 2 || out.String() != "ok" {
		t.Errorf("./tor-relay-setup: %d, %v, %q", n, err, out.String())
	}
	if _, err := extract(strings.NewReader("not gzip"), io.Discard); err == nil {
		t.Error("garbage accepted")
	}
}

func TestCheckCached(t *testing.T) {
	f := newFixture(t, nil)
	dir := filepath.Join(t.TempDir(), "state")
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	f.u.Now = func() time.Time { return now }

	latest, err := f.u.CheckCached(context.Background(), dir, time.Hour)
	if err != nil || latest != "v3.1.0" || f.rel.hit("/api/releases/latest") != 1 {
		t.Fatalf("first check: %q, %v, hits %d", latest, err, f.rel.hit("/api/releases/latest"))
	}
	p := filepath.Join(dir, CacheFile)
	info, err := os.Stat(p)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file: %v, %v", info, err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), `"checked_at":"2026-10-01T12:00:00Z"`) || !strings.Contains(string(data), `"latest":"v3.1.0"`) {
		t.Errorf("cache = %s", data)
	}

	// Fresh: no API call.
	now = now.Add(30 * time.Minute)
	if latest, err := f.u.CheckCached(context.Background(), dir, time.Hour); err != nil || latest != "v3.1.0" || f.rel.hit("/api/releases/latest") != 1 {
		t.Errorf("fresh cache: %q, %v, hits %d", latest, err, f.rel.hit("/api/releases/latest"))
	}

	// Stale and the API fails: the stale value comes back with the error.
	now = now.Add(2 * time.Hour)
	f.rel.mu.Lock()
	f.rel.latest = "broken"
	f.rel.mu.Unlock()
	if latest, err := f.u.CheckCached(context.Background(), dir, time.Hour); err == nil || latest != "v3.1.0" {
		t.Errorf("stale cache with a failing API: %q, %v", latest, err)
	}

	// Stale and the API answers: the cache is refreshed.
	f.rel.mu.Lock()
	f.rel.latest = `{"tag_name":"v3.2.0"}`
	f.rel.mu.Unlock()
	if latest, err := f.u.CheckCached(context.Background(), dir, time.Hour); err != nil || latest != "v3.2.0" {
		t.Errorf("refresh: %q, %v", latest, err)
	}
	data, _ = os.ReadFile(p)
	if !strings.Contains(string(data), "v3.2.0") {
		t.Errorf("cache not refreshed: %s", data)
	}

	// A corrupt cache is ignored; an unwritable state dir only costs a call.
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if latest, err := f.u.CheckCached(context.Background(), dir, time.Hour); err != nil || latest != "v3.2.0" {
		t.Errorf("corrupt cache: %q, %v", latest, err)
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if latest, err := f.u.CheckCached(context.Background(), filepath.Join(blocker, "state"), time.Hour); err != nil || latest != "v3.2.0" {
		t.Errorf("unwritable state dir: %q, %v", latest, err)
	}
}
