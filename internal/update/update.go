// Package update replaces the running tor-relay-setup binary with the newest
// GitHub release, verified the same way install.sh verifies it: the archive's
// SHA-256 from SHA256SUMS (exact file-name match), and the build-provenance
// attestation when the GitHub CLI is installed.
//
// It also answers "is there a newer release?" cheaply for the TUI header:
// CheckCached remembers the answer in the state directory.
package update

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Repository is the GitHub repository releases come from.
const Repository = "ljkx/tor-relay-setup"

const (
	// DefaultAPI is the GitHub REST endpoint of the repository.
	DefaultAPI = "https://api.github.com/repos/" + Repository
	// DefaultDownload is the base URL of release assets; the tag follows.
	DefaultDownload = "https://github.com/" + Repository + "/releases/download"

	binaryName = "tor-relay-setup"

	apiTimeout      = 15 * time.Second
	downloadTimeout = 5 * time.Minute
	maxAPIBody      = 1 << 20   // 1 MiB of release JSON
	maxSumsBody     = 1 << 20   // 1 MiB of SHA256SUMS
	maxArchive      = 128 << 20 // 128 MiB archive
	maxBinary       = 64 << 20  // 64 MiB binary inside it
)

// stableTag is a release tag the /releases/latest endpoint may return.
var stableTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// defaultHTTP has no overall timeout: every request carries a context
// deadline instead (15 s for the API, longer for downloads).
var defaultHTTP = &http.Client{}

// Updater checks for and installs new releases. The zero value is not
// usable; start from New and override fields in tests.
type Updater struct {
	HTTP         *http.Client
	BaseAPI      string // DefaultAPI
	BaseDownload string // DefaultDownload
	Current      string // running version, e.g. "v3.0.0" or "dev"
	GOOS, GOARCH string

	// Executable returns the path of the running binary (os.Executable).
	Executable func() (string, error)
	// LookPath finds optional helpers (gh).
	LookPath func(name string) (string, error)
	// Run runs dpkg-query and gh.
	Run func(ctx context.Context, c host.Command) (host.Result, error)
	// Now is the clock for CheckCached.
	Now func() time.Time

	Out    io.Writer
	DryRun bool // download and verify, but never replace the binary
	// Replaced is set once Update has installed a new binary.
	Replaced bool
}

// New returns an Updater for the public repository that runs helpers on
// this machine.
func New(current string, out io.Writer, dryRun bool) *Updater {
	local := host.NewLocal()
	return &Updater{
		HTTP:         defaultHTTP,
		BaseAPI:      DefaultAPI,
		BaseDownload: DefaultDownload,
		Current:      current,
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		Executable:   os.Executable,
		LookPath:     local.LookPath,
		Run:          local.Run,
		Now:          time.Now,
		Out:          out,
		DryRun:       dryRun,
	}
}

// Latest returns the tag of the newest published, non-prerelease release
// of tor-relay-setup. A nil client uses a default one; the request times
// out after 15 seconds.
func Latest(ctx context.Context, client *http.Client) (string, error) {
	u := New("", io.Discard, false)
	if client != nil {
		u.HTTP = client
	}
	return u.Latest(ctx)
}

// Latest returns the newest non-prerelease tag from BaseAPI. GitHub's
// /releases/latest endpoint already skips drafts and pre-releases; a
// response that is marked as either, or whose tag has a pre-release suffix,
// is rejected anyway.
func (u *Updater) Latest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	body, err := u.get(ctx, strings.TrimRight(u.BaseAPI, "/")+"/releases/latest", maxAPIBody, "application/vnd.github+json")
	if err != nil {
		return "", fmt.Errorf("look up the latest release: %w", err)
	}
	var rel struct {
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", fmt.Errorf("look up the latest release: %w", err)
	}
	if rel.Draft || rel.Prerelease {
		return "", fmt.Errorf("the latest release %q is a draft or pre-release; refusing it", rel.TagName)
	}
	if !stableTag.MatchString(rel.TagName) {
		return "", fmt.Errorf("unexpected release tag %q", rel.TagName)
	}
	return rel.TagName, nil
}

// CheckResult compares the running version with the latest release.
type CheckResult struct {
	Current string
	Latest  string
	// Known is false when Current is not a release version ("dev", a
	// source build): Available is then true, but only "maybe".
	Known     bool
	Available bool
}

// Check looks up the latest release and compares it with Current.
func (u *Updater) Check(ctx context.Context) (CheckResult, error) {
	latest, err := u.Latest(ctx)
	if err != nil {
		return CheckResult{Current: u.Current}, err
	}
	res := CheckResult{Current: u.Current, Latest: latest}
	cmp, ok := Compare(u.Current, latest)
	res.Known = ok
	res.Available = !ok || cmp < 0
	return res, nil
}

// UpdateAvailable reports whether latest is newer than current. An
// unparsable current version ("dev") counts as outdated.
func UpdateAvailable(current, latest string) bool {
	cmp, ok := Compare(current, latest)
	if _, latestOK := parseSemver(latest); !latestOK {
		return false
	}
	return !ok || cmp < 0
}

// OwnedByPackage reports whether dpkg lists path as part of an installed
// package. Missing dpkg-query means no.
func OwnedByPackage(ctx context.Context, run func(context.Context, host.Command) (host.Result, error), path string) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := run(ctx, host.Command{Name: "dpkg-query", Args: []string{"-S", path}})
	return err == nil
}

// PackagedError is returned when the binary belongs to the Debian package.
type PackagedError struct {
	Version, Arch string
}

func (e *PackagedError) Error() string {
	return fmt.Sprintf("installed from the .deb package — update with: sudo apt install ./tor-relay-setup_%s_%s.deb (or apt upgrade when using the apt repository)", e.Version, e.Arch)
}

// Update installs the latest release over the running binary, unless it
// is already current. With DryRun it downloads and verifies, then stops.
func (u *Updater) Update(ctx context.Context) error {
	if u.GOOS != "linux" || (u.GOARCH != "amd64" && u.GOARCH != "arm64") {
		return fmt.Errorf("releases are built for linux/amd64 and linux/arm64, not %s/%s", u.GOOS, u.GOARCH)
	}
	res, err := u.Check(ctx)
	if err != nil {
		return err
	}
	switch {
	case !res.Available:
		fmt.Fprintf(u.Out, "tor-relay-setup %s is up to date.\n", res.Current)
		return nil
	case !res.Known:
		fmt.Fprintf(u.Out, "Running version %q is not a release; installing the latest release %s.\n", res.Current, res.Latest)
	default:
		fmt.Fprintf(u.Out, "Updating tor-relay-setup %s → %s\n", res.Current, res.Latest)
	}

	exe, err := u.target()
	if err != nil {
		return err
	}
	if err := u.checkNotPackaged(ctx, exe, res.Latest); err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	if err := writable(dir); err != nil {
		if !u.DryRun {
			return fmt.Errorf("cannot write to %s (%w); run: sudo tor-relay-setup self-update", dir, err)
		}
		fmt.Fprintf(u.Out, "Note: %s is not writable for this user; a real update needs sudo.\n", dir)
	}

	work, err := os.MkdirTemp("", "tor-relay-setup-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	archive := ArchiveName(res.Latest, u.GOARCH)
	archivePath, err := u.download(ctx, res.Latest, archive, work)
	if err != nil {
		return err
	}
	if err := u.attest(ctx, archivePath); err != nil {
		return err
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	if u.DryRun {
		n, err := extract(f, io.Discard)
		if err != nil {
			return err
		}
		fmt.Fprintf(u.Out, "Dry run: would replace %s with the verified %s binary (%d bytes). Nothing was changed.\n", exe, res.Latest, n)
		return nil
	}
	if err := replace(exe, f); err != nil {
		return err
	}
	u.Replaced = true
	fmt.Fprintf(u.Out, "Updated %s to %s.\n", exe, res.Latest)
	return nil
}

// ArchiveName is the release archive for a tag and CPU architecture.
func ArchiveName(tag, arch string) string {
	return fmt.Sprintf("%s_%s_linux_%s.tar.gz", binaryName, strings.TrimPrefix(tag, "v"), arch)
}

// target resolves the running executable through symlinks.
func (u *Updater) target() (string, error) {
	exe, err := u.Executable()
	if err != nil {
		return "", fmt.Errorf("find the running executable: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", exe, err)
	}
	return resolved, nil
}

func (u *Updater) checkNotPackaged(ctx context.Context, exe, tag string) error {
	if OwnedByPackage(ctx, u.Run, exe) {
		return &PackagedError{Version: strings.TrimPrefix(tag, "v"), Arch: u.GOARCH}
	}
	return nil
}

// download fetches SHA256SUMS and the archive into dir and verifies the
// archive's checksum. It returns the archive path.
func (u *Updater) download(ctx context.Context, tag, archive, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	base := strings.TrimRight(u.BaseDownload, "/") + "/" + tag + "/"

	sums, err := u.get(ctx, base+"SHA256SUMS", maxSumsBody, "")
	if err != nil {
		return "", fmt.Errorf("download SHA256SUMS: %w", err)
	}
	want, err := ChecksumFor(sums, archive)
	if err != nil {
		return "", err
	}

	fmt.Fprintf(u.Out, "Downloading %s\n", archive)
	resp, err := u.request(ctx, base+archive, "")
	if err != nil {
		return "", fmt.Errorf("download %s: %w", archive, err)
	}
	defer resp.Body.Close()
	p := filepath.Join(dir, archive)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArchive+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("download %s: %w", archive, err)
	}
	if n > maxArchive {
		return "", fmt.Errorf("%s is larger than %d MiB; refusing it", archive, maxArchive>>20)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("checksum mismatch for %s (got %s, SHA256SUMS lists %s); do not install it", archive, got, want)
	}
	fmt.Fprintln(u.Out, "Verified SHA-256 against SHA256SUMS.")
	return p, nil
}

// ChecksumFor returns the lower-case SHA-256 that SHA256SUMS lists for
// name. The line is selected by exact file name (field 2, optionally with
// sha256sum's binary-mode '*'), never by prefix: "<name>.sbom.json" is a
// different file.
func ChecksumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 || (fields[1] != name && fields[1] != "*"+name) {
			continue
		}
		sum := strings.ToLower(fields[0])
		if len(sum) != sha256.Size*2 {
			return "", fmt.Errorf("SHA256SUMS has a malformed line for %s", name)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return "", fmt.Errorf("SHA256SUMS has a malformed line for %s", name)
		}
		return sum, nil
	}
	return "", fmt.Errorf("%s is not listed in SHA256SUMS", name)
}

// attest runs `gh attestation verify` when gh is installed.
func (u *Updater) attest(ctx context.Context, archive string) error {
	if _, err := u.LookPath("gh"); err != nil {
		fmt.Fprintln(u.Out, "GitHub CLI not found; skipping the attestation check (only the checksum was verified).")
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	_, err := u.Run(ctx, host.Command{Name: "gh", Args: []string{"attestation", "verify", archive, "--repo", Repository}})
	if err != nil {
		return fmt.Errorf("attestation verification failed for %s (gh must be logged in): %w", filepath.Base(archive), err)
	}
	fmt.Fprintln(u.Out, "Verified build provenance with gh attestation verify.")
	return nil
}

// extract copies the tor-relay-setup regular file from a tar.gz to w. Only
// that one entry is read; nothing is written to disk by name.
func extract(r io.Reader, w io.Writer) (int64, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, fmt.Errorf("read archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("the archive has no %s binary", binaryName)
		}
		if err != nil {
			return 0, fmt.Errorf("read archive: %w", err)
		}
		if path.Clean(strings.TrimPrefix(hdr.Name, "./")) != binaryName {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return 0, fmt.Errorf("%s in the archive is not a regular file", binaryName)
		}
		if hdr.Size > maxBinary {
			return 0, fmt.Errorf("%s in the archive is larger than %d MiB", binaryName, maxBinary>>20)
		}
		n, err := io.Copy(w, io.LimitReader(tr, maxBinary+1))
		if err != nil {
			return n, fmt.Errorf("extract %s: %w", binaryName, err)
		}
		if n > maxBinary || n != hdr.Size {
			return n, fmt.Errorf("%s in the archive has an unexpected size", binaryName)
		}
		return n, nil
	}
}

// replace atomically swaps exe for the binary extracted from archive: a
// temporary file in the same directory, mode 0755, fsync, rename.
func replace(exe string, archive io.Reader) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(exe)+".new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // fails harmlessly after the rename
	if err := writeBinary(tmp, archive); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func writeBinary(f *os.File, archive io.Reader) error {
	if _, err := extract(archive, f); err != nil {
		return err
	}
	if err := f.Chmod(0o755); err != nil {
		return err
	}
	return f.Sync()
}

// writable reports whether a file can be created in dir.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".tor-relay-setup.check-*")
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return fs.ErrPermission
		}
		return err
	}
	_ = f.Close()
	return os.Remove(f.Name())
}

func (u *Updater) request(ctx context.Context, url, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tor-relay-setup/"+u.Current)
	if accept != "" {
		req.Header.Set("Accept", accept)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	client := u.HTTP
	if client == nil {
		client = defaultHTTP
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	return resp, nil
}

func (u *Updater) get(ctx context.Context, url string, limit int64, accept string) ([]byte, error) {
	resp, err := u.request(ctx, url, accept)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s: response larger than %d bytes", url, limit)
	}
	return body, nil
}
