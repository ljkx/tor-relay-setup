// Package remote applies one relay.toml to several relays over SSH with the
// system OpenSSH client, so ~/.ssh/config, agents and known_hosts apply as
// usual. For every host it uploads the running binary and the config to a
// private temporary directory, runs `tor-relay-setup apply` there with
// sudo, and removes the directory again.
//
// A config that generates a family key is applied to the first host as is;
// the key it created is then fetched back and imported on every further
// host, so the whole fleet ends up in one family.
package remote

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
)

const (
	binaryName = "tor-relay-setup"
	configName = "relay.toml"
	// keyDir is where apply installs family keys (plan.familyStep).
	keyDir = "/var/lib/tor/keys"

	secretSuffix = ".secret_family_key"
	publicSuffix = ".public_family_id"
)

// sshOptions go to every ssh and scp call. Host key checking is left to
// the user's configuration and is never disabled.
var sshOptions = []string{"-o", "ConnectTimeout=10"}

// Outcome is the result of one host.
type Outcome string

// Outcomes in the summary.
const (
	OK      Outcome = "ok"
	Failed  Outcome = "failed"
	Skipped Outcome = "skipped"
)

// HostResult is one row of the summary.
type HostResult struct {
	Host    string
	Outcome Outcome
	Err     error
}

// Options describes one fleet run.
type Options struct {
	ConfigPath string
	Hosts      []string
	DryRun     bool // run apply --dry-run on every host
	KeepGoing  bool // continue with the next host after a failure
}

// Fleet runs ssh and scp through Host. Host should be a real host even for
// a dry run: the remote tor-relay-setup performs the dry run itself.
type Fleet struct {
	Host       host.Host
	Out        io.Writer
	Executable func() (string, error)
	GOOS       string
	GOARCH     string
}

// New returns a Fleet that runs the system ssh and scp.
func New(out io.Writer) *Fleet {
	return &Fleet{Host: host.NewLocal(), Out: out, Executable: os.Executable, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

var (
	hostPattern = regexp.MustCompile(`^(?:[A-Za-z0-9_][A-Za-z0-9._-]*@)?(?:[A-Za-z0-9_][A-Za-z0-9._-]*|\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*)$`)
	tmpPattern  = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

// ValidHost accepts plausible ssh destinations: [user@]host, where host is
// a name, an ssh_config alias, or an IP address (IPv6 optionally in
// brackets). Whitespace, a leading '-', URIs and shell syntax are rejected.
func ValidHost(s string) error {
	if s == "" || len(s) > 255 || strings.HasPrefix(s, "-") || !hostPattern.MatchString(s) {
		return fmt.Errorf("%q is not an ssh destination; use [user@]host (ports and options belong in ~/.ssh/config)", s)
	}
	return nil
}

// sshDest is the destination as ssh takes it (IPv6 without brackets).
func sshDest(dest string) string {
	user, h := splitUser(dest)
	return user + strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
}

// scpTarget is an scp remote path; IPv6 addresses need brackets.
func scpTarget(dest, p string) string {
	user, h := splitUser(dest)
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		h = "[" + h + "]"
	}
	return user + h + ":" + p
}

func splitUser(dest string) (user, h string) {
	if i := strings.LastIndex(dest, "@"); i >= 0 {
		return dest[:i+1], dest[i+1:]
	}
	return "", dest
}

// ShellQuote quotes s for a POSIX shell.
func ShellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=@%+,") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// goarch maps `uname -m` to a Go architecture.
func goarch(machine string) string {
	switch machine {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	}
	return ""
}

// fleetRun is the state of one Apply.
type fleetRun struct {
	f    *Fleet
	opt  Options
	s    config.Setup
	raw  []byte
	exe  string
	work string

	// share: a generated family key is copied from the first host.
	share bool
	// key, keyFile and id hold the family key to import: from the first
	// host when share is set, or the local import_key.
	key     []byte
	keyFile string // NAME.secret_family_key
	id      string
}

// Apply runs the fleet and prints a summary. It returns an error when any
// host failed or was skipped.
func (f *Fleet) Apply(ctx context.Context, opt Options) ([]HostResult, error) {
	r, err := f.prepare(opt)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(r.work)

	results := make([]HostResult, len(opt.Hosts))
	var stop error
	for i, dest := range opt.Hosts {
		results[i] = HostResult{Host: dest, Outcome: Skipped}
		if stop == nil && ctx.Err() != nil {
			stop = ctx.Err()
		}
		if stop != nil {
			results[i].Err = stop
			continue
		}
		fmt.Fprintf(f.Out, "\n==> [%d/%d] %s\n", i+1, len(opt.Hosts), dest)
		if err := r.applyHost(ctx, i, dest); err != nil {
			results[i] = HostResult{Host: dest, Outcome: Failed, Err: err}
			fmt.Fprintf(f.Out, "[%s] FAILED: %v\n", dest, err)
			switch {
			case r.share && i == 0:
				stop = fmt.Errorf("the family key could not be shared from %s", dest)
			case !opt.KeepGoing:
				stop = errors.New("stopped after an earlier failure (--keep-going continues)")
			}
			continue
		}
		results[i].Outcome = OK
	}
	f.summary(results)

	var failed, skipped int
	for _, res := range results {
		switch res.Outcome {
		case Failed:
			failed++
		case Skipped:
			skipped++
		}
	}
	if failed+skipped > 0 {
		return results, fmt.Errorf("%d of %d relays failed, %d skipped", failed, len(results), skipped)
	}
	return results, nil
}

func (f *Fleet) prepare(opt Options) (*fleetRun, error) {
	if len(opt.Hosts) == 0 {
		return nil, errors.New("no hosts given")
	}
	seen := map[string]bool{}
	for _, h := range opt.Hosts {
		if err := ValidHost(h); err != nil {
			return nil, err
		}
		if seen[h] {
			return nil, fmt.Errorf("host %s is listed twice", h)
		}
		seen[h] = true
	}
	if opt.ConfigPath == "" {
		return nil, errors.New("apply --host needs --config FILE")
	}
	if f.GOOS != "linux" {
		return nil, fmt.Errorf("this tor-relay-setup binary is built for %s; run apply --host from a Linux machine", f.GOOS)
	}
	raw, err := os.ReadFile(opt.ConfigPath)
	if err != nil {
		return nil, err
	}
	s, err := config.Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	exe, err := f.Executable()
	if err != nil {
		return nil, fmt.Errorf("find the running executable: %w", err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return nil, err
	}

	r := &fleetRun{f: f, opt: opt, s: s, raw: raw, exe: exe}
	switch s.Family.Mode {
	case "generate":
		r.share = len(opt.Hosts) > 1
		r.keyFile = s.Family.KeyName + secretSuffix
	case "import":
		if err := r.loadLocalKey(); err != nil {
			return nil, err
		}
	}
	// The work directory holds staged uploads and the family key: 0700.
	if r.work, err = os.MkdirTemp("", "tor-relay-setup-fleet-"); err != nil {
		return nil, err
	}
	return r, nil
}

// loadLocalKey reads family.import_key and its FamilyId on this machine.
func (r *fleetRun) loadLocalKey() error {
	p := r.s.Family.ImportKey
	key, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if !family.ValidKey(key) {
		return fmt.Errorf("%s is not a Tor family key", p)
	}
	id := r.s.Family.FamilyID
	if pub, err := os.ReadFile(strings.TrimSuffix(p, secretSuffix) + publicSuffix); err == nil {
		id = strings.TrimSpace(string(pub))
	}
	if !family.ValidID(id) {
		return errors.New("no FamilyId: copy NAME.public_family_id next to the key, or set family.family_id")
	}
	r.key, r.keyFile, r.id = key, filepath.Base(p), id
	return nil
}

// probe is what the first ssh call learns about a host.
type probe struct {
	arch string // uname -m
	root bool
	sudo bool // passwordless sudo works
	tmp  string
}

const probeScript = `printf 'TRS-ARCH %s\n' "$(uname -m)"
u=$(id -u)
printf 'TRS-UID %s\n' "$u"
if [ "$u" != 0 ]; then
  if sudo -n true >/dev/null 2>&1; then echo 'TRS-SUDO yes'; else echo 'TRS-SUDO no'; fi
fi
d=$(mktemp -d "${TMPDIR:-/tmp}/tor-relay-setup.XXXXXXXX") || exit 1
printf 'TRS-TMP %s\n' "$d"`

func (r *fleetRun) ssh(dest, script string, mutates bool) host.Command {
	args := append(append([]string{}, sshOptions...), "--", sshDest(dest), "sh -c "+ShellQuote(script))
	return host.Command{Name: "ssh", Args: args, Mutates: mutates}
}

func (r *fleetRun) printer(dest string) func(string) {
	return func(line string) { fmt.Fprintf(r.f.Out, "[%s] %s\n", dest, strings.TrimRight(line, "\r")) }
}

func (r *fleetRun) probe(ctx context.Context, dest string) (probe, error) {
	var p probe
	show := r.printer(dest)
	res, err := r.f.Host.Run(ctx, r.ssh(dest, probeScript, false))
	for _, line := range strings.Split(res.Output, "\n") {
		line = strings.TrimRight(line, "\r")
		key, value, _ := strings.Cut(line, " ")
		switch key {
		case "TRS-ARCH":
			p.arch = value
		case "TRS-UID":
			p.root = value == "0"
		case "TRS-SUDO":
			p.sudo = value == "yes"
		case "TRS-TMP":
			p.tmp = value
		default:
			if line != "" {
				show(line)
			}
		}
	}
	if err != nil {
		return p, commandError("ssh", err)
	}
	if p.arch == "" || !tmpPattern.MatchString(p.tmp) || strings.Contains(p.tmp, "..") {
		return p, errors.New("unexpected answer from the host (is it a Linux system with a POSIX shell?)")
	}
	return p, nil
}

// applyHost runs the whole sequence for one host.
func (r *fleetRun) applyHost(ctx context.Context, i int, dest string) error {
	p, err := r.probe(ctx, dest)
	if err != nil {
		return err
	}
	removeTmp := true
	defer func() {
		if removeTmp {
			r.cleanup(ctx, dest, p.tmp)
		}
	}()
	if arch := goarch(p.arch); arch != r.f.GOARCH {
		return fmt.Errorf("the host's CPU is %s but this binary is built for linux/%s; install tor-relay-setup there with install.sh and run apply on the host itself", p.arch, r.f.GOARCH)
	}
	sudo, err := r.sudo(dest, p)
	if err != nil {
		return err
	}

	cfg, files, err := r.payload(i, dest, p.tmp)
	if err != nil {
		return err
	}
	if err := r.upload(ctx, i, dest, p.tmp, cfg, files); err != nil {
		return err
	}

	// The remote script removes its directory itself on exit.
	if _, err := r.f.Host.Stream(ctx, r.ssh(dest, applyScript(p.tmp, sudo, r.opt.DryRun), !r.opt.DryRun), r.printer(dest)); err != nil {
		return commandError("remote apply", err)
	}
	removeTmp = false

	if r.share && i == 0 {
		if r.opt.DryRun {
			fmt.Fprintf(r.f.Out, "[%s] dry run: would fetch the new family key %s and import it on the other %d relays (family.mode = \"import\")\n", dest, r.keyFile, len(r.opt.Hosts)-1)
			return nil
		}
		if err := r.fetchKey(ctx, dest, sudo); err != nil {
			return fmt.Errorf("applied, but fetching the family key failed: %w", err)
		}
		fmt.Fprintf(r.f.Out, "[%s] fetched FamilyId %s; the other relays join this family\n", dest, r.id)
	}
	return nil
}

// sudo returns the prefix for privileged remote commands. ssh runs without
// a terminal, so sudo must not need a password.
func (r *fleetRun) sudo(dest string, p probe) (string, error) {
	switch {
	case p.root:
		return "", nil
	case p.sudo:
		return "sudo -n ", nil
	case r.opt.DryRun:
		fmt.Fprintf(r.f.Out, "[%s] note: no passwordless sudo; the dry run runs unprivileged\n", dest)
		return "", nil
	}
	return "", errors.New("the remote user is not root and sudo asks for a password; ssh in as root, or allow this user passwordless sudo (commands run without a terminal)")
}

// payload returns the config to upload and any extra files (name → data).
func (r *fleetRun) payload(i int, dest, tmp string) ([]byte, map[string][]byte, error) {
	switch {
	case r.share && i > 0 && r.opt.DryRun:
		fmt.Fprintf(r.f.Out, "[%s] dry run: the real run imports the family key from %s; this dry run uses the config as is\n", dest, r.opt.Hosts[0])
		return r.raw, nil, nil
	case r.share && i > 0, r.s.Family.Mode == "import":
		d := r.s
		d.Family.Mode = "import"
		d.Family.ImportKey = path.Join(tmp, r.keyFile)
		d.Family.FamilyID = r.id
		cfg, err := d.Marshal()
		if err != nil {
			return nil, nil, err
		}
		files := map[string][]byte{
			r.keyFile: r.key,
			strings.TrimSuffix(r.keyFile, secretSuffix) + publicSuffix: []byte(r.id + "\n"),
		}
		return cfg, files, nil
	}
	return r.raw, nil, nil
}

// upload stages the binary, config and files locally and copies them into
// the remote directory with one scp call.
func (r *fleetRun) upload(ctx context.Context, i int, dest, tmp string, cfg []byte, files map[string][]byte) error {
	stage := filepath.Join(r.work, fmt.Sprintf("host-%d", i+1))
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	srcs := []string{filepath.Join(stage, binaryName), filepath.Join(stage, configName)}
	if err := os.Symlink(r.exe, srcs[0]); err != nil {
		return err
	}
	if err := os.WriteFile(srcs[1], cfg, 0o600); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := filepath.Join(stage, name)
		if err := os.WriteFile(p, files[name], 0o600); err != nil {
			return err
		}
		srcs = append(srcs, p)
	}
	args := append([]string{"-q"}, sshOptions...)
	args = append(append(append(args, "--"), srcs...), scpTarget(dest, tmp+"/"))
	if _, err := r.f.Host.Stream(ctx, host.Command{Name: "scp", Args: args, Mutates: !r.opt.DryRun}, r.printer(dest)); err != nil {
		return commandError("upload with scp", err)
	}
	return nil
}

func applyScript(tmp, sudo string, dryRun bool) string {
	cmd := sudo + `"$tmp/` + binaryName + `" apply --config "$tmp/` + configName + `" --yes --plain`
	if dryRun {
		cmd += " --dry-run"
	}
	return "tmp=" + ShellQuote(tmp) + `
trap 'rm -rf -- "$tmp"' EXIT
trap 'exit 130' HUP INT TERM
chmod 0700 "$tmp/` + binaryName + `"
` + cmd
}

// fetchKey copies the generated family key and FamilyId from dest. The
// output carries the secret key, so it is never printed.
func (r *fleetRun) fetchKey(ctx context.Context, dest, sudo string) error {
	name := strings.TrimSuffix(r.keyFile, secretSuffix)
	script := "k=" + ShellQuote(path.Join(keyDir, r.keyFile)) + `
i=` + ShellQuote(path.Join(keyDir, name+publicSuffix)) + `
echo TRS-KEY-BEGIN
` + sudo + `base64 -- "$k"
echo TRS-KEY-END
printf 'TRS-ID %s\n' "$(` + sudo + `cat -- "$i")"`
	res, err := r.f.Host.Run(ctx, r.ssh(dest, script, false))
	if err != nil {
		var exit *host.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("ssh exited with status %d", exit.ExitCode)
		}
		return errors.New("ssh failed")
	}
	var b64 strings.Builder
	inKey := false
	id := ""
	for _, line := range strings.Split(res.Output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "TRS-KEY-BEGIN":
			inKey = true
		case line == "TRS-KEY-END":
			inKey = false
		case inKey:
			b64.WriteString(line)
		case strings.HasPrefix(line, "TRS-ID "):
			id = strings.TrimSpace(strings.TrimPrefix(line, "TRS-ID "))
		}
	}
	key, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil || !family.ValidKey(key) {
		return fmt.Errorf("%s did not return a valid family key from %s", dest, path.Join(keyDir, r.keyFile))
	}
	if !family.ValidID(id) {
		return fmt.Errorf("%s did not return a valid FamilyId", dest)
	}
	dir := filepath.Join(r.work, "family")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, r.keyFile), key, 0o600); err != nil {
		return err
	}
	r.key, r.id = key, id
	return nil
}

// cleanup removes the remote directory after a failure, best effort.
func (r *fleetRun) cleanup(ctx context.Context, dest, tmp string) {
	if tmp == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	_, _ = r.f.Host.Run(ctx, r.ssh(dest, "rm -rf -- "+ShellQuote(tmp), false))
}

func (f *Fleet) summary(results []HostResult) {
	fmt.Fprintln(f.Out, "\nSummary:")
	tw := tabwriter.NewWriter(f.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  HOST\tRESULT\t")
	for _, res := range results {
		detail := ""
		if res.Err != nil {
			detail = res.Err.Error()
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", res.Host, res.Outcome, detail)
	}
	_ = tw.Flush()
}

// commandError describes a failed ssh or scp call without repeating the
// (long) remote script.
func commandError(what string, err error) error {
	var exit *host.ExitError
	if !errors.As(err, &exit) {
		return fmt.Errorf("%s: %w", what, err)
	}
	if exit.ExitCode == 255 {
		return fmt.Errorf("%s failed: ssh could not connect or authenticate (exit status 255)", what)
	}
	return fmt.Errorf("%s failed with exit status %d", what, exit.ExitCode)
}
