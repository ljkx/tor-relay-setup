// Package remote applies relay configs to a fleet over SSH with the system
// OpenSSH client, so ~/.ssh/config, agents and known_hosts apply as usual.
// For every relay it uploads the running binary and that relay's config to
// a private temporary directory, runs `tor-relay-setup apply` there with
// sudo, and removes the directory again. It also probes hosts for the
// fleet dashboard and runs rolling restarts.
//
// A fleet that generates a family key is applied to the first generating
// relay alone; the key it created is then fetched back and imported on
// every further one, so the whole fleet ends up in one family. The other
// servers are then applied concurrently (bounded), the relays of one
// server one after another.
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
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

const (
	binaryName = "tor-relay-setup"
	configName = "relay.toml"

	secretSuffix = ".secret_family_key"
	publicSuffix = ".public_family_id"
)

// sshOptions go to every ssh and scp call, last before "--". Host key
// checking is left to the user's configuration and is never disabled.
var sshOptions = []string{"-o", "ConnectTimeout=10"}

// controlPersist keeps an idle shared connection open between calls.
const controlPersist = "120s"

// Outcome is the result of one relay.
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
	Relay   string // nickname, plus the instance on multi-relay servers
	Outcome Outcome
	Err     error
}

// Options describes one fleet run: an inventory, or one config for a list
// of hosts (the one-off inventory of `apply --config FILE --host ...`).
type Options struct {
	ConfigPath string
	Hosts      []string
	Inventory  *fleet.Inventory // used instead of ConfigPath and Hosts
	DryRun     bool             // run apply --dry-run on every host
	KeepGoing  bool             // continue with the next relay after a failure
	// Parallel is how many servers are applied at once after the family
	// host; it overrides the inventory's setting when positive.
	Parallel int
}

// Fleet runs ssh and scp through Host. Host should be a real host even for
// a dry run: the remote tor-relay-setup performs the dry run itself.
type Fleet struct {
	Host       host.Host
	Out        io.Writer
	Executable func() (string, error)
	GOOS       string
	GOARCH     string
	// Multiplex shares one ssh connection per host (OpenSSH ControlMaster
	// with a private ControlPath) for the Fleet's lifetime; Close ends the
	// connections. New sets it.
	Multiplex bool

	mu         sync.Mutex
	controlDir string
	masters    map[string]bool // ssh destinations that may have a master
	closed     bool            // after Close, ssh connects per call
	outMu      sync.Mutex
}

// New returns a Fleet that runs the system ssh and scp with shared
// connections. Call Close when done.
func New(out io.Writer) *Fleet {
	return &Fleet{Host: host.NewLocal(), Out: out, Executable: os.Executable, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Multiplex: true}
}

// ValidHost accepts plausible ssh destinations; see fleet.ValidAddress.
func ValidHost(s string) error { return fleet.ValidAddress(s) }

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

// controlOptions make ssh share one connection per destination through a
// socket in dir; %C is a hash of the connection, so paths stay short.
func controlOptions(dir string) []string {
	return []string{
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=" + filepath.Join(dir, "%C"),
		"-o", "ControlPersist=" + controlPersist,
	}
}

// maxControlDir leaves room for "/%C" (40 hex digits) in the 104-byte
// limit of a Unix socket path.
const maxControlDir = 60

// sshArgs are the options for an ssh or scp call to dest.
func (f *Fleet) sshArgs(dest string) []string {
	var args []string
	if dir := f.control(dest); dir != "" {
		args = controlOptions(dir)
	}
	return append(args, sshOptions...)
}

// control returns the private control socket directory (0700), creating
// it on first use, and remembers dest for Close. Without Multiplex, or
// when no directory can be made, it returns "" and ssh connects per call.
func (f *Fleet) control(dest string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Multiplex || f.closed {
		return ""
	}
	if f.controlDir == "" {
		parent := ""
		if len(os.TempDir()) > maxControlDir-20 {
			parent = "/tmp"
		}
		dir, err := os.MkdirTemp(parent, "trs-ssh-")
		if err != nil {
			return ""
		}
		f.controlDir, f.masters = dir, map[string]bool{}
	}
	f.masters[sshDest(dest)] = true
	return f.controlDir
}

// Close ends the shared ssh connections (`ssh -O exit`) and removes their
// socket directory.
func (f *Fleet) Close() error {
	f.mu.Lock()
	dir, masters := f.controlDir, f.masters
	f.controlDir, f.masters, f.closed = "", nil, true
	f.mu.Unlock()
	if dir == "" {
		return nil
	}
	dests := make([]string, 0, len(masters))
	for d := range masters {
		dests = append(dests, d)
	}
	sort.Strings(dests)
	for _, d := range dests {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = f.Host.Run(ctx, host.Command{Name: "ssh", Args: []string{"-o", "ControlPath=" + filepath.Join(dir, "%C"), "-O", "exit", "--", d}})
		cancel()
	}
	return os.RemoveAll(dir)
}

// ssh runs a script on dest with sh -c.
func (f *Fleet) ssh(dest, script string, mutates bool) host.Command {
	args := append(f.sshArgs(dest), "--", sshDest(dest), "sh -c "+ShellQuote(script))
	return host.Command{Name: "ssh", Args: args, Mutates: mutates}
}

// say writes to Out; concurrent relays never interleave within a line.
func (f *Fleet) say(format string, a ...any) {
	f.outMu.Lock()
	defer f.outMu.Unlock()
	fmt.Fprintf(f.Out, format, a...)
}

// printer prefixes every line of a relay's output with its label.
func (f *Fleet) printer(label string) func(string) {
	return func(line string) { f.say("[%s] %s\n", label, strings.TrimRight(line, "\r")) }
}

// target is one relay to apply.
type target struct {
	fleet.Entry
	pos   int    // index in the results
	label string // output prefix: the address, plus the nickname on multi-relay servers
}

// localKey is a family key read from this machine (family.mode = "import").
type localKey struct {
	key     []byte
	keyFile string // NAME.secret_family_key
	id      string
}

// fleetRun is the state of one Apply.
type fleetRun struct {
	f       *Fleet
	opt     Options
	targets []target
	exe     string
	work    string

	// share: a generated family key is copied from the family host (the
	// first relay with family.mode = "generate") to the other generating
	// relays. key, keyFile and id hold it once fetched.
	share     bool
	familyIdx int
	sharers   int // generating relays besides the family host
	key       []byte
	keyFile   string
	id        string

	local  map[string]localKey // import_key path → key
	shared bool                // one config for every host (apply --host)
}

// stopper records the first reason to start no further relays.
type stopper struct {
	mu  sync.Mutex
	err error
}

func (s *stopper) set(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

func (s *stopper) get() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Apply runs the fleet and prints a summary. It returns an error when any
// relay failed or was skipped.
func (f *Fleet) Apply(ctx context.Context, opt Options) ([]HostResult, error) {
	if opt.Inventory != nil && opt.Inventory.MonitorOnly {
		return nil, fleet.ErrMonitorOnly
	}
	r, err := f.prepare(opt)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(r.work)
	r.intro()

	results := make([]HostResult, len(r.targets))
	for i, t := range r.targets {
		results[i] = HostResult{Host: t.Address, Relay: relayName(t), Outcome: Skipped}
	}
	var stop stopper
	run := func(t target) {
		if stop.get() == nil && ctx.Err() != nil {
			stop.set(ctx.Err())
		}
		if err := stop.get(); err != nil {
			results[t.pos].Err = err
			return
		}
		f.say("\n==> [%d/%d] %s\n", t.pos+1, len(r.targets), t.label)
		if err := r.applyHost(ctx, t); err != nil {
			results[t.pos].Outcome, results[t.pos].Err = Failed, err
			f.say("[%s] FAILED: %v\n", t.label, err)
			switch {
			case r.share && t.pos == r.familyIdx:
				stop.set(fmt.Errorf("the family key could not be shared from %s", t.Address))
			case !opt.KeepGoing:
				stop.set(errors.New("stopped after an earlier failure (--keep-going continues)"))
			}
			return
		}
		results[t.pos].Outcome = OK
	}

	rest := r.targets
	if r.share {
		run(r.targets[r.familyIdx])
		rest = nil
		for _, t := range r.targets {
			if t.pos != r.familyIdx {
				rest = append(rest, t)
			}
		}
	}
	parallel := r.parallel()
	runServers(servers(rest), parallel, func(group []target) {
		for _, t := range group {
			run(t)
		}
	})
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

// intro says what is about to happen, once everything was validated.
func (r *fleetRun) intro() {
	n := len(r.targets)
	switch {
	case r.shared && n > 1:
		nick := r.targets[0].Nickname()
		r.f.say("note: all %d relays get the nickname %s; an inventory (--inventory fleet.toml) with nickname = \"%s{n}\" gives each its own\n", n, nick, nick)
	case !r.shared:
		plan := fmt.Sprintf("%d relays on %d servers", n, len(servers(r.targets)))
		if r.share {
			plan += "; " + r.targets[r.familyIdx].label + " generates the family key first"
		}
		r.f.say("Fleet: %s; up to %d servers at a time.\n", plan, r.parallel())
	}
}

func (r *fleetRun) parallel() int {
	switch {
	case r.opt.Parallel > 0:
		return r.opt.Parallel
	case r.opt.Inventory != nil:
		return max(r.opt.Inventory.Parallel, 1)
	}
	return 1
}

// servers groups targets by address, in order of first appearance.
func servers(ts []target) [][]target {
	var out [][]target
	at := map[string]int{}
	for _, t := range ts {
		key := strings.ToLower(t.Address)
		i, ok := at[key]
		if !ok {
			i = len(out)
			at[key] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], t)
	}
	return out
}

// runServers calls fn for every group, at most n at once, and returns when
// all are done. Groups start in order.
func runServers[T any](groups []T, n int, fn func(T)) {
	n = min(max(n, 1), len(groups))
	jobs := make(chan T)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			for g := range jobs {
				fn(g)
			}
		})
	}
	for _, g := range groups {
		jobs <- g
	}
	close(jobs)
	wg.Wait()
}

func relayName(t target) string {
	if t.Instance != fleet.DefaultInstance {
		return t.Nickname() + " (" + t.Instance + ")"
	}
	return t.Nickname()
}

func (f *Fleet) prepare(opt Options) (*fleetRun, error) {
	inv := opt.Inventory
	if inv == nil {
		one, err := fleet.FromHosts(opt.ConfigPath, opt.Hosts)
		if err != nil {
			return nil, err
		}
		inv = &one
	}
	if len(inv.Entries) == 0 {
		return nil, errors.New("no relays to apply")
	}
	if f.GOOS != "linux" {
		return nil, fmt.Errorf("this tor-relay-setup binary is built for %s; run apply --host from a Linux machine", f.GOOS)
	}
	exe, err := f.Executable()
	if err != nil {
		return nil, fmt.Errorf("find the running executable: %w", err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return nil, err
	}

	r := &fleetRun{f: f, opt: opt, exe: exe, familyIdx: -1, local: map[string]localKey{}, shared: inv.SharedNickname}
	perServer := map[string]int{}
	for _, e := range inv.Entries {
		perServer[strings.ToLower(e.Address)]++
	}
	for i, e := range inv.Entries {
		t := target{Entry: e, pos: i, label: e.Address}
		if perServer[strings.ToLower(e.Address)] > 1 {
			t.label = e.Address + "/" + e.Nickname()
		}
		r.targets = append(r.targets, t)
		switch e.Setup.Family.Mode {
		case "generate":
			if r.familyIdx < 0 {
				r.familyIdx = i
			} else {
				r.sharers++
			}
		case "import":
			p := e.Setup.Family.ImportKey
			if _, ok := r.local[p]; ok {
				continue
			}
			k, err := loadLocalKey(e.Setup)
			if err != nil {
				return nil, err
			}
			r.local[p] = k
		}
	}
	if r.share = r.sharers > 0; r.share {
		r.keyFile = r.targets[r.familyIdx].Setup.Family.KeyName + secretSuffix
	}
	// The work directory holds staged uploads and the family key: 0700.
	if r.work, err = os.MkdirTemp("", "tor-relay-setup-fleet-"); err != nil {
		return nil, err
	}
	return r, nil
}

// loadLocalKey reads family.import_key and its FamilyId on this machine.
func loadLocalKey(s config.Setup) (localKey, error) {
	p := s.Family.ImportKey
	key, err := os.ReadFile(p)
	if err != nil {
		return localKey{}, err
	}
	if !family.ValidKey(key) {
		return localKey{}, fmt.Errorf("%s is not a Tor family key", p)
	}
	id := s.Family.FamilyID
	if pub, err := os.ReadFile(strings.TrimSuffix(p, secretSuffix) + publicSuffix); err == nil {
		id = strings.TrimSpace(string(pub))
	}
	if !family.ValidID(id) {
		return localKey{}, errors.New("no FamilyId: copy NAME.public_family_id next to the key, or set family.family_id")
	}
	return localKey{key: key, keyFile: filepath.Base(p), id: id}, nil
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

func (r *fleetRun) probe(ctx context.Context, t target) (probe, error) {
	var p probe
	show := r.f.printer(t.label)
	res, err := r.f.Host.Run(ctx, r.f.ssh(t.Address, probeScript, false))
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
	if p.arch == "" || !tmpPattern(p.tmp) {
		return p, errors.New("unexpected answer from the host (is it a Linux system with a POSIX shell?)")
	}
	return p, nil
}

// tmpPattern accepts the absolute, plain path mktemp printed.
func tmpPattern(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return false
	}
	return strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-") == ""
}

// applyHost runs the whole sequence for one relay.
func (r *fleetRun) applyHost(ctx context.Context, t target) error {
	p, err := r.probe(ctx, t)
	if err != nil {
		return err
	}
	removeTmp := true
	defer func() {
		if removeTmp {
			r.cleanup(ctx, t.Address, p.tmp)
		}
	}()
	if arch := goarch(p.arch); arch != r.f.GOARCH {
		return fmt.Errorf("the host's CPU is %s but this binary is built for linux/%s; install tor-relay-setup there with install.sh and run apply on the host itself", p.arch, r.f.GOARCH)
	}
	sudo, err := r.sudo(t, p)
	if err != nil {
		return err
	}

	cfg, files, err := r.payload(t, p.tmp)
	if err != nil {
		return err
	}
	if err := r.upload(ctx, t, p.tmp, cfg, files); err != nil {
		return err
	}

	// The remote script removes its directory itself on exit.
	if _, err := r.f.Host.Stream(ctx, r.f.ssh(t.Address, applyScript(p.tmp, sudo, r.opt.DryRun), !r.opt.DryRun), r.f.printer(t.label)); err != nil {
		return commandError("remote apply", err)
	}
	removeTmp = false

	if r.share && t.pos == r.familyIdx {
		if r.opt.DryRun {
			r.f.say("[%s] dry run: would fetch the new family key %s and import it on the other %d relays (family.mode = \"import\")\n", t.label, r.keyFile, r.sharers)
			return nil
		}
		if err := r.fetchKey(ctx, t, sudo); err != nil {
			return fmt.Errorf("applied, but fetching the family key failed: %w", err)
		}
		r.f.say("[%s] fetched FamilyId %s; the other relays join this family\n", t.label, r.id)
	}
	return nil
}

// sudo returns the prefix for privileged remote commands. ssh runs without
// a terminal, so sudo must not need a password.
func (r *fleetRun) sudo(t target, p probe) (string, error) {
	switch {
	case p.root:
		return "", nil
	case p.sudo:
		return "sudo -n ", nil
	case r.opt.DryRun:
		r.f.say("[%s] note: no passwordless sudo; the dry run runs unprivileged\n", t.label)
		return "", nil
	}
	return "", errors.New("the remote user is not root and sudo asks for a password; ssh in as root, or allow this user passwordless sudo (commands run without a terminal)")
}

// payload returns the config to upload and any extra files (name → data).
func (r *fleetRun) payload(t target, tmp string) ([]byte, map[string][]byte, error) {
	sharer := r.share && t.pos != r.familyIdx && t.Setup.Family.Mode == "generate"
	var k localKey
	switch {
	case sharer && r.opt.DryRun:
		r.f.say("[%s] dry run: the real run imports the family key from %s; this dry run uses the config as is\n", t.label, r.targets[r.familyIdx].Address)
		return t.Config, nil, nil
	case sharer:
		k = localKey{key: r.key, keyFile: r.keyFile, id: r.id}
	case t.Setup.Family.Mode == "import":
		k = r.local[t.Setup.Family.ImportKey]
	default:
		return t.Config, nil, nil
	}
	d := t.Setup
	d.Family.Mode = "import"
	d.Family.ImportKey = path.Join(tmp, k.keyFile)
	d.Family.FamilyID = k.id
	cfg, err := d.Marshal()
	if err != nil {
		return nil, nil, err
	}
	files := map[string][]byte{
		k.keyFile: k.key,
		strings.TrimSuffix(k.keyFile, secretSuffix) + publicSuffix: []byte(k.id + "\n"),
	}
	return cfg, files, nil
}

// upload stages the binary, config and files locally and copies them into
// the remote directory with one scp call.
func (r *fleetRun) upload(ctx context.Context, t target, tmp string, cfg []byte, files map[string][]byte) error {
	stage := filepath.Join(r.work, fmt.Sprintf("host-%d", t.pos+1))
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
	args := append([]string{"-q"}, r.f.sshArgs(t.Address)...)
	args = append(append(append(args, "--"), srcs...), scpTarget(t.Address, tmp+"/"))
	if _, err := r.f.Host.Stream(ctx, host.Command{Name: "scp", Args: args, Mutates: !r.opt.DryRun}, r.f.printer(t.label)); err != nil {
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

// fetchKey copies the generated family key and FamilyId from the family
// host. The output carries the secret key, so it is never printed.
func (r *fleetRun) fetchKey(ctx context.Context, t target, sudo string) error {
	dest := t.Address
	keyDir, err := keyDirFor(t.Instance)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(r.keyFile, secretSuffix)
	script := "k=" + ShellQuote(path.Join(keyDir, r.keyFile)) + `
i=` + ShellQuote(path.Join(keyDir, name+publicSuffix)) + `
echo TRS-KEY-BEGIN
` + sudo + `base64 -- "$k"
echo TRS-KEY-END
printf 'TRS-ID %s\n' "$(` + sudo + `cat -- "$i")"`
	res, err := r.f.Host.Run(ctx, r.f.ssh(dest, script, false))
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

// keyDirFor is where apply installs a relay's family keys (plan.familyStep):
// /var/lib/tor/keys for the default instance, and
// /var/lib/tor-instances/NAME/keys for a named Debian tor instance.
func keyDirFor(instance string) (string, error) {
	inst, err := relay.Named(instance)
	if err != nil {
		return "", err
	}
	return inst.KeyDir, nil
}

// cleanup removes the remote directory after a failure, best effort.
func (r *fleetRun) cleanup(ctx context.Context, dest, tmp string) {
	if tmp == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	_, _ = r.f.Host.Run(ctx, r.f.ssh(dest, "rm -rf -- "+ShellQuote(tmp), false))
}

func (f *Fleet) summary(results []HostResult) {
	f.outMu.Lock()
	defer f.outMu.Unlock()
	fmt.Fprintln(f.Out, "\nSummary:")
	tw := tabwriter.NewWriter(f.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  HOST\tRELAY\tRESULT\t")
	for _, res := range results {
		detail := ""
		if res.Err != nil {
			detail = res.Err.Error()
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", res.Host, res.Relay, res.Outcome, detail)
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
