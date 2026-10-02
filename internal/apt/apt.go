// Package apt drives apt-get, apt-cache and dpkg-query through a host.Host.
//
// Mutating apt-get runs are non-interactive, keep existing configuration
// files, wait for the dpkg lock instead of failing immediately, and report
// machine-readable progress (APT::Status-Fd) as Progress values. Failures
// carry a remediation hint for the common cases: a held lock, an
// interrupted dpkg run, or a full disk.
package apt

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// DefaultLockTimeout is how long apt-get waits for the dpkg lock when
// Client.LockTimeout is zero. unattended-upgrades often holds it for a few
// minutes right after a server boots.
const DefaultLockTimeout = 5 * time.Minute

// env is the environment for every apt-get run: no debconf prompts, no
// needrestart dialog, no apt-listchanges pager.
var env = []string{
	"DEBIAN_FRONTEND=noninteractive",
	"NEEDRESTART_MODE=a",
	"APT_LISTCHANGES_FRONTEND=none",
}

// packageRE matches Debian package names (Debian Policy 5.6.7).
var packageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

// Client runs package-management commands on a Host.
type Client struct {
	Host host.Host
	// LockTimeout is how long apt-get waits for the dpkg lock
	// (DPkg::Lock::Timeout). Zero means DefaultLockTimeout.
	LockTimeout time.Duration
	// NoRecommends installs without recommended packages
	// (--no-install-recommends), for servers that must not gain extra
	// listening services.
	NoRecommends bool
}

// Error is a failed apt-get run. Hint, when set, tells the user how to fix
// the most likely cause.
type Error struct {
	Op string // "update", "install" or "purge"
	// DpkgErrors are the pmerror messages dpkg reported, as
	// "<package>: <message>".
	DpkgErrors []string
	Hint       string
	Err        error // usually a *host.ExitError
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("apt-get " + e.Op + " failed: " + e.Err.Error())
	for _, d := range e.DpkgErrors {
		b.WriteString("\ndpkg: " + d)
	}
	if e.Hint != "" {
		b.WriteString("\nhint: " + e.Hint)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// hints maps output fragments to advice, checked in order.
var hints = []struct{ match, hint string }{
	{"dpkg was interrupted", "a previous package operation was interrupted; run: sudo dpkg --configure -a"},
	{"Could not get lock", "another package manager (often unattended-upgrades) holds the dpkg lock; wait for it to finish, then retry"},
	{"Unable to acquire the dpkg frontend lock", "another package manager (often unattended-upgrades) holds the dpkg lock; wait for it to finish, then retry"},
	{"No space left on device", "the disk is full; free space (for example: sudo apt-get clean) and retry"},
}

// hintFor returns advice for known failure messages in output.
func hintFor(output string) string {
	for _, h := range hints {
		if strings.Contains(output, h.match) {
			return h.hint
		}
	}
	return ""
}

// Update refreshes the package lists (apt-get update).
func (c Client) Update(ctx context.Context, onProgress func(Progress), onLine func(string)) error {
	return c.aptGet(ctx, "update", nil, onProgress, onLine)
}

// Install installs pkgs (apt-get install). An empty list does nothing.
func (c Client) Install(ctx context.Context, pkgs []string, onProgress func(Progress), onLine func(string)) error {
	if len(pkgs) == 0 {
		return nil
	}
	return c.aptGet(ctx, "install", pkgs, onProgress, onLine)
}

// Purge removes pkgs together with their configuration files
// (apt-get purge). An empty list does nothing.
func (c Client) Purge(ctx context.Context, pkgs []string, onLine func(string)) error {
	if len(pkgs) == 0 {
		return nil
	}
	return c.aptGet(ctx, "purge", pkgs, nil, onLine)
}

// args returns the full apt-get argument list for a subcommand.
func (c Client) args(subcommand string, pkgs ...string) []string {
	args := []string{
		"-q", "-y",
		"-o", "APT::Status-Fd=3",
		"-o", "DPkg::Lock::Timeout=" + strconv.Itoa(c.lockSeconds()),
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
	}
	if c.NoRecommends && subcommand == "install" {
		args = append(args, "--no-install-recommends")
	}
	args = append(args, subcommand)
	return append(args, pkgs...)
}

func (c Client) lockSeconds() int {
	d := c.LockTimeout
	if d <= 0 {
		d = DefaultLockTimeout
	}
	return int(math.Ceil(d.Seconds()))
}

func (c Client) aptGet(ctx context.Context, op string, pkgs []string, onProgress func(Progress), onLine func(string)) error {
	if err := validate(pkgs...); err != nil {
		return err
	}
	var (
		mu         sync.Mutex
		dpkgErrors []string
	)
	cmd := host.Command{
		Name:    "apt-get",
		Args:    c.args(op, pkgs...),
		Env:     append([]string(nil), env...),
		Mutates: true,
		StatusFD: func(line string) {
			if p, ok := ParseStatusLine(line); ok {
				if onProgress != nil {
					onProgress(p)
				}
				return
			}
			if pkg, msg, ok := ParseStatusError(line); ok {
				mu.Lock()
				dpkgErrors = append(dpkgErrors, pkg+": "+msg)
				mu.Unlock()
			}
		},
	}
	res, err := c.Host.Stream(ctx, cmd, onLine)
	if err == nil {
		return nil
	}
	output := res.Output
	var exitErr *host.ExitError
	if errors.As(err, &exitErr) && exitErr.Output != "" {
		output = exitErr.Output
	}
	mu.Lock()
	defer mu.Unlock()
	return &Error{Op: op, DpkgErrors: dpkgErrors, Hint: hintFor(output), Err: err}
}

// Policy returns the output of `apt-cache policy <pkg>`. It is read-only and
// runs even in a dry run. LC_ALL=C keeps the output parseable.
func (c Client) Policy(ctx context.Context, pkg string) (string, error) {
	if err := validate(pkg); err != nil {
		return "", err
	}
	res, err := c.Host.Run(ctx, host.Command{
		Name: "apt-cache",
		Args: []string{"policy", pkg},
		Env:  []string{"LC_ALL=C"},
	})
	if err != nil {
		return "", fmt.Errorf("apt-cache policy %s: %w", pkg, err)
	}
	return res.Output, nil
}

// ParseCandidate returns the "Candidate:" version from apt-cache policy
// output, or "" when there is none. "(none)" is returned as is.
func ParseCandidate(policyOutput string) string {
	for line := range strings.Lines(policyOutput) {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "Candidate:" {
			return f[1]
		}
	}
	return ""
}

// CandidateAvailable reports whether apt can install pkg: apt-cache policy
// shows a candidate version other than "(none)".
func (c Client) CandidateAvailable(ctx context.Context, pkg string) (bool, error) {
	out, err := c.Policy(ctx, pkg)
	if err != nil {
		return false, err
	}
	cand := ParseCandidate(out)
	return cand != "" && cand != "(none)", nil
}

// Installed reports whether pkg is installed, according to dpkg's status
// database. An unknown package is not installed; that is not an error.
func (c Client) Installed(ctx context.Context, pkg string) (bool, error) {
	if err := validate(pkg); err != nil {
		return false, err
	}
	res, err := c.Host.Run(ctx, host.Command{
		Name: "dpkg-query",
		Args: []string{"-W", "-f=${Status}", pkg},
	})
	if err != nil {
		var exitErr *host.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode == 1 {
			return false, nil // "no packages found matching <pkg>"
		}
		return false, fmt.Errorf("dpkg-query %s: %w", pkg, err)
	}
	return statusInstalled(res.Output), nil
}

// statusInstalled reports whether dpkg-query ${Status} output
// ("<want> <flag> <status>") describes an installed package, regardless of
// the selection state: "install ok installed" and "hold ok installed" are
// installed, "deinstall ok config-files" is not.
func statusInstalled(output string) bool {
	for line := range strings.Lines(output) {
		f := strings.Fields(line)
		if len(f) == 3 && f[1] == "ok" && f[2] == "installed" {
			return true
		}
	}
	return false
}

// validate rejects anything that is not a plain Debian package name, so no
// argument can be mistaken for an option.
func validate(pkgs ...string) error {
	for _, p := range pkgs {
		if !packageRE.MatchString(p) {
			return fmt.Errorf("invalid package name %q", p)
		}
	}
	return nil
}
