package monitor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
)

// Relay-side files of `fleet authorize`.
const (
	ProbeSSHDir        = ProbeHome + "/.ssh"
	ProbeAuthorizedKey = ProbeSSHDir + "/authorized_keys"
	SudoersPath        = "/etc/sudoers.d/tor-relay-setup-probe"
	// sudo skips files in sudoers.d whose name contains a dot, so the
	// candidate is never active while visudo checks it.
	sudoersCandidate = SudoersPath + ".new"
	hostKeyPath      = "/etc/ssh/ssh_host_ed25519_key.pub"
	maxFrom          = 16
)

// AuthorizeOptions is what `fleet authorize` was asked for on a relay.
type AuthorizeOptions struct {
	Keys   []string // monitoring servers' public keys (ssh-ed25519)
	From   []string // optional source addresses or CIDRs for from="..."
	Binary string   // resolved absolute path of tor-relay-setup
	Name   string   // the relay's name in the monitor's known_hosts
	Remove bool
}

// Normalize validates the keys, the from= list and the binary path.
func (o *AuthorizeOptions) Normalize() error {
	if o.Remove {
		return nil
	}
	if len(o.Keys) == 0 {
		return errors.New("--key is required: the monitoring server's public key (monitor install prints it)")
	}
	for i, k := range o.Keys {
		norm, err := ParseEd25519Key(k)
		if err != nil {
			return err
		}
		o.Keys[i] = norm
	}
	if len(o.From) > maxFrom {
		return fmt.Errorf("--from: at most %d addresses", maxFrom)
	}
	for _, f := range o.From {
		if net.ParseIP(f) == nil {
			if _, _, err := net.ParseCIDR(f); err != nil {
				return fmt.Errorf("--from %q is not an IP address or CIDR network (host names would make sshd trust DNS)", f)
			}
		}
	}
	if !path.IsAbs(o.Binary) || !unitSafe(o.Binary) {
		return fmt.Errorf("tor-relay-setup at %q: the path must be absolute and plain to be used in sudoers", o.Binary)
	}
	if o.Name != "" && !hostNameRE.MatchString(o.Name) {
		return fmt.Errorf("--name %q is not a host name or address", o.Name)
	}
	return nil
}

var (
	keyCommentRE = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,100}$`)
	hostNameRE   = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]{1,253}$`)
)

// ParseEd25519Key checks an OpenSSH ed25519 public key line and returns it
// normalized ("ssh-ed25519 BASE64 [comment]"). Only ed25519 is accepted:
// monitor install generates that type, and nothing else needs to log in.
func ParseEd25519Key(line string) (string, error) {
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "ssh-ed25519" {
		return "", errors.New("--key must be an ssh-ed25519 public key line (ssh-ed25519 AAAA... comment)")
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return "", errors.New("--key: the key data is not base64")
	}
	// Wire format: string "ssh-ed25519", string <32-byte key>.
	r := bytes.NewReader(blob)
	readString := func() ([]byte, bool) {
		var n uint32
		if binary.Read(r, binary.BigEndian, &n) != nil || n > 256 || int(n) > r.Len() {
			return nil, false
		}
		b := make([]byte, n)
		_, err := r.Read(b)
		return b, err == nil
	}
	typ, ok1 := readString()
	key, ok2 := readString()
	if !ok1 || !ok2 || string(typ) != "ssh-ed25519" || len(key) != 32 || r.Len() != 0 {
		return "", errors.New("--key: not a valid ssh-ed25519 key")
	}
	out := f[0] + " " + f[1]
	if len(f) == 3 && keyCommentRE.MatchString(f[2]) {
		out += " " + f[2]
	}
	return out, nil
}

// ProbeCommand is the only command the monitoring key may run.
func ProbeCommand(binary string) string { return "sudo -n " + binary + " fleet-probe" }

// AuthorizedKeysLine restricts key to the probe: restrict turns off port,
// agent and X11 forwarding, PTYs and ~/.ssh/rc; command= ignores whatever
// the client asks to run; from= (when given) limits the source addresses.
func AuthorizedKeysLine(key, binary string, from []string) string {
	opts := `restrict,command="` + ProbeCommand(binary) + `"`
	if len(from) > 0 {
		opts += `,from="` + strings.Join(from, ",") + `"`
	}
	return opts + " " + strings.TrimSpace(key)
}

// AuthorizedKeysFile is ProbeUser's authorized_keys.
func AuthorizedKeysFile(o AuthorizeOptions) []byte {
	var b strings.Builder
	b.WriteString("# Written by tor-relay-setup fleet authorize; this file belongs to root so " + ProbeUser + " cannot change it.\n")
	b.WriteString("# Each key may only run: " + ProbeCommand(o.Binary) + "\n")
	for _, k := range o.Keys {
		b.WriteString(AuthorizedKeysLine(k, o.Binary, o.From) + "\n")
	}
	return []byte(b.String())
}

// SudoersFile lets ProbeUser run exactly `BINARY fleet-probe` as root: a
// sudoers command with arguments matches only those arguments, so no other
// subcommand, flag or program is allowed, and env_reset drops the caller's
// environment (no TOR_RELAY_SETUP_* overrides).
func SudoersFile(binary string) []byte {
	return []byte(`# Written by tor-relay-setup fleet authorize; remove with: tor-relay-setup fleet authorize --remove
# The monitoring server logs in as ` + ProbeUser + ` with a forced-command key and
# may run this one read-only probe as root, nothing else.
Defaults:` + ProbeUser + ` !requiretty, !lecture, env_reset
` + ProbeUser + ` ALL=(root) NOPASSWD: ` + binary + ` fleet-probe
`)
}

// AuthorizeSteps builds the relay-side plan.
func AuthorizeSteps(o AuthorizeOptions) []plan.Step {
	if o.Remove {
		return []plan.Step{removeProbeStep()}
	}
	return []plan.Step{
		{
			ID: "check", Title: "Check sudo, sshd and the tor-relay-setup binary", Weight: 1,
			Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
				return checkAuthorize(ctx, e, o, r)
			},
		},
		{
			ID: "probe-user", Title: "Create the " + ProbeUser + " user", Weight: 1,
			Changes: []string{
				"Create system user " + ProbeUser + " (shell /bin/sh for the forced command, no password, home " + ProbeHome + " owned by root) unless it exists",
				"Write " + ProbeAuthorizedKey + " (root-owned): " + strconv.Itoa(len(o.Keys)) + " key(s) limited to \"" + ProbeCommand(o.Binary) + "\"" + fromNote(o.From),
			},
			Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
				h := e.Host
				if !userExists(ctx, h, ProbeUser) {
					// "*" is no valid password hash, so password logins are
					// impossible; unlike "!" it does not lock the account,
					// which sshd would refuse even for keys with UsePAM no.
					if _, err := h.Run(ctx, host.Command{Name: "useradd", Args: []string{
						"--system", "--user-group", "--home-dir", ProbeHome, "--no-create-home",
						"--shell", "/bin/sh", "--password", "*", "--comment", "tor-relay-setup fleet probe (forced command)", ProbeUser,
					}, Mutates: true}); err != nil {
						return err
					}
				}
				for _, d := range []string{ProbeHome, ProbeSSHDir} {
					if err := h.MkdirAll(d, 0o755, ""); err != nil {
						return err
					}
				}
				_, err := h.WriteFile(ProbeAuthorizedKey, AuthorizedKeysFile(o), host.FileOptions{Mode: 0o644, Backup: true})
				return err
			},
		},
		{
			ID: "sudoers", Title: "Allow the probe command in sudoers", Weight: 1,
			Changes: []string{"Write " + SudoersPath + " (0440) after visudo accepts it: " + ProbeUser + " may run \"" + o.Binary + " fleet-probe\" as root, nothing else"},
			Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
				h := e.Host
				data := SudoersFile(o.Binary)
				if old, err := h.ReadFile(SudoersPath); err == nil && bytes.Equal(old, data) {
					return nil
				}
				if _, err := h.WriteFile(sudoersCandidate, data, host.FileOptions{Mode: 0o440}); err != nil {
					return err
				}
				_, err := h.Run(ctx, host.Command{Name: "visudo", Args: []string{"-c", "-q", "-f", sudoersCandidate}, Mutates: true})
				_ = h.Remove(sudoersCandidate)
				if err != nil {
					return fmt.Errorf("visudo rejected the sudoers rule: %w", err)
				}
				_, err = h.WriteFile(SudoersPath, data, host.FileOptions{Mode: 0o440})
				return err
			},
		},
	}
}

func fromNote(from []string) string {
	if len(from) == 0 {
		return ", from any address (add --from MONITOR_IP to pin it)"
	}
	return ", from " + strings.Join(from, ", ") + " only"
}

func checkAuthorize(ctx context.Context, e *plan.Env, o AuthorizeOptions, r plan.Reporter) error {
	h := e.Host
	if !h.DryRun() && e.Facts.EUID != 0 {
		return errors.New("run as root, for example: sudo tor-relay-setup fleet authorize --key KEY")
	}
	for _, tool := range []string{"sudo", "visudo"} {
		if _, err := h.LookPath(tool); err != nil {
			return errors.New("sudo is not installed; install it first: apt install sudo")
		}
	}
	// Whoever can replace the binary (or a directory above it) could make
	// the probe user run anything as root, so all must belong to root and
	// be writable only by root.
	paths := []string{o.Binary}
	for d := path.Dir(o.Binary); ; d = path.Dir(d) {
		paths = append(paths, d)
		if d == "/" {
			break
		}
	}
	res, err := h.Run(ctx, host.Command{Name: "stat", Args: append([]string{"-c", "%u %a %n"}, paths...)})
	if err != nil {
		return fmt.Errorf("stat %s: %w", o.Binary, err)
	}
	for l := range strings.Lines(res.Output) {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		mode, _ := strconv.ParseUint(f[1], 8, 32)
		if f[0] != "0" || mode&0o022 != 0 {
			return fmt.Errorf("%s must belong to root and be writable only by root (it is uid %s, mode %s): the probe runs it as root", f[2], f[0], f[1])
		}
	}
	r.Note(plan.Success, o.Binary+" and its directories belong to root")
	sshdWarnings(ctx, h, r)
	return nil
}

// sshdWarnings notes sshd settings that would keep the probe user out.
func sshdWarnings(ctx context.Context, h host.Host, r plan.Reporter) {
	res, err := h.Run(ctx, host.Command{Name: "sshd", Args: []string{"-T", "-C", "user=" + ProbeUser + ",host=monitor,addr=192.0.2.1"}})
	if err != nil {
		return
	}
	for l := range strings.Lines(res.Output) {
		k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
		switch k {
		case "allowusers":
			if !strings.Contains(" "+v+" ", " "+ProbeUser+" ") && !strings.Contains(v, ProbeUser+"@") {
				r.Note(plan.Warn, "sshd AllowUsers does not include "+ProbeUser+": add it, or the monitoring server cannot log in")
			}
		case "allowgroups":
			if !strings.Contains(" "+v+" ", " "+ProbeUser+" ") {
				r.Note(plan.Warn, "sshd AllowGroups does not include "+ProbeUser+": add the group, or the monitoring server cannot log in")
			}
		case "pubkeyauthentication":
			if v == "no" {
				r.Note(plan.Warn, "sshd has PubkeyAuthentication no: the monitoring key cannot be used")
			}
		case "authorizedkeysfile":
			if !strings.Contains(v, ".ssh/authorized_keys") {
				r.Note(plan.Warn, "sshd AuthorizedKeysFile is "+v+": put the line from "+ProbeAuthorizedKey+" there")
			}
		}
	}
}

func removeProbeStep() plan.Step {
	return plan.Step{
		ID: "remove", Title: "Remove the monitoring access", Weight: 1,
		Changes: []string{"Remove " + SudoersPath + ", " + ProbeHome + " and the " + ProbeUser + " user"},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			for _, p := range []string{SudoersPath, ProbeHome} {
				if _, err := h.Stat(p); err == nil {
					if err := h.Remove(p); err != nil {
						return err
					}
				}
			}
			if userExists(ctx, h, ProbeUser) {
				if _, err := h.Run(ctx, host.Command{Name: "userdel", Args: []string{ProbeUser}, Mutates: true}); err != nil {
					return err
				}
			}
			r.Note(plan.Success, "The monitoring server can no longer log in here")
			return nil
		},
	}
}

// KnownHostsLine is the relay's ed25519 host key as a known_hosts line for
// name, or "" when the key cannot be read.
func KnownHostsLine(h host.Host, name string) string {
	data, err := h.ReadFile(hostKeyPath)
	if err != nil {
		return ""
	}
	f := strings.Fields(string(data))
	if len(f) < 2 || f[0] != "ssh-ed25519" {
		return ""
	}
	return name + " " + f[0] + " " + f[1]
}
