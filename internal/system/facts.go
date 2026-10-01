// Package system inspects the machine the installer runs on: operating
// system, CPU architecture, memory, disk space, IPv6 addresses, SSH ports and
// the firewall manager. It also builds the firewall commands that open the
// Tor ORPort and offers small read-only network checks.
//
// Everything that reads files or runs programs goes through a host.Host, so
// tests use host.Fake. The few probes that cannot (network interfaces and
// statfs) are side-effect-free library calls behind package variables.
package system

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// probeTimeout bounds every read-only command Detect runs, so one hanging
// program (a stuck nft, an sshd waiting on DNS) cannot stall the installer.
const probeTimeout = 2 * time.Second

// Facts describes the target machine.
type Facts struct {
	OSID, VersionID, Codename, PrettyName string

	// Arch is the dpkg architecture (amd64, arm64, armhf, ...), from
	// `dpkg --print-architecture` with a runtime.GOARCH fallback.
	Arch string

	Hostname    string
	MemTotalMiB int // 0 when /proc/meminfo is unreadable
	DiskFreeMiB int // free space for /var as seen by unprivileged users; 0 if unknown
	Systemd     bool

	// IPv6 lists global unicast IPv6 addresses of up, non-loopback
	// interfaces (link-local, ULA fc00::/7 and loopback excluded).
	IPv6 []string

	// SSHPorts is the sorted, de-duplicated union of `sshd -T` ports, the
	// server port of $SSH_CONNECTION and Port lines in sshd_config (and
	// sshd_config.d/*.conf). It defaults to [22] when nothing is found.
	SSHPorts []int

	Firewall Firewall
	EUID     int
}

// Package variables for the probes that do not go through host.Host;
// tests replace them.
var (
	interfaceAddrs = defaultInterfaceAddrs
	diskFree       = DiskFree
	osHostname     = os.Hostname
)

// Detect gathers Facts, running independent probes concurrently. Optional
// probes that fail leave their field at its zero value (or a documented
// fallback); only a missing os-release file is an error. env looks up
// environment variables and defaults to os.Getenv.
func Detect(ctx context.Context, h host.Host, env func(string) string) (Facts, error) {
	if env == nil {
		env = os.Getenv
	}
	f := Facts{EUID: os.Geteuid()}

	// Each goroutine writes only its own fields of f.
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return f.detectOS(gctx, h) })
	g.Go(func() error {
		if data, err := h.ReadFile("/proc/meminfo"); err == nil {
			f.MemTotalMiB = ParseMemTotalMiB(data)
		}
		return nil
	})
	g.Go(func() error {
		info, err := h.Stat("/run/systemd/system")
		f.Systemd = err == nil && info.IsDir()
		return nil
	})
	g.Go(func() error { f.Arch = detectArch(gctx, h); return nil })
	g.Go(func() error { f.Hostname = detectHostname(h); return nil })
	g.Go(func() error {
		if mib, _, err := diskFree("/var"); err == nil {
			f.DiskFreeMiB = mib
		}
		return nil
	})
	g.Go(func() error { f.IPv6 = localIPv6(); return nil })
	g.Go(func() error { f.SSHPorts = detectSSHPorts(gctx, h, env); return nil })
	g.Go(func() error { f.Firewall = DetectFirewall(gctx, h); return nil })
	if err := g.Wait(); err != nil {
		return Facts{}, err
	}
	return f, nil
}

// detectOS fills the os-release fields. /usr/lib/os-release is the
// documented fallback when /etc/os-release is absent.
func (f *Facts) detectOS(ctx context.Context, h host.Host) error {
	data, err := h.ReadFile("/etc/os-release")
	if err != nil {
		var ferr error
		if data, ferr = h.ReadFile("/usr/lib/os-release"); ferr != nil {
			return fmt.Errorf("cannot read /etc/os-release; unsupported system: %w", err)
		}
	}
	kv := ParseOSRelease(data)
	f.OSID = kv["ID"]
	f.VersionID = kv["VERSION_ID"]
	f.Codename = kv["VERSION_CODENAME"]
	if f.Codename == "" {
		f.Codename = kv["UBUNTU_CODENAME"]
	}
	f.PrettyName = kv["PRETTY_NAME"]
	if f.PrettyName == "" {
		f.PrettyName = strings.TrimSpace(f.OSID + " " + f.VersionID)
	}
	if f.Codename == "" {
		if _, err := h.LookPath("lsb_release"); err == nil {
			if out, err := probe(ctx, h, "lsb_release", "-cs"); err == nil {
				f.Codename = firstField(out)
			}
		}
	}
	return nil
}

// probe runs a read-only command with probeTimeout.
func probe(ctx context.Context, h host.Host, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	res, err := h.Run(ctx, host.Command{Name: name, Args: args})
	return res.Output, err
}

func firstField(s string) string {
	if fields := strings.Fields(s); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// goarchToDpkg maps Go architecture names to Debian ones where they differ.
var goarchToDpkg = map[string]string{
	"386":      "i386",
	"arm":      "armhf",
	"ppc64le":  "ppc64el",
	"mips64le": "mips64el",
	"mipsle":   "mipsel",
}

func detectArch(ctx context.Context, h host.Host) string {
	if out, err := probe(ctx, h, "dpkg", "--print-architecture"); err == nil {
		if arch := firstField(out); arch != "" {
			return arch
		}
	}
	if arch, ok := goarchToDpkg[runtime.GOARCH]; ok {
		return arch
	}
	return runtime.GOARCH
}

func detectHostname(h host.Host) string {
	for _, p := range []string{"/proc/sys/kernel/hostname", "/etc/hostname"} {
		if data, err := h.ReadFile(p); err == nil {
			if name := firstField(string(data)); name != "" {
				return name
			}
		}
	}
	name, _ := osHostname()
	return name
}

// ParseOSRelease parses os-release(5) content: KEY=value lines with shell
// quoting. Blank lines, comments and malformed lines are skipped; single
// quotes are literal, double quotes honour \" \\ \$ and \` escapes, and an
// unquoted value ends at whitespace.
func ParseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok || !validEnvKey(key) {
			continue
		}
		out[key] = shellValue(raw)
	}
	return out
}

func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// shellValue decodes one shell word as os-release uses it.
func shellValue(s string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch quote {
		case '\'':
			if c == '\'' {
				quote = 0
			} else {
				b.WriteByte(c)
			}
		case '"':
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\", s[i+1]) >= 0:
				i++
				b.WriteByte(s[i])
			default:
				b.WriteByte(c)
			}
		default:
			switch {
			case c == '\'' || c == '"':
				quote = c
			case c == '\\' && i+1 < len(s):
				i++
				b.WriteByte(s[i])
			case c == ' ' || c == '\t':
				return b.String()
			default:
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// ParseMemTotalMiB returns MemTotal from /proc/meminfo in MiB, or 0.
func ParseMemTotalMiB(meminfo []byte) int {
	for _, line := range strings.Split(string(meminfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "MemTotal:" {
			continue
		}
		kib, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kib < 0 {
			return 0
		}
		if len(fields) > 2 && !strings.EqualFold(fields[2], "kB") {
			return 0
		}
		return int(kib / 1024)
	}
	return 0
}

// detectSSHPorts collects the ports sshd listens on; see Facts.SSHPorts.
func detectSSHPorts(ctx context.Context, h host.Host, env func(string) string) []int {
	var ports []int

	sshd := "sshd"
	if _, err := h.LookPath(sshd); err != nil {
		sshd = ""
		if _, err := h.Stat("/usr/sbin/sshd"); err == nil {
			sshd = "/usr/sbin/sshd"
		}
	}
	if sshd != "" {
		if out, err := probe(ctx, h, sshd, "-T"); err == nil {
			ports = append(ports, ParseSSHPorts([]byte(out))...)
		}
	}

	// SSH_CONNECTION: client-ip client-port server-ip server-port
	if fields := strings.Fields(env("SSH_CONNECTION")); len(fields) == 4 {
		if p, ok := parsePort(fields[3]); ok {
			ports = append(ports, p)
		}
	}

	configs := []string{"/etc/ssh/sshd_config"}
	if more, err := h.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		configs = append(configs, more...)
	}
	for _, path := range configs {
		if data, err := h.ReadFile(path); err == nil {
			ports = append(ports, ParseSSHPorts(data)...)
		}
	}

	if len(ports) == 0 {
		return []int{22}
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

// ParseSSHPorts extracts Port values from sshd_config syntax or `sshd -T`
// output ("port 22"). Keywords are case-insensitive, "Port=22" is accepted,
// comments and invalid ports are ignored. sshd listens on every Port line,
// so all of them are returned.
func ParseSSHPorts(config []byte) []int {
	var ports []int
	for _, line := range strings.Split(string(config), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		key, value, ok := cutKeyword(line)
		if !ok || !strings.EqualFold(key, "port") {
			continue
		}
		if p, ok := parsePort(firstField(value)); ok {
			ports = append(ports, p)
		}
	}
	return ports
}

// cutKeyword splits "Keyword value" or "Keyword=value".
func cutKeyword(line string) (key, value string, ok bool) {
	i := strings.IndexAny(line, " \t=")
	if i <= 0 {
		return "", "", false
	}
	key = line[:i]
	value = strings.TrimLeft(line[i:], " \t")
	value = strings.TrimPrefix(value, "=")
	return key, strings.TrimSpace(value), true
}

func parsePort(s string) (int, bool) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, false
	}
	return p, true
}

// RequiredRAMMiB is the memory Tor recommends for the relay type.
func RequiredRAMMiB(exit bool) int {
	if exit {
		return 1536
	}
	return 512
}

// Problems lists the reasons the installer cannot target this machine; it is
// empty when the system is supported (Linux is assumed): Debian or Ubuntu
// with a known codename on amd64 or arm64, running systemd.
func (f Facts) Problems() []string {
	var out []string
	name := f.PrettyName
	if name == "" {
		name = strings.TrimSpace(f.OSID + " " + f.VersionID)
	}
	if name == "" {
		name = "unknown"
	}
	switch f.OSID {
	case "debian", "ubuntu":
		if f.Codename == "" {
			out = append(out, fmt.Sprintf("could not detect the Debian/Ubuntu release codename for %s", name))
		}
	default:
		out = append(out, fmt.Sprintf("unsupported OS %s: only Debian and Ubuntu releases with a Tor Project apt suite are supported", name))
	}
	switch f.Arch {
	case "amd64", "arm64":
	default:
		arch := f.Arch
		if arch == "" {
			arch = "unknown"
		}
		out = append(out, fmt.Sprintf("unsupported CPU architecture %q: the Tor Project apt repository offers amd64 and arm64 packages", arch))
	}
	if !f.Systemd {
		out = append(out, "systemd is not running (/run/systemd/system is missing); it is required to manage the tor service")
	}
	return out
}

// defaultInterfaceAddrs returns the addresses of up, non-loopback interfaces.
func defaultInterfaceAddrs() ([]net.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		out = append(out, addrs...)
	}
	return out, nil
}

func localIPv6() []string {
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if IsGlobalIPv6(ip) {
			s := ip.String()
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// IsGlobalIPv6 reports whether ip is a global unicast IPv6 address suitable
// for an IPv6 ORPort: not IPv4 (or IPv4-mapped), loopback, link-local,
// multicast, unspecified or unique-local (fc00::/7).
func IsGlobalIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len && ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}
