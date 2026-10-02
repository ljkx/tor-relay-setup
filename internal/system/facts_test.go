package system

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{
			name: "debian",
			in: `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION_CODENAME=bookworm
ID=debian
`,
			want: map[string]string{
				"PRETTY_NAME":      "Debian GNU/Linux 12 (bookworm)",
				"NAME":             "Debian GNU/Linux",
				"VERSION_ID":       "12",
				"VERSION_CODENAME": "bookworm",
				"ID":               "debian",
			},
		},
		{
			name: "comments blanks and junk",
			in:   "# comment\n\n   \nnot a line\n=novalue\n1BAD=x\nID=ubuntu\n  # indented comment\n",
			want: map[string]string{"ID": "ubuntu"},
		},
		{
			name: "single quotes are literal",
			in:   `NAME='It\'s'` + "\nX='a \"b\" $c'\n",
			want: map[string]string{"NAME": `It\s`, "X": `a "b" $c`},
		},
		{
			name: "double quote escapes",
			in:   `X="say \"hi\" \\ \$HOME \` + "`" + `x\` + "`" + ` \n"` + "\n",
			want: map[string]string{"X": `say "hi" \ $HOME ` + "`x`" + ` \n`},
		},
		{
			name: "unquoted escapes and trailing comment",
			in:   "X=a\\ b\nY=plain # trailing\nZ=\n",
			want: map[string]string{"X": "a b", "Y": "plain", "Z": ""},
		},
		{
			name: "crlf and later keys win",
			in:   "ID=debian\r\nID=ubuntu\r\n",
			want: map[string]string{"ID": "ubuntu"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseOSRelease([]byte(tt.in)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseMemTotalMiB(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"MemTotal:       16303244 kB\nMemFree:         1234 kB\n", 15921},
		{"MemFree: 1 kB\nMemTotal: 524288 kB\n", 512},
		{"MemTotal: abc kB\n", 0},
		{"MemTotal: 524288 MB\n", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := ParseMemTotalMiB([]byte(tt.in)); got != tt.want {
			t.Errorf("ParseMemTotalMiB(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseSSHPorts(t *testing.T) {
	tests := []struct {
		in   string
		want []int
	}{
		{"port 22\naddressfamily any\nport 2222\n", []int{22, 2222}},
		{"#Port 22\nPort 2200\n  Port=2201\nPORT\t2202 # x\nPort 0\nPort 70000\nPort abc\nPortX 1\n", []int{2200, 2201, 2202}},
		{"", nil},
	}
	for _, tt := range tests {
		if got := ParseSSHPorts([]byte(tt.in)); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseSSHPorts(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestDetectSSHPorts(t *testing.T) {
	tests := []struct {
		name    string
		sshd    string // sshd -T output; "" means sshd not installed
		sshdErr bool
		conn    string
		files   map[string]string
		want    []int
	}{
		{name: "default", want: []int{22}},
		{name: "sshd -T", sshd: "port 2222\nport 22\n", want: []int{22, 2222}},
		{name: "sshd -T fails", sshd: "port 9\n", sshdErr: true, want: []int{22}},
		{name: "ssh connection", conn: "198.51.100.7 51234 203.0.113.5 4422", want: []int{4422}},
		{name: "bad ssh connection", conn: "198.51.100.7 51234 203.0.113.5", want: []int{22}},
		{
			name: "config files",
			files: map[string]string{
				"/etc/ssh/sshd_config":                 "Include /etc/ssh/sshd_config.d/*.conf\n#Port 22\nPort 2022\n",
				"/etc/ssh/sshd_config.d/50-extra.conf": "Port 3022\n",
				"/etc/ssh/sshd_config.d/ignored.txt":   "Port 4022\n",
			},
			want: []int{2022, 3022},
		},
		{
			name:  "union deduplicated",
			sshd:  "port 2022\n",
			conn:  "::1 1 ::1 2022",
			files: map[string]string{"/etc/ssh/sshd_config": "Port 2022\nPort 22\n"},
			want:  []int{22, 2022},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := host.NewFake()
			for p, c := range tt.files {
				f.Files[p] = []byte(c)
			}
			if tt.sshd != "" {
				f.Paths["sshd"] = true
			}
			f.Handler = func(c host.Command) (host.Result, error) {
				if c.Name == "sshd" && strings.Join(c.Args, " ") == "-T" {
					if tt.sshdErr {
						return host.Result{Output: tt.sshd, ExitCode: 255}, &host.ExitError{Command: "sshd -T", ExitCode: 255}
					}
					return host.Result{Output: tt.sshd}, nil
				}
				return host.Result{}, errors.New("unexpected " + c.String())
			}
			env := func(k string) string {
				if k == "SSH_CONNECTION" {
					return tt.conn
				}
				return ""
			}
			if got := detectSSHPorts(context.Background(), f, env); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
			for _, c := range f.Commands {
				if c.Mutates {
					t.Errorf("probe %s must not mutate", c)
				}
			}
		})
	}
}

func TestDetectSSHPortsUsesSbinFallback(t *testing.T) {
	f := host.NewFake()
	f.Files["/usr/sbin/sshd"] = []byte("ELF")
	f.Handler = func(c host.Command) (host.Result, error) {
		if c.Name == "/usr/sbin/sshd" {
			return host.Result{Output: "port 822\n"}, nil
		}
		return host.Result{}, errors.New("unexpected")
	}
	if got := detectSSHPorts(context.Background(), f, func(string) string { return "" }); !reflect.DeepEqual(got, []int{822}) {
		t.Errorf("got %v", got)
	}
}

func TestDetect(t *testing.T) {
	origAddrs, origDisk, origHost := interfaceAddrs, diskFree, osHostname
	t.Cleanup(func() { interfaceAddrs, diskFree, osHostname = origAddrs, origDisk, origHost })
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("203.0.113.5"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("fd00::5"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("2001:db8::5"), Mask: net.CIDRMask(64, 128)},
			&net.IPAddr{IP: net.ParseIP("2001:db8::5")},
			&net.IPAddr{IP: net.ParseIP("2a01:4f8::10")},
		}, nil
	}
	diskFree = func(path string) (int, uint64, error) {
		if path != "/var" {
			t.Errorf("diskFree(%q), want /var", path)
		}
		return 20480, 1000, nil
	}
	osHostname = func() (string, error) { return "fallback", nil }

	f := host.NewFake()
	f.Files["/etc/os-release"] = []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n")
	f.Files["/proc/meminfo"] = []byte("MemTotal:        2048000 kB\n")
	f.Files["/proc/sys/kernel/hostname"] = []byte("relay1\n")
	f.Files["/etc/ssh/sshd_config"] = []byte("Port 2222\n")
	f.Dirs["/run/systemd/system"] = true
	f.Paths["sshd"] = true
	f.Paths["ufw"] = true
	f.Handler = func(c host.Command) (host.Result, error) {
		switch c.String() {
		case "dpkg --print-architecture":
			return host.Result{Output: "arm64\n"}, nil
		case "sshd -T":
			return host.Result{Output: "port 2222\n"}, nil
		case "ufw status":
			return host.Result{Output: "Status: active\n\nTo Action From\n"}, nil
		}
		return host.Result{}, errors.New("unexpected " + c.String())
	}

	start := time.Now()
	got, err := Detect(context.Background(), f, func(k string) string {
		if k == "SSH_CONNECTION" {
			return "198.51.100.1 5000 203.0.113.5 22"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Errorf("Detect took %v", d)
	}
	want := Facts{
		OSID: "ubuntu", VersionID: "24.04", Codename: "noble", PrettyName: "Ubuntu 24.04.1 LTS",
		Arch: "arm64", Hostname: "relay1", MemTotalMiB: 2000, DiskFreeMiB: 20480, Systemd: true,
		IPv6:     []string{"2001:db8::5", "2a01:4f8::10"},
		IPv4:     []string{"203.0.113.5"},
		SSHPorts: []int{22, 2222},
		Firewall: Firewall{Kind: KindUFW, Active: true, Detail: DetailActive},
		EUID:     got.EUID,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Detect =\n%+v\nwant\n%+v", got, want)
	}
	if len(got.Problems()) != 0 {
		t.Errorf("Problems = %v", got.Problems())
	}
	for _, c := range f.Commands {
		if c.Mutates {
			t.Errorf("Detect ran mutating command %s", c)
		}
	}
}

func TestDetectFallbacks(t *testing.T) {
	origAddrs, origDisk, origHost := interfaceAddrs, diskFree, osHostname
	t.Cleanup(func() { interfaceAddrs, diskFree, osHostname = origAddrs, origDisk, origHost })
	interfaceAddrs = func() ([]net.Addr, error) { return nil, errors.New("no interfaces") }
	diskFree = func(string) (int, uint64, error) { return 0, 0, errors.New("no statfs") }
	osHostname = func() (string, error) { return "from-os", nil }

	f := host.NewFake()
	f.Files["/usr/lib/os-release"] = []byte("ID=debian\nVERSION_ID=13\n")
	f.Paths["lsb_release"] = true
	f.Handler = func(c host.Command) (host.Result, error) {
		if c.String() == "lsb_release -cs" {
			return host.Result{Output: "trixie\n"}, nil
		}
		return host.Result{}, errors.New("not found") // dpkg fails too
	}
	got, err := Detect(context.Background(), f, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if got.Codename != "trixie" || got.PrettyName != "debian 13" || got.Hostname != "from-os" {
		t.Errorf("fallbacks: %+v", got)
	}
	if got.Arch == "" || got.DiskFreeMiB != 0 || got.IPv6 != nil || got.MemTotalMiB != 0 || got.Systemd {
		t.Errorf("optional probes: %+v", got)
	}
	if !reflect.DeepEqual(got.SSHPorts, []int{22}) || got.Firewall.Kind != KindNone {
		t.Errorf("defaults: %+v", got)
	}
}

func TestDetectUbuntuCodenameFallback(t *testing.T) {
	f := host.NewFake()
	f.Files["/etc/os-release"] = []byte("ID=ubuntu\nUBUNTU_CODENAME=jammy\n")
	got, err := Detect(context.Background(), f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Codename != "jammy" {
		t.Errorf("Codename = %q", got.Codename)
	}
}

func TestDetectMissingOSRelease(t *testing.T) {
	if _, err := Detect(context.Background(), host.NewFake(), nil); err == nil || !strings.Contains(err.Error(), "os-release") {
		t.Fatalf("err = %v", err)
	}
}

func TestProblems(t *testing.T) {
	ok := Facts{OSID: "debian", Codename: "bookworm", Arch: "amd64", Systemd: true, PrettyName: "Debian 12"}
	tests := []struct {
		name   string
		mutate func(*Facts)
		want   []string // substrings, one per problem
	}{
		{"supported debian", func(*Facts) {}, nil},
		{"supported ubuntu arm64", func(f *Facts) { f.OSID, f.Arch = "ubuntu", "arm64" }, nil},
		{"fedora", func(f *Facts) { f.OSID, f.PrettyName = "fedora", "Fedora 40" }, []string{"unsupported OS Fedora 40"}},
		{"derivative not accepted", func(f *Facts) { f.OSID = "linuxmint" }, []string{"unsupported OS"}},
		{"no codename", func(f *Facts) { f.Codename = "" }, []string{"codename"}},
		{"armhf", func(f *Facts) { f.Arch = "armhf" }, []string{`"armhf"`}},
		{"no systemd", func(f *Facts) { f.Systemd = false }, []string{"systemd"}},
		{
			"everything wrong",
			func(f *Facts) { *f = Facts{} },
			[]string{"unsupported OS unknown", `"unknown"`, "systemd"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ok
			tt.mutate(&f)
			got := f.Problems()
			if len(got) != len(tt.want) {
				t.Fatalf("Problems = %q, want %d", got, len(tt.want))
			}
			for i, sub := range tt.want {
				if !strings.Contains(got[i], sub) {
					t.Errorf("problem %d = %q, want it to contain %q", i, got[i], sub)
				}
			}
		})
	}
}

func TestRequiredRAMMiB(t *testing.T) {
	if RequiredRAMMiB(true) != 1536 || RequiredRAMMiB(false) != 512 {
		t.Error("RequiredRAMMiB mismatch")
	}
}

func TestIsGlobalIPv6(t *testing.T) {
	tests := map[string]bool{
		"2a01:4f8::10":       true,
		"2001:db8::1":        true,
		"fe80::1":            false,
		"fd12:3456::1":       false,
		"fc00::1":            false,
		"::1":                false,
		"::":                 false,
		"ff02::1":            false,
		"::ffff:203.0.113.5": false,
		"203.0.113.5":        false,
	}
	for in, want := range tests {
		if got := IsGlobalIPv6(net.ParseIP(in)); got != want {
			t.Errorf("IsGlobalIPv6(%s) = %v, want %v", in, got, want)
		}
	}
	if IsGlobalIPv6(nil) {
		t.Error("nil IP is not global")
	}
}

func TestIsPublicIPv4(t *testing.T) {
	for in, want := range map[string]bool{
		"203.0.113.5":        true,
		"::ffff:203.0.113.5": true,
		"8.8.8.8":            true,
		"10.0.0.1":           false,
		"172.16.5.1":         false,
		"192.168.1.1":        false,
		"100.64.0.1":         false,
		"100.127.255.254":    false,
		"100.128.0.1":        true,
		"127.0.0.1":          false,
		"169.254.1.1":        false,
		"0.0.0.0":            false,
		"224.0.0.1":          false,
		"2001:db8::1":        false,
	} {
		if got := IsPublicIPv4(net.ParseIP(in)); got != want {
			t.Errorf("IsPublicIPv4(%s) = %v, want %v", in, got, want)
		}
	}
	if IsPublicIPv4(nil) {
		t.Error("nil IP is not public")
	}
}

func TestDiskFreeRoot(t *testing.T) {
	mib, _, err := DiskFree("/")
	if err != nil {
		t.Skip("statfs unavailable:", err)
	}
	if mib <= 0 {
		t.Errorf("DiskFree(/) = %d MiB", mib)
	}
}
