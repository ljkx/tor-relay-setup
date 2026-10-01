package tui

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

// ansiRE matches CSI and OSC escape sequences.
var ansiRE = regexp.MustCompile("\x1b\\[[0-9;:?<=>]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)")

func strip(s string) string { return ansiRE.ReplaceAllString(s, "") }

func famID(c string) string { return strings.Repeat(c, 43) }

func testFacts() system.Facts {
	return system.Facts{
		OSID: "debian", VersionID: "12", Codename: "bookworm", PrettyName: "Debian GNU/Linux 12 (bookworm)",
		Arch: "amd64", Hostname: "old-host", MemTotalMiB: 4096, DiskFreeMiB: 20000, Systemd: true,
		SSHPorts: []int{22, 2222}, Firewall: system.Firewall{Kind: system.KindUFW, Active: true, Detail: system.DetailActive},
	}
}

func testSetup() config.Setup {
	s := config.Default()
	s.Relay.Nickname = "TestRelay"
	s.Relay.Contact = "tor-ops@example.org"
	s.Bandwidth.MonthlyQuota = "10TB"
	return s
}

// testApp returns an App whose background checks have finished, sized
// like a roomy terminal. Nothing touches a real terminal or machine.
func testApp() *App {
	a := newApp(Options{Host: host.NewFake(), Version: "vtest"}, nil)
	a.checks.Facts, a.checks.FactsReady = testFacts(), true
	a.width, a.height = 120, 40
	return a
}

func TestStripHelper(t *testing.T) {
	t.Parallel()
	styled := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true).Render("hi")
	if got := strip(styled); got != "hi" {
		t.Fatalf("strip(%q) = %q", styled, got)
	}
}

func TestCompactCommand(t *testing.T) {
	t.Parallel()
	apt := host.Command{
		Name: "apt-get",
		Args: []string{"-q", "-y", "-o", "APT::Status-Fd=3", "-o", "DPkg::Lock::Timeout=300",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "install", "tor", "nyx"},
		Env: []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "APT_LISTCHANGES_FRONTEND=none"},
	}.String()
	tests := []struct{ name, in, want string }{
		{"apt install", apt, "apt-get install tor nyx"},
		{"plain command", "systemctl restart tor@default", "systemctl restart tor@default"},
		{"empty", "", ""},
		{"extra spaces collapse", "  tor   --version  ", "tor --version"},
		{"lower-case assignment is an argument", "a=b cmd", "a=b cmd"},
		{"assignment after the command stays", "env FOO=bar tor", "env FOO=bar tor"},
		{"trailing -o is kept", "cmd -o", "cmd -o"},
		{"-q and -y anywhere", "apt-get update -q -y", "apt-get update"},
		{"quoted args survive", "ufw allow 9001/tcp comment 'Tor relay ORPort'", "ufw allow 9001/tcp comment 'Tor relay ORPort'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := compactCommand(tt.in); got != tt.want {
				t.Errorf("compactCommand(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello w…"},
		{"hello world", 4, "hel…"},
		{"hello world", 3, "hello world"}, // too narrow to truncate usefully
		{"hello world", 0, "hello world"},
		{"äöüßäöüß", 5, "äöüß…"},
		{"", 5, ""},
	}
	for _, tt := range tests {
		if got := truncate(tt.in, tt.max); got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
		if tt.max >= 4 && lipgloss.Width(truncate(tt.in, tt.max)) > tt.max {
			t.Errorf("truncate(%q, %d) is wider than %d", tt.in, tt.max, tt.max)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0ms"},
		{250 * time.Millisecond, "250ms"},
		{999 * time.Millisecond, "999ms"},
		{time.Second, "1.0s"},
		{1500 * time.Millisecond, "1.5s"},
		{59*time.Second + 940*time.Millisecond, "59.9s"},
		{time.Minute, "1m00s"},
		{65 * time.Second, "1m05s"},
		{61*time.Minute + 9*time.Second, "61m09s"},
	}
	for _, tt := range tests {
		if got := formatDuration(tt.d); got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestSmallHelpers(t *testing.T) {
	t.Parallel()
	if atoi(" 42 ") != 42 || atoi("x") != 0 || atoi("") != 0 || atoi("-3") != -3 {
		t.Error("atoi mishandles input")
	}
	if itoa(9001) != "9001" {
		t.Error("itoa")
	}
	if joinOr(nil, "none") != "none" || joinOr([]string{"a", "b"}, "none") != "a, b" {
		t.Error("joinOr")
	}
	if yesNo(true) != "yes" || yesNo(false) != "no" {
		t.Error("yesNo")
	}
	if program("v1.2.3") != "tor-relay-setup v1.2.3" {
		t.Error("program")
	}
	for _, c := range []struct{ v, lo, hi, want int }{{5, 1, 10, 5}, {-1, 0, 10, 0}, {11, 0, 10, 10}} {
		if got := clamp(c.v, c.lo, c.hi); got != c.want {
			t.Errorf("clamp(%d, %d, %d) = %d", c.v, c.lo, c.hi, got)
		}
	}
	if got := trimHeader("a\nb\nc\n\nd", 3); got != "d" {
		t.Errorf("trimHeader = %q", got)
	}
	if got := trimHeader("a\nb", 3); got != "a\nb" {
		t.Errorf("trimHeader(short) = %q", got)
	}
	if got := humanBandwidth(1_250_000); got != "10.0 Mbit/s" {
		t.Errorf("humanBandwidth = %q", got)
	}
}

func TestHighlightTorrc(t *testing.T) {
	t.Parallel()
	th := NewTheme(true)
	in := "# A comment\n\nNickname Relay\nSafeLogging\nContactInfo \"email:ops[]example.org ciissversion:3\"\n"
	got := strip(highlightTorrc(th, in, 200))
	want := strings.TrimRight(in, "\n")
	if got != want {
		t.Errorf("highlightTorrc text =\n%q\nwant\n%q", got, want)
	}

	got = strip(highlightTorrc(th, "# a very long comment line here\nContactInfo abcdefghijklmnop\n", 20))
	lines := strings.Split(got, "\n")
	if lines[0] != "# a very long comme…" {
		t.Errorf("comment line = %q", lines[0])
	}
	// "ContactInfo " leaves 8 columns for the value.
	if lines[1] != "ContactInfo abcdefg…" {
		t.Errorf("directive line = %q", lines[1])
	}
	for _, l := range lines {
		if lipgloss.Width(l) > 20 {
			t.Errorf("line %q wider than 20", l)
		}
	}
}

func TestKV(t *testing.T) {
	t.Parallel()
	got := strip(kv(NewTheme(false), [][2]string{{"a", "1"}, {"long", "2"}, {"mid", ""}}))
	want := "a     1\nlong  2\nmid   "
	if got != want {
		t.Errorf("kv =\n%q\nwant\n%q", got, want)
	}
	if kv(NewTheme(false), nil) != "" {
		t.Error("kv(nil) should be empty")
	}
}

func TestStepper(t *testing.T) {
	t.Parallel()
	th := NewTheme(true)
	steps := []string{"Relay", "Contact", "Network", "Family", "Bandwidth", "System", "Review"}

	wide := strip(stepper(th, 200, steps, 2))
	for _, want := range []string{"✓ Relay", "✓ Contact", "● Network", "○ Family", "○ Review", " ─ "} {
		if !strings.Contains(wide, want) {
			t.Errorf("wide stepper %q lacks %q", wide, want)
		}
	}
	if lipgloss.Width(wide) > 200 {
		t.Errorf("wide stepper overflows: %d", lipgloss.Width(wide))
	}

	for _, width := range []int{40, 20, 0} {
		narrow := strip(stepper(th, width, steps, 2))
		if narrow != " Step 3/7 · Network" {
			t.Errorf("stepper(width %d) = %q, want the compact form", width, narrow)
		}
	}
	if got := strip(stepper(th, 20, steps, 6)); got != " Step 7/7 · Review" {
		t.Errorf("last step compact = %q", got)
	}
}

func TestHeaderRuleKeyHelpStatusIcon(t *testing.T) {
	t.Parallel()
	th := NewTheme(true)
	h := header(th, 100, "vtest", "old-host")
	if lipgloss.Width(h) != 100 {
		t.Errorf("header width = %d, want 100", lipgloss.Width(h))
	}
	if s := strip(h); !strings.HasPrefix(s, " ◆ tor-relay-setup vtest") || !strings.HasSuffix(s, "old-host ") {
		t.Errorf("header = %q", s)
	}
	if s := strip(header(th, 10, "vtest", "old-host")); s != " ◆ tor-relay-setup vtest" {
		t.Errorf("narrow header = %q, want only the brand", s)
	}

	if rule(th, 0) != "" || strip(rule(th, 3)) != "───" {
		t.Error("rule")
	}
	if got := strip(keyHelp(th, "enter", "next", "q", "quit", "dangling")); got != " enter next  ·  q quit" {
		t.Errorf("keyHelp = %q", got)
	}
	for _, c := range []struct {
		ok, warn bool
		want     string
	}{{true, false, "✓"}, {true, true, "✓"}, {false, true, "!"}, {false, false, "✗"}} {
		if got := strip(statusIcon(th, c.ok, c.warn)); got != c.want {
			t.Errorf("statusIcon(%v, %v) = %q, want %q", c.ok, c.warn, got, c.want)
		}
	}
	p := strip(panel(th, "Title", "body text", 30, false))
	if !strings.Contains(p, "Title") || !strings.Contains(p, "body text") || !strings.HasPrefix(p, "╭") {
		t.Errorf("panel =\n%s", p)
	}
}

func TestBorderStretch(t *testing.T) {
	t.Parallel()
	th := NewTheme(true)
	short := panel(th, "A", "one", 20, false)
	tall := panel(th, "B", "one\ntwo\nthree\nfour", 20, false)
	row := sideBySide(short, tall)
	if lipgloss.Height(row) != lipgloss.Height(tall) {
		t.Errorf("sideBySide height = %d, want %d", lipgloss.Height(row), lipgloss.Height(tall))
	}
	lines := strings.Split(strip(row), "\n")
	last := lines[len(lines)-1]
	if strings.Count(last, "╰") != 2 {
		t.Errorf("both panels should end on the last row, got %q", last)
	}
	if got := strip(stretch(short, lipgloss.Height(short)+2)); strings.Count(got, "\n") != lipgloss.Height(short)+1 {
		t.Errorf("stretch did not add two lines:\n%s", got)
	}
	if got := stretch("x", 5); got != "x" {
		t.Errorf("stretch of a single line = %q", got)
	}
	if got := borderLine("╰──╯", 4); got != "│  │" {
		t.Errorf("borderLine = %q", got)
	}
	if got := borderLine("╰──╯", 9); got != strings.Repeat(" ", 9) {
		t.Errorf("borderLine with mismatched width = %q", got)
	}
}
