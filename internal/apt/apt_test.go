package apt

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

func TestParseStatusLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want Progress
		ok   bool
	}{
		{
			"dlstatus start",
			"dlstatus:1:0:Retrieving file 1 of 3",
			Progress{Phase: "download", Percent: 0, Detail: "Retrieving file 1 of 3"}, true,
		},
		{
			"dlstatus fractional",
			"dlstatus:3:66.6667:Retrieving file 3 of 3",
			Progress{Phase: "download", Percent: 66.6667, Detail: "Retrieving file 3 of 3"}, true,
		},
		{
			"dlstatus real apt 2.7 sample",
			"dlstatus:1:100.0000:Retrieving file 1 of 1",
			Progress{Phase: "download", Percent: 100, Detail: "Retrieving file 1 of 1"}, true,
		},
		{
			"dlstatus with CRLF",
			"dlstatus:1:9.0909:Retrieving file 1 of 11\r\n",
			Progress{Phase: "download", Percent: 9.0909, Detail: "Retrieving file 1 of 11"}, true,
		},
		{
			"pmstatus plain",
			"pmstatus:tor:12.5:Preparing tor (amd64)",
			Progress{Phase: "install", Percent: 12.5, Package: "tor", Detail: "Preparing tor (amd64)"}, true,
		},
		{
			"pmstatus arch suffix",
			"pmstatus:tor:amd64:25:Unpacking tor:amd64 (0.4.9.13-1~noble+1)",
			Progress{Phase: "install", Percent: 25, Package: "tor:amd64", Detail: "Unpacking tor:amd64 (0.4.9.13-1~noble+1)"}, true,
		},
		{
			"pmstatus colons in description",
			"pmstatus:libssl3t64:amd64:62.5:Setting up libssl3t64:amd64 (3.0.13): done: 1:2",
			Progress{Phase: "install", Percent: 62.5, Package: "libssl3t64:amd64", Detail: "Setting up libssl3t64:amd64 (3.0.13): done: 1:2"}, true,
		},
		{
			"pmstatus dpkg-exec",
			"pmstatus:dpkg-exec:0:Running dpkg",
			Progress{Phase: "install", Percent: 0, Package: "dpkg-exec", Detail: "Running dpkg"}, true,
		},
		{
			"pmstatus numeric package name",
			"pmstatus:0ad:amd64:50:Installing 0ad:amd64",
			Progress{Phase: "install", Percent: 50, Package: "0ad:amd64", Detail: "Installing 0ad:amd64"}, true,
		},
		{
			"pmstatus description starting with a number",
			"pmstatus:tor:90:3 triggers pending",
			Progress{Phase: "install", Percent: 90, Package: "tor", Detail: "3 triggers pending"}, true,
		},
		{
			"pmstatus without description",
			"pmstatus:tor:100",
			Progress{Phase: "install", Percent: 100, Package: "tor"}, true,
		},
		{
			"percent clamped",
			"pmstatus:tor:150:Weird",
			Progress{Phase: "install", Percent: 100, Package: "tor", Detail: "Weird"}, true,
		},
		{"pmerror", "pmerror:/var/cache/apt/archives/tor_0.4.9.13_amd64.deb:40:trying to overwrite '/usr/bin/tor'", Progress{}, false},
		{"pmconffile", "pmconffile:/etc/tor/torrc:80:'/etc/tor/torrc' '/etc/tor/torrc.dpkg-new' 1 1", Progress{}, false},
		{"media-change", "media-change:Debian 12:/dev/cdrom", Progress{}, false},
		{"garbage", "Reading package lists...", Progress{}, false},
		{"empty", "", Progress{}, false},
		{"no percent", "pmstatus:tor:amd64", Progress{}, false},
		{"empty package", "pmstatus::50:Nothing", Progress{}, false},
		{"NaN is not a percent", "pmstatus:tor:NaN:x", Progress{}, false},
		{"signed is not a percent", "pmstatus:tor:-5:x", Progress{}, false},
		{"prefix only", "dlstatus:", Progress{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseStatusLine(tt.line)
			if ok != tt.ok || got != tt.want {
				t.Errorf("ParseStatusLine(%q) = %+v, %v; want %+v, %v", tt.line, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestParseStatusError(t *testing.T) {
	tests := []struct {
		line, pkg, msg string
		ok             bool
	}{
		{
			"pmerror:/var/cache/apt/archives/tor_0.4.9.13-1_amd64.deb:40:trying to overwrite '/usr/bin/tor', which is also in package evil 1.0",
			"/var/cache/apt/archives/tor_0.4.9.13-1_amd64.deb", "trying to overwrite '/usr/bin/tor', which is also in package evil 1.0", true,
		},
		{
			"pmerror:tor:amd64:75:installed tor package post-installation script subprocess returned error exit status 1",
			"tor:amd64", "installed tor package post-installation script subprocess returned error exit status 1", true,
		},
		{"pmstatus:tor:50:Installing", "", "", false},
		{"pmerror:", "", "", false},
		{"garbage", "", "", false},
	}
	for _, tt := range tests {
		pkg, msg, ok := ParseStatusError(tt.line)
		if pkg != tt.pkg || msg != tt.msg || ok != tt.ok {
			t.Errorf("ParseStatusError(%q) = %q, %q, %v; want %q, %q, %v", tt.line, pkg, msg, ok, tt.pkg, tt.msg, tt.ok)
		}
	}
}

var wantEnv = []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "APT_LISTCHANGES_FRONTEND=none"}

func baseArgs(lock string) []string {
	return []string{
		"-q", "-y",
		"-o", "APT::Status-Fd=3",
		"-o", "DPkg::Lock::Timeout=" + lock,
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
	}
}

func TestAptGetCommands(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		lock     time.Duration
		run      func(Client) error
		wantArgs []string
	}{
		{
			"update default lock",
			0,
			func(c Client) error { return c.Update(ctx, nil, nil) },
			append(baseArgs("300"), "update"),
		},
		{
			"install custom lock",
			90 * time.Second,
			func(c Client) error { return c.Install(ctx, []string{"tor", "deb.torproject.org-keyring"}, nil, nil) },
			append(baseArgs("90"), "install", "tor", "deb.torproject.org-keyring"),
		},
		{
			"purge sub-second lock rounds up",
			1500 * time.Millisecond,
			func(c Client) error { return c.Purge(ctx, []string{"nyx", "libstdc++6"}, nil) },
			append(baseArgs("2"), "purge", "nyx", "libstdc++6"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := host.NewFake()
			if err := tt.run(Client{Host: f, LockTimeout: tt.lock}); err != nil {
				t.Fatal(err)
			}
			if len(f.Commands) != 1 {
				t.Fatalf("ran %d commands: %v", len(f.Commands), f.CommandLines())
			}
			c := f.Commands[0]
			if c.Name != "apt-get" {
				t.Errorf("Name = %q, want apt-get", c.Name)
			}
			if !reflect.DeepEqual(c.Args, tt.wantArgs) {
				t.Errorf("Args =\n%q\nwant\n%q", c.Args, tt.wantArgs)
			}
			if !reflect.DeepEqual(c.Env, wantEnv) {
				t.Errorf("Env = %q, want %q", c.Env, wantEnv)
			}
			if !c.Mutates {
				t.Error("Mutates = false, want true")
			}
			if c.StatusFD == nil {
				t.Error("StatusFD not wired")
			}
		})
	}
}

func TestEmptyPackageListIsNoOp(t *testing.T) {
	f := host.NewFake()
	c := Client{Host: f}
	if err := c.Install(context.Background(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Purge(context.Background(), []string{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.Commands) != 0 {
		t.Errorf("ran %v, want nothing", f.CommandLines())
	}
}

func TestInvalidPackageNames(t *testing.T) {
	bad := []string{"", "-o", "--allow-unauthenticated", "Tor", "t", "tor;rm", "tor amd64", "tor:amd64", "../tor", "tor\n"}
	ctx := context.Background()
	for _, name := range bad {
		f := host.NewFake()
		c := Client{Host: f}
		if err := c.Install(ctx, []string{"tor", name}, nil, nil); err == nil {
			t.Errorf("Install accepted %q", name)
		}
		if err := c.Purge(ctx, []string{name}, nil); err == nil {
			t.Errorf("Purge accepted %q", name)
		}
		if _, err := c.Policy(ctx, name); err == nil {
			t.Errorf("Policy accepted %q", name)
		}
		if _, err := c.Installed(ctx, name); err == nil {
			t.Errorf("Installed accepted %q", name)
		}
		if len(f.Commands) != 0 {
			t.Errorf("%q: ran %v", name, f.CommandLines())
		}
	}
}

func TestProgressAndOutputPlumbing(t *testing.T) {
	f := host.NewFake()
	f.Handler = func(c host.Command) (host.Result, error) {
		for _, l := range []string{
			"dlstatus:1:0:Retrieving file 1 of 2",
			"dlstatus:2:50:Retrieving file 2 of 2",
			"pmstatus:dpkg-exec:0:Running dpkg",
			"pmconffile:/etc/tor/torrc:10:'a' 'b' 1 1",
			"pmstatus:tor:amd64:40:Unpacking tor:amd64 (0.4.9.13)",
			"pmstatus:tor:amd64:100:Installed tor:amd64 (0.4.9.13)",
		} {
			c.StatusFD(l)
		}
		return host.Result{Output: "Reading package lists...\nSetting up tor (0.4.9.13) ...\n"}, nil
	}
	var progress []Progress
	var lines []string
	err := Client{Host: f}.Install(context.Background(), []string{"tor"},
		func(p Progress) { progress = append(progress, p) },
		func(l string) { lines = append(lines, l) })
	if err != nil {
		t.Fatal(err)
	}
	want := []Progress{
		{Phase: "download", Percent: 0, Detail: "Retrieving file 1 of 2"},
		{Phase: "download", Percent: 50, Detail: "Retrieving file 2 of 2"},
		{Phase: "install", Percent: 0, Package: "dpkg-exec", Detail: "Running dpkg"},
		{Phase: "install", Percent: 40, Package: "tor:amd64", Detail: "Unpacking tor:amd64 (0.4.9.13)"},
		{Phase: "install", Percent: 100, Package: "tor:amd64", Detail: "Installed tor:amd64 (0.4.9.13)"},
	}
	if !reflect.DeepEqual(progress, want) {
		t.Errorf("progress =\n%+v\nwant\n%+v", progress, want)
	}
	wantLines := []string{"Reading package lists...", "Setting up tor (0.4.9.13) ..."}
	if !reflect.DeepEqual(lines, wantLines) {
		t.Errorf("lines = %q, want %q", lines, wantLines)
	}
}

func TestNilCallbacksAreSafe(t *testing.T) {
	f := host.NewFake()
	f.Handler = func(c host.Command) (host.Result, error) {
		c.StatusFD("dlstatus:1:10:Retrieving file 1 of 1")
		return host.Result{Output: "Hit:1 http://deb.debian.org/debian bookworm InRelease\n"}, nil
	}
	if err := (Client{Host: f}).Update(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestErrorHints(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		wantHint string
	}{
		{"lock", "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 (unattended-upgr)", "holds the dpkg lock"},
		{"frontend lock", "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?", "holds the dpkg lock"},
		{"interrupted", "E: dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem.", "run: sudo dpkg --configure -a"},
		{"disk full", "E: Write error - write (28: No space left on device)", "disk is full"},
		{"unknown", "E: Unable to locate package tor", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := host.NewFake()
			f.Handler = func(c host.Command) (host.Result, error) {
				res := host.Result{Output: tt.output + "\n", ExitCode: 100}
				return res, &host.ExitError{Command: c.String(), ExitCode: 100, Output: res.Output}
			}
			err := Client{Host: f}.Install(context.Background(), []string{"tor"}, nil, nil)
			var aptErr *Error
			if !errors.As(err, &aptErr) {
				t.Fatalf("error %v (%T) is not *apt.Error", err, err)
			}
			if aptErr.Op != "install" {
				t.Errorf("Op = %q, want install", aptErr.Op)
			}
			var exitErr *host.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode != 100 {
				t.Errorf("error does not unwrap to the *host.ExitError: %v", err)
			}
			if tt.wantHint == "" {
				if aptErr.Hint != "" || strings.Contains(err.Error(), "hint:") {
					t.Errorf("unexpected hint in %q", err)
				}
				return
			}
			if !strings.Contains(aptErr.Hint, tt.wantHint) {
				t.Errorf("Hint = %q, want it to contain %q", aptErr.Hint, tt.wantHint)
			}
			if !strings.Contains(err.Error(), "hint: "+aptErr.Hint) {
				t.Errorf("Error() = %q does not include the hint", err)
			}
		})
	}
}

func TestDpkgErrorsCollected(t *testing.T) {
	f := host.NewFake()
	f.Handler = func(c host.Command) (host.Result, error) {
		c.StatusFD("pmstatus:tor:amd64:50:Setting up tor:amd64")
		c.StatusFD("pmerror:tor:amd64:75:installed tor package post-installation script subprocess returned error exit status 1")
		return host.Result{ExitCode: 100}, &host.ExitError{Command: c.String(), ExitCode: 100, Output: "E: Sub-process /usr/bin/dpkg returned an error code (1)\n"}
	}
	err := Client{Host: f}.Install(context.Background(), []string{"tor"}, nil, nil)
	var aptErr *Error
	if !errors.As(err, &aptErr) {
		t.Fatalf("error %v is not *apt.Error", err)
	}
	want := []string{"tor:amd64: installed tor package post-installation script subprocess returned error exit status 1"}
	if !reflect.DeepEqual(aptErr.DpkgErrors, want) {
		t.Errorf("DpkgErrors = %q, want %q", aptErr.DpkgErrors, want)
	}
	if !strings.Contains(err.Error(), "dpkg: "+want[0]) {
		t.Errorf("Error() = %q does not include the dpkg error", err)
	}
}

func TestContextErrorWrapped(t *testing.T) {
	f := host.NewFake()
	f.Handler = func(c host.Command) (host.Result, error) { return host.Result{}, context.Canceled }
	err := Client{Host: f}.Update(context.Background(), nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not wrap context.Canceled", err)
	}
}

func TestDryRunSkipsMutations(t *testing.T) {
	f := host.NewFake()
	f.Dry = true
	f.Handler = func(c host.Command) (host.Result, error) {
		t.Errorf("handler called for %s in dry run", c)
		return host.Result{}, nil
	}
	if err := (Client{Host: f}).Install(context.Background(), []string{"tor"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !f.Ran("apt-get", "install", "tor") {
		t.Errorf("dry-run command not recorded: %v", f.CommandLines())
	}
}

const policyTor = `tor:
  Installed: (none)
  Candidate: 0.4.9.13-1~noble+1
  Version table:
     0.4.9.13-1~noble+1 500
        500 https://deb.torproject.org/torproject.org noble/main amd64 Packages
`

const policyNone = `deb.torproject.org-keyring:
  Installed: (none)
  Candidate: (none)
  Version table:
`

func TestPolicyAndCandidateAvailable(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		err     error
		want    bool
		wantErr bool
	}{
		{"candidate", policyTor, nil, true, false},
		{"none", policyNone, nil, false, false},
		{"unknown package prints nothing", "", nil, false, false},
		{"apt-cache fails", "", &host.ExitError{Command: "apt-cache policy tor", ExitCode: 100}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := host.NewFake()
			f.Handler = func(c host.Command) (host.Result, error) { return host.Result{Output: tt.output}, tt.err }
			got, err := Client{Host: f}.CandidateAvailable(context.Background(), "tor")
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Errorf("CandidateAvailable() = %v, %v; want %v, err=%v", got, err, tt.want, tt.wantErr)
			}
			c := f.Commands[0]
			if c.Name != "apt-cache" || !reflect.DeepEqual(c.Args, []string{"policy", "tor"}) || c.Mutates {
				t.Errorf("command = %s (Mutates=%v), want read-only apt-cache policy tor", c, c.Mutates)
			}
			if !reflect.DeepEqual(c.Env, []string{"LC_ALL=C"}) {
				t.Errorf("Env = %q, want LC_ALL=C", c.Env)
			}
		})
	}
}

func TestPolicyReturnsOutput(t *testing.T) {
	f := host.NewFake()
	f.Handler = func(host.Command) (host.Result, error) { return host.Result{Output: policyTor}, nil }
	got, err := Client{Host: f}.Policy(context.Background(), "tor")
	if err != nil || got != policyTor {
		t.Errorf("Policy() = %q, %v", got, err)
	}
}

func TestParseCandidate(t *testing.T) {
	for in, want := range map[string]string{
		policyTor:              "0.4.9.13-1~noble+1",
		policyNone:             "(none)",
		"":                     "",
		"tor:\n  Candidate:\n": "",
	} {
		if got := ParseCandidate(in); got != want {
			t.Errorf("ParseCandidate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInstalled(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		err     error
		want    bool
		wantErr bool
	}{
		{"installed", "install ok installed", nil, true, false},
		{"installed with newline", "install ok installed\n", nil, true, false},
		{"held", "hold ok installed", nil, true, false},
		{"config files only", "deinstall ok config-files", nil, false, false},
		{"half configured", "install ok half-configured", nil, false, false},
		{"not installed", "unknown ok not-installed", nil, false, false},
		{"unknown package", "dpkg-query: no packages found matching nosuchpkg\n", &host.ExitError{Command: "dpkg-query", ExitCode: 1}, false, false},
		{"dpkg-query broken", "dpkg-query: error: parsing file '/var/lib/dpkg/status'", &host.ExitError{Command: "dpkg-query", ExitCode: 2}, false, true},
		{"other failure", "", errors.New("exec: dpkg-query not found"), false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := host.NewFake()
			f.Handler = func(c host.Command) (host.Result, error) { return host.Result{Output: tt.output}, tt.err }
			got, err := Client{Host: f}.Installed(context.Background(), "tor")
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Errorf("Installed() = %v, %v; want %v, err=%v", got, err, tt.want, tt.wantErr)
			}
			c := f.Commands[0]
			if c.Name != "dpkg-query" || !reflect.DeepEqual(c.Args, []string{"-W", "-f=${Status}", "tor"}) || c.Mutates {
				t.Errorf("command = %s (Mutates=%v)", c, c.Mutates)
			}
		})
	}
}
