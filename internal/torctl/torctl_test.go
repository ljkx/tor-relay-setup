package torctl

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// collect gathers output lines and progress details.
type collect struct{ lines, progress []string }

func (c *collect) out(s string)             { c.lines = append(c.lines, s) }
func (c *collect) prog(_ float64, d string) { c.progress = append(c.progress, d) }
func fail(code int) (host.Result, error) {
	return host.Result{ExitCode: code}, &host.ExitError{ExitCode: code}
}
func ok(output string) (host.Result, error) { return host.Result{Output: output}, nil }
func quick(h host.Host) Ops {
	return Ops{Host: h, ActiveTimeout: 50 * time.Millisecond, Poll: time.Millisecond}
}
func ran(f *host.Fake, s ...string) bool { return f.Ran(s...) }
func lines(f *host.Fake) string          { return strings.Join(f.CommandLines(), "\n") }
func newFake(h func(host.Command) (host.Result, error)) *host.Fake {
	f := host.NewFake()
	f.Handler = h
	return f
}

func TestRestartWaitsForTheService(t *testing.T) {
	inactive := 3
	f := newFake(func(c host.Command) (host.Result, error) {
		switch {
		case c.Name == "systemctl" && c.Args[0] == "is-active":
			if inactive > 0 {
				inactive--
				return fail(3)
			}
		case c.Name == "journalctl":
			return ok("2026-10-01T12:00:00+0000 relay Tor[1]: [warn] Unable to read family key\n2026-10-01T12:00:00+0000 relay Tor[1]: [warn] something else\n")
		}
		return ok("")
	})
	var c collect
	summary, err := quick(f).Restart(context.Background(), c.out, c.prog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(summary, "Tor restarted.") || inactive != 0 {
		t.Errorf("summary %q, inactive %d", summary, inactive)
	}
	if !ran(f, "systemctl restart tor@default") || !ran(f, "journalctl -u tor@default", "-p warning") {
		t.Errorf("commands:\n%s", lines(f))
	}
	if len(c.lines) != 1 || !strings.Contains(c.lines[0], "family key") {
		t.Errorf("family warnings = %q", c.lines)
	}
	if strings.Join(c.progress, ",") != "restarting,waiting for the service" {
		t.Errorf("progress = %q", c.progress)
	}
}

func TestRestartTimesOut(t *testing.T) {
	f := newFake(func(c host.Command) (host.Result, error) {
		if c.Name == "systemctl" && c.Args[0] == "is-active" {
			return fail(3)
		}
		return ok("")
	})
	var c collect
	o := quick(f)
	o.Unit = "tor@second"
	if _, err := o.Restart(context.Background(), c.out, c.prog); err == nil || err.Error() != "tor@second did not come back; check the log" {
		t.Errorf("err = %v", err)
	}
	if !ran(f, "systemctl restart tor@second") {
		t.Errorf("unit not used:\n%s", lines(f))
	}
	// A failing restart is returned as is.
	f.Handler = func(host.Command) (host.Result, error) { return fail(1) }
	if _, err := o.Restart(context.Background(), c.out, c.prog); err == nil {
		t.Error("restart failure swallowed")
	}
}

func TestRestartDryRun(t *testing.T) {
	f := newFake(nil)
	f.Dry = true
	var c collect
	summary, err := quick(f).Restart(context.Background(), c.out, c.prog)
	if err != nil || summary != "Dry run: Tor was not restarted." {
		t.Errorf("%q, %v", summary, err)
	}
	if ran(f, "is-active") {
		t.Error("a dry run waited for the service")
	}
}

func TestReloadVerifiesFirst(t *testing.T) {
	f := newFake(func(c host.Command) (host.Result, error) {
		if c.Name == "tor" {
			return host.Result{ExitCode: 1, Output: "[warn] Failed to parse/validate config: Unknown option 'Nicknam'.\n"}, &host.ExitError{ExitCode: 1}
		}
		return ok("")
	})
	f.Paths["tor"] = true
	var c collect
	if _, err := quick(f).Reload(context.Background(), c.out, c.prog); err == nil || !strings.Contains(err.Error(), "torrc is invalid, not reloading") {
		t.Errorf("err = %v", err)
	}
	if ran(f, "systemctl reload") {
		t.Error("reloaded an invalid torrc")
	}
	f.Handler = nil
	summary, err := quick(f).Reload(context.Background(), c.out, c.prog)
	if err != nil || summary != "Tor re-read its configuration." || !ran(f, "tor -f /etc/tor/torrc --verify-config") || !ran(f, "systemctl reload tor@default") {
		t.Errorf("%q, %v\n%s", summary, err, lines(f))
	}
}

const policy = `tor:
  Installed: 0.4.9.2-1~bookworm+1
  Candidate: 0.4.9.3-1~bookworm+1
  Version table:
     0.4.9.3-1~bookworm+1 500
        500 https://deb.torproject.org/torproject.org bookworm/main amd64 Packages
 *** 0.4.9.2-1~bookworm+1 100
        100 /var/lib/dpkg/status
`

func TestUpdate(t *testing.T) {
	f := newFake(func(c host.Command) (host.Result, error) {
		switch c.Name {
		case "apt-cache":
			return ok(policy)
		case "tor":
			return ok("Tor version 0.4.9.3.\n")
		}
		return ok("")
	})
	var c collect
	summary, err := quick(f).Update(context.Background(), c.out, c.prog)
	if err != nil || summary != "tor 0.4.9.3 is installed." {
		t.Errorf("%q, %v", summary, err)
	}
	if !ran(f, "apt-get", "update") || !ran(f, "apt-get", "install", "tor deb.torproject.org-keyring") {
		t.Errorf("commands:\n%s", lines(f))
	}
	// A candidate from another origin is refused before installing.
	f2 := newFake(func(c host.Command) (host.Result, error) {
		if c.Name == "apt-cache" {
			return ok(strings.ReplaceAll(policy, "https://deb.torproject.org/torproject.org", "http://deb.debian.org/debian"))
		}
		return ok("")
	})
	if _, err := quick(f2).Update(context.Background(), c.out, c.prog); err == nil || !strings.Contains(err.Error(), "does not come from deb.torproject.org") {
		t.Errorf("err = %v", err)
	}
	if ran(f2, "install") {
		t.Error("installed from the wrong origin")
	}
}
