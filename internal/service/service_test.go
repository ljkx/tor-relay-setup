package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

func TestControlCommands(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		unit string
		call func(Tor) error
		want string
	}{
		{"enable", "", func(t Tor) error { return t.Enable(ctx) }, "systemctl enable tor@default"},
		{"restart", "", func(t Tor) error { return t.Restart(ctx) }, "systemctl restart tor@default"},
		{"reload", "", func(t Tor) error { return t.Reload(ctx) }, "systemctl reload tor@default"},
		{"stop", "", func(t Tor) error { return t.Stop(ctx) }, "systemctl stop tor@default"},
		{"disable", "", func(t Tor) error { return t.Disable(ctx) }, "systemctl disable tor@default"},
		{"start custom unit", "tor@relay2", func(t Tor) error { return t.Start(ctx) }, "systemctl start tor@relay2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := host.NewFake()
			if err := tt.call(Tor{Host: f, Unit: tt.unit}); err != nil {
				t.Fatal(err)
			}
			if got := f.CommandLines(); !reflect.DeepEqual(got, []string{tt.want}) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if !f.Commands[0].Mutates {
				t.Error("control command must be Mutates")
			}
		})
	}

	f := host.NewFake()
	f.Handler = func(c host.Command) (host.Result, error) {
		return host.Result{ExitCode: 1}, &host.ExitError{Command: c.String(), ExitCode: 1}
	}
	if err := (Tor{Host: f}).Restart(ctx); err == nil {
		t.Error("Restart swallowed the error")
	}
}

func TestActive(t *testing.T) {
	for _, active := range []bool{true, false} {
		f := host.NewFake()
		f.Handler = func(c host.Command) (host.Result, error) {
			if active {
				return host.Result{}, nil
			}
			return host.Result{ExitCode: 3}, &host.ExitError{Command: c.String(), ExitCode: 3}
		}
		if got := (Tor{Host: f}).Active(context.Background()); got != active {
			t.Errorf("Active = %v, want %v", got, active)
		}
		if f.Commands[0].Mutates || f.CommandLines()[0] != "systemctl is-active --quiet tor@default" {
			t.Errorf("command %+v", f.Commands[0])
		}
	}
	// Read-only: still runs on a dry-run host.
	f := host.NewFake()
	f.Dry = true
	f.Handler = func(host.Command) (host.Result, error) { return host.Result{}, errors.New("inactive") }
	if (Tor{Host: f}).Active(context.Background()) {
		t.Error("dry run must still query systemctl")
	}
}

func TestJournal(t *testing.T) {
	tests := []struct {
		since    string
		lines    int
		priority string
		want     string
	}{
		{"", 0, "", "journalctl -u tor@default --no-pager -o short-iso"},
		{"5 minutes ago", 100, "warning", "journalctl -u tor@default --no-pager -o short-iso --since '5 minutes ago' -n 100 -p warning"},
		{"2026-10-01 12:00:00", 0, "", "journalctl -u tor@default --no-pager -o short-iso --since '2026-10-01 12:00:00'"},
	}
	for _, tt := range tests {
		f := host.NewFake()
		f.Handler = func(host.Command) (host.Result, error) { return host.Result{Output: "line\n"}, nil }
		out, err := Tor{Host: f}.Journal(context.Background(), tt.since, tt.lines, tt.priority)
		if err != nil || out != "line\n" {
			t.Errorf("Journal = %q, %v", out, err)
		}
		if got := f.CommandLines()[0]; got != tt.want {
			t.Errorf("got %q\nwant %q", got, tt.want)
		}
		if f.Commands[0].Mutates {
			t.Error("journalctl must be read-only")
		}
	}
}

func TestFollow(t *testing.T) {
	f := host.NewFake()
	f.Handler = func(host.Command) (host.Result, error) {
		return host.Result{Output: "a\nb\n"}, nil
	}
	var lines []string
	if err := (Tor{Host: f}).Follow(context.Background(), func(s string) { lines = append(lines, s) }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lines, []string{"a", "b"}) {
		t.Errorf("lines = %q", lines)
	}
	if got := f.CommandLines()[0]; got != "journalctl -u tor@default -f -n 50 -o short-iso" {
		t.Errorf("command %q", got)
	}

	// A cancelled context ends following without an error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.Handler = func(host.Command) (host.Result, error) { return host.Result{}, context.Canceled }
	if err := (Tor{Host: f}).Follow(ctx, func(string) {}); err != nil {
		t.Errorf("cancelled Follow = %v", err)
	}
	// Other failures surface.
	f.Handler = func(host.Command) (host.Result, error) { return host.Result{}, errors.New("no journalctl") }
	if err := (Tor{Host: f}).Follow(context.Background(), func(string) {}); err == nil {
		t.Error("Follow swallowed an error")
	}
}

func TestParseSelfTest(t *testing.T) {
	const (
		v4       = "Oct 01 12:00:00 relay Tor[1]: Self-testing indicates your ORPort 203.0.113.5:9001 is reachable from the outside. Excellent. Publishing server descriptor."
		v6       = "Oct 01 12:00:01 relay Tor[1]: Self-testing indicates your ORPort [2001:db8::5]:9001 is reachable from the outside. Excellent."
		legacy   = "Self-testing indicates your ORPort is reachable from the outside. Excellent. Publishing server descriptor."
		fail     = "Your server has not managed to confirm reachability for its ORPort(s) at 203.0.113.5:9001. Relays do not publish descriptors until their ORPort and DirPort are reachable."
		failOld  = "Your server (203.0.113.5:9001) has not managed to confirm that its ORPort is reachable."
		failOld2 = "Your server has not managed to confirm that its ORPort is reachable. Please check your firewalls."
	)
	tests := []struct {
		name string
		log  string
		want SelfTest
	}{
		{"empty", "", SelfTest{}},
		{"ipv4", v4, SelfTest{IPv4: true}},
		{"ipv6 only", v6, SelfTest{IPv6: true}},
		{"both", v4 + "\n" + v6, SelfTest{IPv4: true, IPv6: true}},
		{"legacy counts as ipv4", legacy, SelfTest{IPv4: true}},
		{"failure", fail, SelfTest{Failed: true}},
		{"old failure wording", failOld2, SelfTest{Failed: true}},
		{"old wording with address", failOld, SelfTest{Failed: true}},
		{"success and failure", v4 + "\n" + fail, SelfTest{IPv4: true, Failed: true}},
		{"no excellent", "Self-testing indicates your ORPort 1.2.3.4:9001 is reachable from the outside.", SelfTest{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseSelfTest(tt.log); got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

const (
	okV4 = "2026-10-01T12:00:05+0000 relay Tor[1]: Self-testing indicates your ORPort 203.0.113.5:9001 is reachable from the outside. Excellent.\n"
	okV6 = "2026-10-01T12:00:06+0000 relay Tor[1]: Self-testing indicates your ORPort [2001:db8::5]:9001 is reachable from the outside. Excellent.\n"
)

// pollingFake returns a journal that changes with each poll.
func pollingFake(outputs ...string) (*host.Fake, *atomic.Int32) {
	var n atomic.Int32
	f := host.NewFake()
	f.Handler = func(c host.Command) (host.Result, error) {
		i := int(n.Add(1)) - 1
		if i >= len(outputs) {
			i = len(outputs) - 1
		}
		return host.Result{Output: outputs[i]}, nil
	}
	return f, &n
}

func TestWaitReachable(t *testing.T) {
	since := time.Date(2026, 10, 1, 12, 0, 0, 0, time.Local)

	t.Run("success on second poll", func(t *testing.T) {
		f, n := pollingFake("Bootstrapped 100%\n", okV4)
		st, err := Tor{Host: f}.WaitReachable(context.Background(), since, time.Millisecond, false)
		if err != nil || !st.IPv4 || n.Load() != 2 {
			t.Fatalf("st=%+v err=%v polls=%d", st, err, n.Load())
		}
		want := "journalctl -u tor@default --no-pager -o short-iso --since '2026-10-01 12:00:00'"
		if got := f.CommandLines()[0]; got != want {
			t.Errorf("got %q\nwant %q", got, want)
		}
	})

	t.Run("waits for ipv6 when wanted", func(t *testing.T) {
		f, n := pollingFake(okV4, okV4, okV4+okV6)
		st, err := Tor{Host: f}.WaitReachable(context.Background(), since, time.Millisecond, true)
		if err != nil || !st.IPv4 || !st.IPv6 || n.Load() != 3 {
			t.Fatalf("st=%+v err=%v polls=%d", st, err, n.Load())
		}
	})

	t.Run("failure notice ends the wait", func(t *testing.T) {
		f, _ := pollingFake("Your server has not managed to confirm reachability for its ORPort(s) at 203.0.113.5:9001.\n")
		st, err := Tor{Host: f}.WaitReachable(context.Background(), since, time.Millisecond, false)
		if err != nil || !st.Failed || st.IPv4 {
			t.Fatalf("st=%+v err=%v", st, err)
		}
	})

	t.Run("timeout returns last result", func(t *testing.T) {
		f, _ := pollingFake(okV4)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		st, err := Tor{Host: f}.WaitReachable(ctx, since, time.Millisecond, true)
		if !errors.Is(err, context.DeadlineExceeded) || !st.IPv4 || st.IPv6 {
			t.Fatalf("st=%+v err=%v", st, err)
		}
	})

	t.Run("journal error", func(t *testing.T) {
		f := host.NewFake()
		f.Handler = func(host.Command) (host.Result, error) { return host.Result{}, errors.New("journalctl: not found") }
		if _, err := (Tor{Host: f}).WaitReachable(context.Background(), since, time.Millisecond, false); err == nil || !strings.Contains(err.Error(), "journalctl") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestFamilyWarnings(t *testing.T) {
	var log strings.Builder
	log.WriteString("2026-10-01T12:00:00+0000 relay Tor[1]: Unable to open family key file: No such file\n")
	log.WriteString("2026-10-01T12:00:00+0000 relay Tor[1]: Something unrelated\n")
	for i := 0; i < 6; i++ {
		log.WriteString("2026-10-01T12:00:01+0000 relay Tor[1]: FamilyId configured but no FAMILY key found\n")
	}
	f := host.NewFake()
	f.Handler = func(host.Command) (host.Result, error) { return host.Result{Output: log.String()}, nil }

	since := time.Date(2026, 10, 1, 11, 59, 30, 0, time.Local)
	got, err := Tor{Host: f}.FamilyWarnings(context.Background(), since)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || !strings.Contains(got[0], "family key file") || !strings.Contains(got[4], "FAMILY key") {
		t.Errorf("got %q", got)
	}
	want := "journalctl -u tor@default --no-pager -o short-iso --since '2026-10-01 11:59:30' -p warning"
	if line := f.CommandLines()[0]; line != want {
		t.Errorf("got %q\nwant %q", line, want)
	}

	f.Handler = func(host.Command) (host.Result, error) { return host.Result{Output: "-- No entries --\n"}, nil }
	if got, err := (Tor{Host: f}).FamilyWarnings(context.Background(), since); err != nil || got != nil {
		t.Errorf("no warnings: %q, %v", got, err)
	}
}
