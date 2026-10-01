package relay

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

func TestVerifyWithServiceDefaults(t *testing.T) {
	h := host.NewFake()
	h.Paths["tor"] = true
	h.Files[ServiceDefaultsTorrc] = []byte("User debian-tor\n")
	if err := Verify(context.Background(), h, "/etc/tor/torrc.new"); err != nil {
		t.Fatal(err)
	}
	if len(h.Commands) != 1 {
		t.Fatalf("commands = %v", h.CommandLines())
	}
	c := h.Commands[0]
	wantArgs := []string{"--defaults-torrc", ServiceDefaultsTorrc, "-f", "/etc/tor/torrc.new", "--RunAsDaemon", "0", "--verify-config"}
	if c.Name != "tor" || !slices.Equal(c.Args, wantArgs) || c.Mutates {
		t.Fatalf("command = %+v", c)
	}
}

func TestVerifyWithoutServiceDefaults(t *testing.T) {
	h := host.NewFake()
	h.Paths["tor"] = true
	if err := Verify(context.Background(), h, "/tmp/torrc"); err != nil {
		t.Fatal(err)
	}
	if got := h.CommandLines(); !slices.Equal(got, []string{"tor -f /tmp/torrc --verify-config"}) {
		t.Fatalf("commands = %q", got)
	}
}

func TestVerifyRunsDuringDryRun(t *testing.T) {
	h := host.NewFake()
	h.Dry = true
	h.Paths["tor"] = true
	h.Handler = func(host.Command) (host.Result, error) {
		return host.Result{Output: "[err] bad\n", ExitCode: 1}, &host.ExitError{Command: "tor", ExitCode: 1}
	}
	if err := Verify(context.Background(), h, "/tmp/torrc"); err == nil {
		t.Fatal("dry run skipped the read-only verification")
	}
}

func TestVerifyTorMissing(t *testing.T) {
	h := host.NewFake()
	h.Files[ServiceDefaultsTorrc] = []byte("x")
	err := Verify(context.Background(), h, "/etc/tor/torrc")
	if !errors.Is(err, ErrTorMissing) {
		t.Fatalf("error = %v, want ErrTorMissing", err)
	}
	if len(h.Commands) != 0 {
		t.Fatalf("ran %q", h.CommandLines())
	}
}

func TestVerifyFailureKeepsUsefulLines(t *testing.T) {
	output := strings.Join([]string{
		"Oct 01 12:00:00.000 [notice] Tor 0.4.9.3 running on Linux with Libevent 2.1.12-stable.",
		"Oct 01 12:00:00.000 [notice] Tor can't help you if you use it wrong!",
		"Oct 01 12:00:00.000 [notice] Read configuration file \"/tmp/torrc\".",
		"Oct 01 12:00:00.000 [warn] Failed to parse/validate config: Unknown option 'Bogus'.  Failing.",
		"Oct 01 12:00:00.000 [err] Reading config failed--see warnings above.",
		"",
	}, "\n")
	tests := []struct {
		name    string
		handler func(host.Command) (host.Result, error)
	}{
		{"output in result", func(host.Command) (host.Result, error) {
			return host.Result{Output: output, ExitCode: 1}, &host.ExitError{Command: "tor", ExitCode: 1, Output: output}
		}},
		{"output only in ExitError", func(host.Command) (host.Result, error) {
			return host.Result{}, &host.ExitError{Command: "tor", ExitCode: 1, Output: output}
		}},
		{"non-zero exit without error", func(host.Command) (host.Result, error) {
			return host.Result{Output: output, ExitCode: 1}, nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := host.NewFake()
			h.Paths["tor"] = true
			h.Handler = tt.handler
			err := Verify(context.Background(), h, "/tmp/torrc")
			if err == nil {
				t.Fatal("expected failure")
			}
			msg := err.Error()
			for _, want := range []string{"/tmp/torrc", "exit status 1", "[warn] Failed to parse/validate config: Unknown option 'Bogus'", "[err] Reading config failed"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q lacks %q", msg, want)
				}
			}
			if strings.Contains(msg, "[notice]") {
				t.Errorf("error keeps notice noise: %q", msg)
			}
		})
	}
}

func TestVerifyExecError(t *testing.T) {
	h := host.NewFake()
	h.Paths["tor"] = true
	h.Handler = func(host.Command) (host.Result, error) { return host.Result{}, context.Canceled }
	if err := Verify(context.Background(), h, "/tmp/torrc"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want wrapped context.Canceled", err)
	}
}

func TestUsefulTorOutput(t *testing.T) {
	if got := usefulTorOutput("a [notice] one\n\nb [notice] two\n", 8); got != "a [notice] one\nb [notice] two" {
		t.Errorf("notices-only output = %q", got)
	}
	if got := usefulTorOutput("1\n2\n3\n4\n", 2); got != "3\n4" {
		t.Errorf("tail = %q", got)
	}
	if got := usefulTorOutput("", 2); got != "" {
		t.Errorf("empty = %q", got)
	}
}
