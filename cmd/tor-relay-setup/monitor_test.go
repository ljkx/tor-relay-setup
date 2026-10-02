package main

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestMonitorArgs(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want []string
		ok   bool
	}{
		{[]string{"monitor", "install", "--domain", "g.example.org"}, []string{"install", "--domain", "g.example.org"}, true},
		{[]string{"--dry-run", "--plain", "monitor", "status"}, []string{"status", "--dry-run"}, true},
		{[]string{"status"}, nil, false},
		{[]string{"--config", "x", "monitor"}, nil, false},
	} {
		got, ok := monitorArgs(tt.args)
		if ok != tt.ok || !slices.Equal(got, tt.want) {
			t.Errorf("monitorArgs(%q) = %q %v", tt.args, got, ok)
		}
	}
	for _, tt := range []struct {
		args []string
		want []string
		ok   bool
	}{
		{[]string{"fleet", "authorize", "--key", "k"}, []string{"--key", "k"}, true},
		{[]string{"--dry-run", "fleet", "--yes", "authorize"}, []string{"--dry-run", "--yes"}, true},
		{[]string{"fleet", "status"}, nil, false},
		{[]string{"fleet"}, nil, false},
	} {
		got, ok := fleetAuthorizeArgs(tt.args)
		if ok != tt.ok || !slices.Equal(got, tt.want) {
			t.Errorf("fleetAuthorizeArgs(%q) = %q %v", tt.args, got, ok)
		}
	}
}

func TestMonitorUsageErrors(t *testing.T) {
	for _, tt := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"monitor"}, 2, "needs a command"},
		{[]string{"monitor", "frobnicate"}, 2, "unknown monitor command"},
		{[]string{"monitor", "status", "--domain", "x.example.org"}, 2, "only used with monitor install"},
		{[]string{"monitor", "install", "--purge"}, 2, "--purge is only used"},
		{[]string{"monitor", "status", "--yes"}, 2, "takes no --yes"},
		{[]string{"monitor", "install", "extra"}, 2, "unexpected argument"},
		{[]string{"fleet", "authorize", "--remove", "--key", "x"}, 2, "--remove takes no"},
		{[]string{"fleet", "authorize", "--dry-run"}, 2, "--key is required"},
		{[]string{"fleet", "authorize", "--dry-run", "--key", "ssh-rsa AAAA x"}, 2, "ssh-ed25519"},
		{[]string{"fleet", "authorize", "--dry-run", "--key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOu1fnVr0bHb0nbiU0pWj2uy8W5H8UuK4u3Dd3s4xR9a", "--from", "relay.example.org"}, 2, "not an IP address"},
	} {
		var out, errOut bytes.Buffer
		code := run(tt.args, strings.NewReader(""), &out, &errOut)
		if code != tt.code || !strings.Contains(errOut.String(), tt.msg) {
			t.Errorf("%q: exit %d, stderr %q; want %d and %q", tt.args, code, errOut.String(), tt.code, tt.msg)
		}
	}
	var out bytes.Buffer
	if code := run([]string{"monitor", "--help"}, strings.NewReader(""), &out, &out); code != 0 || !strings.Contains(out.String(), "monitor install --domain NAME") {
		t.Errorf("help: %d %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"--help"}, strings.NewReader(""), &out, &out); code != 0 || !strings.Contains(out.String(), "monitor install|status|uninstall") {
		t.Error("main usage does not mention monitor")
	}
}

func TestPlanRunnerNeedsConfirmation(t *testing.T) {
	var out bytes.Buffer
	p := planRunner{Title: "x", Out: &out}
	if err := p.Run(t.Context(), nil, nil); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("without a terminal: %v", err)
	}
	p.Terminal, p.In = true, strings.NewReader("n\n")
	if err := p.Run(t.Context(), nil, nil); !errors.Is(err, errDeclined) {
		t.Errorf("declined: %v", err)
	}
}
