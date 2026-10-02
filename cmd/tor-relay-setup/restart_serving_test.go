package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

func TestRestartServing(t *testing.T) {
	for _, tt := range []struct {
		name    string
		active  bool
		failRun bool
		want    []string
		out     string
	}{
		{name: "running", active: true, want: []string{"is-active", "restart"}, out: "Restarted tor-relay-setup-fleet.service"},
		{name: "not installed or stopped", want: []string{"is-active"}},
		{name: "restart fails", active: true, failRun: true, want: []string{"is-active", "restart"}, out: "Could not restart"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var ran []string
			run := func(_ context.Context, c host.Command) (host.Result, error) {
				ran = append(ran, c.Args[0])
				switch {
				case c.Name != "systemctl" || c.Args[len(c.Args)-1] != "tor-relay-setup-fleet.service":
					t.Errorf("unexpected command %s %v", c.Name, c.Args)
				case c.Args[0] == "is-active" && !tt.active:
					return host.Result{}, errors.New("inactive")
				case c.Args[0] == "restart" && tt.failRun:
					return host.Result{}, errors.New("boom")
				}
				return host.Result{}, nil
			}
			var out strings.Builder
			restartServing(context.Background(), run, &out)
			if strings.Join(ran, ",") != strings.Join(tt.want, ",") {
				t.Errorf("ran %v, want %v", ran, tt.want)
			}
			if !strings.Contains(out.String(), tt.out) || (tt.out == "" && out.Len() > 0) {
				t.Errorf("output %q, want %q", out.String(), tt.out)
			}
		})
	}
}
