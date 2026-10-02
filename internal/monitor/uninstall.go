package monitor

import (
	"context"
	"slices"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/apt"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
)

// purgeable are the packages --purge may remove, and only when this tool
// installed them: ufw (the firewall) and openssh-client stay.
var purgeable = []string{"grafana", "prometheus", "caddy"}

// UninstallSteps stops the stack. Without purge the packages, data and
// configuration stay, so `monitor install` brings it back as it was; with
// purge everything this tool created goes, including Prometheus's history
// and Grafana's database. Firewall rules are left alone either way. In
// local mode Caddy is not part of the stack and is left alone too.
func UninstallSteps(st State, purge bool) []plan.Step {
	units := UnitsFor(st)
	steps := []plan.Step{{
		ID: "stop", Title: "Stop the monitoring services", Weight: 2,
		Changes: []string{"Stop and disable " + strings.Join(units[:len(units)-1], ", ") + " and " + units[len(units)-1] + "; remove " + FleetUnitPath},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			for _, u := range units {
				// A unit that is missing or already stopped is fine.
				_, _ = h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"disable", "--now", u}, Mutates: true})
			}
			if _, err := h.Stat(FleetUnitPath); err == nil {
				if err := h.Remove(FleetUnitPath); err != nil {
					return err
				}
			}
			_, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"daemon-reload"}, Mutates: true})
			if !purge {
				r.Note(plan.Info, "Packages, dashboards, metrics history and "+AdminPasswordPath+" were kept; monitor install starts everything again")
			}
			return err
		},
	}}
	if !purge {
		return steps
	}
	var pkgs []string
	for _, p := range purgeable {
		if slices.Contains(st.NewPackages, p) {
			pkgs = append(pkgs, p)
		}
	}
	files := []string{
		ServeConfigPath, AdminPasswordPath, PrometheusToken, PrometheusRules,
		GrafanaDatasource, GrafanaProvider, GrafanaDashboards,
		"/var/lib/grafana", "/var/lib/prometheus/metrics2", "/var/cache/tor-relay-setup-fleet", MonitorHome,
		GrafanaRepo.SourcesPath, GrafanaRepo.KeyringPath, CaddyRepo.SourcesPath, CaddyRepo.KeyringPath,
		StatePath,
	}
	purgeChanges := []string{"Delete Grafana's database and Prometheus's metrics history, the monitor SSH key, serve.toml, the admin password file and the apt sources this tool added"}
	if len(pkgs) > 0 {
		purgeChanges = append([]string{"Purge the packages monitor install added: " + strings.Join(pkgs, ", ")}, purgeChanges...)
	}
	purgeChanges = append(purgeChanges, "Remove the "+MonitorUser+" user")
	return append(steps, plan.Step{
		ID: "purge", Title: "Remove the monitoring stack", Weight: 8, Changes: purgeChanges,
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			if err := (apt.Client{Host: h}).Purge(ctx, pkgs, r.Log); err != nil {
				return err
			}
			for _, p := range files {
				if _, err := h.Stat(p); err != nil {
					continue
				}
				if err := h.Remove(p); err != nil {
					return err
				}
			}
			if userExists(ctx, h, MonitorUser) {
				if _, err := h.Run(ctx, host.Command{Name: "userdel", Args: []string{MonitorUser}, Mutates: true}); err != nil {
					return err
				}
			}
			r.Note(plan.Info, "Firewall rules were left alone (ufw status numbered; ufw delete N)")
			return nil
		},
	})
}
