package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Units are the services of the monitoring stack, in data-flow order.
var Units = []string{FleetUnit, "prometheus", "grafana-server", "caddy"}

// StatusOptions locates the local services; tests point them elsewhere.
type StatusOptions struct {
	HTTP          *http.Client
	PrometheusURL string // default http://127.0.0.1:9090
	GrafanaURL    string // default http://127.0.0.1:3000
}

// Status is the health of the monitoring stack.
type Status struct {
	State      State
	Installed  bool
	Units      map[string]bool // unit -> active
	Grafana    bool            // /api/health answers
	Prometheus bool            // /-/ready answers
	Target     string          // the fleet scrape target's health: up, down, unknown, missing
	TargetErr  string
	Fleet      map[string]float64 // a few fleet totals, when Prometheus has them
	PublicKey  string
}

// CollectStatus checks the units, the local HTTP endpoints and the scrape.
func CollectStatus(ctx context.Context, h host.Host, o StatusOptions) Status {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 5 * time.Second}
	}
	if o.PrometheusURL == "" {
		o.PrometheusURL = "http://" + PrometheusListen
	}
	if o.GrafanaURL == "" {
		o.GrafanaURL = "http://" + GrafanaListen
	}
	s := Status{Units: map[string]bool{}, Fleet: map[string]float64{}, Target: "missing"}
	s.State, _ = ReadState(h)
	s.Installed = s.State.Domain != ""
	for _, u := range Units {
		_, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"is-active", "--quiet", u}})
		s.Units[u] = err == nil
	}
	if pub, err := h.ReadFile(MonitorHome + "/.ssh/id_ed25519.pub"); err == nil {
		s.PublicKey = strings.TrimSpace(string(pub))
	}
	s.Grafana = get(ctx, o.HTTP, o.GrafanaURL+"/api/health", nil) == nil
	s.Prometheus = get(ctx, o.HTTP, o.PrometheusURL+"/-/ready", nil) == nil
	var targets struct {
		Data struct {
			ActiveTargets []struct {
				Labels    map[string]string `json:"labels"`
				Health    string            `json:"health"`
				LastError string            `json:"lastError"`
			} `json:"activeTargets"`
		} `json:"data"`
	}
	if get(ctx, o.HTTP, o.PrometheusURL+"/api/v1/targets?state=active", &targets) == nil {
		for _, t := range targets.Data.ActiveTargets {
			if t.Labels["job"] == "tor-relay-fleet" {
				s.Target, s.TargetErr = t.Health, t.LastError
			}
		}
	}
	for _, m := range []string{"relays", "relays_running", "hosts", "hosts_up", "attention"} {
		var res struct {
			Data struct {
				Result []struct {
					Value [2]any `json:"value"`
				} `json:"result"`
			} `json:"data"`
		}
		q := url.Values{"query": {"tor_relay_fleet_" + m}}
		if get(ctx, o.HTTP, o.PrometheusURL+"/api/v1/query?"+q.Encode(), &res) == nil && len(res.Data.Result) == 1 {
			if v, ok := res.Data.Result[0].Value[1].(string); ok {
				var f float64
				if _, err := fmt.Sscan(v, &f); err == nil {
					s.Fleet[m] = f
				}
			}
		}
	}
	return s
}

func get(ctx context.Context, c *http.Client, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", u, resp.Status)
	}
	if into == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(into)
}

// Healthy reports whether everything is up and Prometheus scrapes the fleet.
func (s Status) Healthy() bool {
	if !s.Installed || !s.Grafana || !s.Prometheus || s.Target != "up" {
		return false
	}
	for _, ok := range s.Units {
		if !ok {
			return false
		}
	}
	return true
}

// Write prints the status as text.
func (s Status) Write(w io.Writer) {
	mark := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	if !s.Installed {
		fmt.Fprintln(w, "The monitoring stack is not installed here (sudo tor-relay-setup monitor install --domain NAME).")
	} else {
		fmt.Fprintf(w, "Grafana      https://%s/  (admin %s, password in %s)\n", s.State.Domain, s.State.AdminUser, AdminPasswordPath)
		if s.State.FleetPath != "" {
			fmt.Fprintf(w, "Fleet UI     https://%s%s/\n", s.State.Domain, s.State.FleetPath)
		}
		fmt.Fprintf(w, "Inventory    %s\n", s.State.Inventory)
	}
	for _, u := range Units {
		fmt.Fprintf(w, "Service      %s %s\n", mark(s.Units[u]), u)
	}
	fmt.Fprintf(w, "Grafana      %s %s/api/health\n", mark(s.Grafana), "http://"+GrafanaListen)
	fmt.Fprintf(w, "Prometheus   %s %s/-/ready\n", mark(s.Prometheus), "http://"+PrometheusListen)
	line := "Scrape       " + mark(s.Target == "up") + " fleet serve on " + ServeListen + ": " + s.Target
	if s.TargetErr != "" {
		line += " (" + s.TargetErr + ")"
	}
	fmt.Fprintln(w, line)
	if len(s.Fleet) > 0 {
		fmt.Fprintf(w, "Fleet        %.0f/%.0f relays running, %.0f/%.0f hosts up, %.0f need attention\n",
			s.Fleet["relays_running"], s.Fleet["relays"], s.Fleet["hosts_up"], s.Fleet["hosts"], s.Fleet["attention"])
	}
	if s.PublicKey != "" {
		fmt.Fprintf(w, "SSH key      %s\n", s.PublicKey)
		fmt.Fprintf(w, "Authorize    %s\n", AuthorizeCommand(s.PublicKey))
	}
}
