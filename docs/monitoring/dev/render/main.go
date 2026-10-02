// Command render writes the files `tor-relay-setup monitor install`
// generates into a directory, with paths below that directory, so the
// local stack (run-local-stack.sh) runs Prometheus and Grafana with the
// very same configuration and dashboards as a management server.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/monitor"
)

func main() {
	out := flag.String("out", "", "output directory (required)")
	domain := flag.String("domain", "grafana.example.org", "domain for grafana.ini and the Caddyfile")
	target := flag.String("target", monitor.ServeListen, "fleet serve address Prometheus scrapes (and serve.toml's listen)")
	tokenFile := flag.String("token-file", "", "metrics token whose SHA-256 goes into serve.toml")
	flag.Parse()
	if *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	dir, err := filepath.Abs(*out)
	if err != nil {
		fail(err)
	}
	o := monitor.Options{Domain: *domain, FleetPath: monitor.DefaultFleetPath, Executable: "/usr/local/bin/tor-relay-setup"}
	if err := o.Normalize(); err != nil {
		fail(err)
	}
	p := func(rel string) string { return filepath.Join(dir, rel) }
	token := "dev-token"
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fail(err)
		}
		token = strings.TrimSpace(string(data))
	}
	// serve.toml as monitor install writes it, listening on the target.
	serve := monitor.ServeConfig(nil, o, monitor.TokenSHA256(token))
	serve = bytes.Replace(serve, []byte(`listen = "`+monitor.ServeListen+`"`), []byte(`listen = "`+*target+`"`), 1)
	files := map[string][]byte{
		"prometheus/prometheus.yml":                             monitor.PrometheusConfigFile(p("prometheus/rules.yml"), p("prometheus/token"), *target),
		"prometheus/rules.yml":                                  monitor.FleetRulesFile(),
		"prometheus/default":                                    monitor.PrometheusDefaultsFile(),
		"grafana/grafana.ini":                                   monitor.GrafanaINIFile(o, "dev-secret-key-not-for-production"),
		"grafana/provisioning/datasources/tor-relay-setup.yaml": monitor.GrafanaDatasourceFile(),
		"grafana/provisioning/dashboards/tor-relay-setup.yaml":  monitor.GrafanaProviderFile(p("grafana/dashboards")),
		"caddy/Caddyfile":                                       monitor.CaddyfileContent(o),
		"systemd/tor-relay-setup-fleet.service":                 monitor.FleetUnitFile(o.Executable),
		"serve.toml":                                            serve,
		"ssh/config":                                            monitor.SSHConfigFile(),
	}
	for name, data := range monitor.DashboardFiles() {
		files["grafana/dashboards/"+name] = data
	}
	for name, data := range files {
		path := p(name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fail(err)
		}
		// serve.toml and the token must not be readable by others.
		if err := os.WriteFile(path, data, 0o600); err != nil {
			fail(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			fail(err)
		}
	}
	fmt.Println("wrote", len(files), "files to", dir)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
