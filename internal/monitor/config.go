// Package monitor sets up a management server that watches a whole relay
// fleet: `tor-relay-setup fleet serve` probes every relay over SSH and
// exposes Prometheus metrics on loopback, Prometheus stores them, Grafana
// shows the provisioned dashboards, and Caddy publishes Grafana (and the
// fleet web UI) over HTTPS. Relays expose nothing new: the monitoring
// server reaches them with a dedicated SSH key that a forced command
// limits to `sudo -n tor-relay-setup fleet-probe` (see Authorize).
//
// Like internal/plan, every change goes through a host.Host and is listed
// in the steps' Changes, so --dry-run and the tests see exactly what a real
// run does. Rendering is pure; steps.go applies it.
package monitor

import (
	"errors"
	"fmt"
	"net/mail"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/system"
)

// Service users, ports and paths on the management server.
const (
	// MonitorUser runs `fleet serve` and owns the SSH key it probes with.
	MonitorUser = "tor-relay-monitor"
	MonitorHome = "/var/lib/tor-relay-monitor"
	// ProbeUser is the relay-side account the monitor key logs in as.
	ProbeUser = "tor-relay-probe"
	ProbeHome = "/var/lib/tor-relay-probe"

	ServeListen      = "127.0.0.1:9850"
	PrometheusListen = "127.0.0.1:9090"
	GrafanaListen    = "127.0.0.1:3000"
	// MetricsPath is where `fleet serve` publishes the metrics contract
	// (docs/monitoring/fleet-metrics.md), independent of base_path.
	MetricsPath = "/metrics"

	ConfigDir         = "/etc/tor-relay-setup"
	ServeConfigPath   = ConfigDir + "/serve.toml"
	AdminPasswordPath = ConfigDir + "/grafana-admin"
	DefaultInventory  = ConfigDir + "/fleet.toml"
	StatePath         = "/var/lib/tor-relay-setup/monitor.json"

	FleetUnit     = "tor-relay-setup-fleet"
	FleetUnitPath = "/etc/systemd/system/" + FleetUnit + ".service"

	PrometheusDefaults = "/etc/default/prometheus"
	PrometheusConfig   = "/etc/prometheus/prometheus.yml"
	PrometheusRules    = "/etc/prometheus/rules/tor-relay-fleet.yml"
	PrometheusToken    = "/etc/prometheus/tor-relay-fleet.token"

	GrafanaINI        = "/etc/grafana/grafana.ini"
	GrafanaDatasource = "/etc/grafana/provisioning/datasources/tor-relay-setup.yaml"
	GrafanaProvider   = "/etc/grafana/provisioning/dashboards/tor-relay-setup.yaml"
	GrafanaDashboards = "/etc/grafana/dashboards/tor-relay-setup"
	GrafanaDB         = "/var/lib/grafana/grafana.db"
	GrafanaHome       = "/usr/share/grafana"

	Caddyfile = "/etc/caddy/Caddyfile"

	// DatasourceUID is the provisioned Prometheus data source the
	// dashboards default to.
	DatasourceUID = "tor-prometheus"
	// FolderUID is the "Tor relays" dashboard folder.
	FolderUID = "tor-relays"

	DefaultAdminUser = "tor-admin"
	DefaultFleetPath = "/fleet"

	// Retention keeps 400 days, so a full year can be compared with the
	// previous one (yearly accounting, seasonal traffic), but never more
	// than RetentionSize on disk: whichever limit is reached first wins.
	RetentionTime = "400d"
	RetentionSize = "20GB"
	// ScrapeInterval matches fleet serve's probe cadence closely enough;
	// a faster scrape would only repeat the same values.
	ScrapeInterval = "30s"
)

// Release is a supported management-server distribution release.
type Release struct {
	OSID, Codename, Name string
	// CaddyRepo: the distribution has no caddy package, so Caddy's own
	// repository (with its pinned key) is added.
	CaddyRepo bool
}

// Releases lists the supported management-server releases. Every one has
// prometheus >= 2.31 in its archive (enough for authorization
// credentials_file and size-based retention); caddy is in the archive
// from Debian 12 and Ubuntu 24.04 on.
var Releases = []Release{
	{OSID: "debian", Codename: "bookworm", Name: "Debian 12"},
	{OSID: "debian", Codename: "trixie", Name: "Debian 13"},
	{OSID: "ubuntu", Codename: "jammy", Name: "Ubuntu 22.04", CaddyRepo: true},
	{OSID: "ubuntu", Codename: "noble", Name: "Ubuntu 24.04"},
	{OSID: "ubuntu", Codename: "resolute", Name: "Ubuntu 26.04"},
}

// ReleaseFor finds the release of facts.
func ReleaseFor(f system.Facts) (Release, bool) {
	for _, r := range Releases {
		if r.OSID == f.OSID && r.Codename == f.Codename {
			return r, true
		}
	}
	return Release{}, false
}

// Options is what `monitor install` was asked for.
type Options struct {
	Domain    string // the public name Caddy serves Grafana on
	Email     string // ACME account e-mail, optional
	Inventory string // fleet.toml the fleet service probes
	// FleetPath publishes the fleet web UI under https://DOMAIN/FleetPath/;
	// empty keeps it on loopback only.
	FleetPath   string
	AdminUser   string // Grafana's administrator login
	Executable  string // absolute path of tor-relay-setup, for the unit
	Version     string
	RotateToken bool // replace the metrics token shared with Prometheus
}

var (
	domainRE    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	fleetPathRE = regexp.MustCompile(`^(/[a-z0-9][a-z0-9_-]*)+$`)
	adminRE     = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)
)

// Normalize fills defaults and validates everything that ends up in a
// configuration file, so no value can break out of its syntax.
func (o *Options) Normalize() error {
	o.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(o.Domain)), ".")
	if o.Inventory == "" {
		o.Inventory = DefaultInventory
	}
	if o.AdminUser == "" {
		o.AdminUser = DefaultAdminUser
	}
	var errs []error
	switch {
	case o.Domain == "":
		errs = append(errs, errors.New("--domain is required: the DNS name Grafana is served on, e.g. grafana.example.org"))
	case len(o.Domain) > 253 || !domainRE.MatchString(o.Domain):
		errs = append(errs, fmt.Errorf("--domain %q is not a DNS name (Let's Encrypt needs a name, not an IP address)", o.Domain))
	}
	if o.Email != "" {
		a, err := mail.ParseAddress(o.Email)
		if err != nil || a.Address != o.Email || strings.ContainsAny(o.Email, " \t\"'{}\\") {
			errs = append(errs, fmt.Errorf("--email %q is not a plain e-mail address", o.Email))
		}
	}
	if !filepath.IsAbs(o.Inventory) || !unitSafe(o.Inventory) {
		errs = append(errs, fmt.Errorf("--inventory %q must be an absolute path of letters, digits and ._+-/", o.Inventory))
	}
	if o.FleetPath != "" && (!fleetPathRE.MatchString(o.FleetPath) || len(o.FleetPath) > 64) {
		errs = append(errs, fmt.Errorf("--fleet-path %q must look like /fleet (lower-case letters, digits, - and _), or be \"off\"", o.FleetPath))
	}
	if !adminRE.MatchString(o.AdminUser) || o.AdminUser == "admin" {
		errs = append(errs, fmt.Errorf("--admin-user %q: use 3-32 lower-case letters, digits, - or _, and not \"admin\"", o.AdminUser))
	}
	if o.Executable != "" && (!filepath.IsAbs(o.Executable) || !unitSafe(o.Executable)) {
		errs = append(errs, fmt.Errorf("%q must be an absolute path of letters, digits and ._+-/ only, to be used in a systemd unit", o.Executable))
	}
	return errors.Join(errs...)
}

// URL is the public Grafana address.
func (o Options) URL() string { return "https://" + o.Domain + "/" }

// unitSafe accepts paths that need no quoting in a unit or config file.
func unitSafe(p string) bool {
	for _, r := range p {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '/' && r != '.' && r != '_' && r != '-' && r != '+' {
			return false
		}
	}
	return !strings.Contains(p, "..")
}
