// Package monitoring embeds the fleet monitoring assets in this directory
// (the Grafana dashboards and the Prometheus fleet rules), so
// `tor-relay-setup monitor install` provisions exactly the files that are
// documented here. The dashboards are generated: edit
// dev/gendashboards/main.go and run `go generate ./docs/monitoring`.
package monitoring

import (
	"embed"
	"io/fs"
	"path"
)

//go:generate go run ./dev/gendashboards -out grafana

// Dashboard file names in grafana/.
const (
	OverviewFile = "tor-fleet-overview.json"
	RelayFile    = "tor-fleet-relay.json"
)

// Dashboard UIDs; the relay table links to the detail dashboard by UID.
const (
	OverviewUID = "tor-fleet-overview"
	RelayUID    = "tor-fleet-relay"
)

//go:embed grafana/*.json
var dashboards embed.FS

// FleetRules is prometheus-fleet-rules.yml.
//
//go:embed prometheus-fleet-rules.yml
var FleetRules []byte

// Dashboards returns the provisioned dashboards by file name.
func Dashboards() map[string][]byte {
	out := map[string][]byte{}
	entries, _ := fs.ReadDir(dashboards, "grafana")
	for _, e := range entries {
		data, err := dashboards.ReadFile(path.Join("grafana", e.Name()))
		if err == nil {
			out[e.Name()] = data
		}
	}
	return out
}
