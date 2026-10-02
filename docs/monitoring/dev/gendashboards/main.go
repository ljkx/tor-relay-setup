// Command gendashboards writes the fleet Grafana dashboards
// (docs/monitoring/grafana/*.json). Run it with go generate ./docs/monitoring.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ljkx/tor-relay-setup/docs/monitoring/internal/dashgen"
)

func main() {
	out := flag.String("out", "grafana", "output directory")
	flag.Parse()
	for name, d := range dashgen.All() {
		data, err := dashgen.Marshal(d)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(*out, name), data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
