package status

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// These tests guard docs/monitoring: every metric the Prometheus rules and
// the Grafana dashboard query must exist in `status --format prometheus`
// (Report.WritePrometheus plus WriteLoadPrometheus) or in the real tor
// MetricsPort sample, so a renamed gauge cannot silently break them.

var (
	metricName = regexp.MustCompile(`\btor_[a-z0-9_]+\b`)
	quoted     = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`) // label values such as file="tor_relay.prom"
)

// knownMetrics collects the metric names our output and tor's MetricsPort
// expose, plus the few non-tor series the docs use on purpose.
func knownMetrics(t *testing.T) map[string]bool {
	t.Helper()
	known := map[string]bool{"node_textfile_mtime_seconds": true, "up": true}
	var r Report
	r.Relay.Configured, r.Relay.Fingerprint = true, "0123456789ABCDEF0123456789ABCDEF01234567"
	r.Directory = &onionoo.Relay{Running: true}
	var buf bytes.Buffer
	if err := r.WritePrometheus(&buf); err != nil {
		t.Fatal(err)
	}
	if err := WriteLoadPrometheus(&buf, fullLoadMetrics(t)); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile("../metrics/testdata/metricsport-0.4.9.13.txt")
	if err != nil {
		t.Fatal(err)
	}
	buf.Write(page)
	for line := range strings.Lines(buf.String()) {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "#" && f[1] == "TYPE" {
			known[f[2]] = true
		}
	}
	return known
}

func checkExpr(t *testing.T, where, expr string, known map[string]bool) {
	t.Helper()
	if strings.TrimSpace(expr) == "" {
		t.Errorf("%s: empty expression", where)
	}
	for _, name := range metricName.FindAllString(quoted.ReplaceAllString(expr, `""`), -1) {
		if !known[name] && name != "tor_instance" { // tor_instance is a label
			t.Errorf("%s: unknown metric %s in %q", where, name, expr)
		}
	}
	if strings.Count(expr, "(") != strings.Count(expr, ")") || strings.Count(expr, "{") != strings.Count(expr, "}") {
		t.Errorf("%s: unbalanced brackets in %q", where, expr)
	}
}

func TestPrometheusRulesUseKnownMetrics(t *testing.T) {
	data, err := os.ReadFile("../../docs/monitoring/prometheus-rules.yml")
	if err != nil {
		t.Fatal(err)
	}
	known := knownMetrics(t)
	// The rules file is plain block YAML: "expr: <one line>" or "expr: |"
	// followed by more-indented lines. (promtool check rules validates it
	// fully; CI has no promtool, and the repository takes no YAML module.)
	lines := strings.Split(string(data), "\n")
	exprs, alerts := 0, map[string]bool{}
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if name, ok := strings.CutPrefix(trimmed, "- alert: "); ok {
			if alerts[name] {
				t.Errorf("duplicate alert %s", name)
			}
			alerts[name] = true
		}
		if strings.Contains(lines[i], "\t") {
			t.Errorf("line %d: tabs are not valid YAML indentation", i+1)
		}
		rest, ok := strings.CutPrefix(trimmed, "expr: ")
		if !ok {
			continue
		}
		exprs++
		if rest == "|" {
			indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
			var block []string
			for i+1 < len(lines) && (strings.TrimSpace(lines[i+1]) == "" || len(lines[i+1])-len(strings.TrimLeft(lines[i+1], " ")) > indent) {
				i++
				block = append(block, lines[i])
			}
			rest = strings.Join(block, "\n")
		}
		checkExpr(t, "prometheus-rules.yml line "+itoa(i+1), rest, known)
		if strings.Contains(rest, "(instance)") {
			t.Errorf("line %d: group or match by (instance, tor_instance), so relays sharing a host stay apart: %s", i+1, rest)
		}
	}
	if exprs < 15 || exprs != len(alerts) {
		t.Errorf("%d expressions for %d alerts", exprs, len(alerts))
	}
	for _, want := range []string{"TorRelayDown", "TorRelayUnreachable", "TorRelayFamilyKeyMissing", "TorRelayConsensusWeightDropped", "TorRelayOverloaded", "TorOnionskinsDropped"} {
		if !alerts[want] {
			t.Errorf("rules lack %s", want)
		}
	}
}

func TestGrafanaDashboard(t *testing.T) {
	data, err := os.ReadFile("../../docs/monitoring/grafana-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	type target struct {
		Expr string `json:"expr"`
	}
	type datasource struct {
		Type string `json:"type"`
		UID  string `json:"uid"`
	}
	type panel struct {
		ID         int         `json:"id"`
		Type       string      `json:"type"`
		Title      string      `json:"title"`
		Datasource *datasource `json:"datasource"`
		Targets    []target    `json:"targets"`
		GridPos    struct{ H, W, X, Y int }
	}
	var d struct {
		Inputs []struct {
			Name, Type, PluginID string
		} `json:"__inputs"`
		Panels        []panel `json:"panels"`
		SchemaVersion int     `json:"schemaVersion"`
		UID           string  `json:"uid"`
		Title         string  `json:"title"`
		Templating    struct {
			List []struct {
				Name       string      `json:"name"`
				Datasource *datasource `json:"datasource"`
				Definition string      `json:"definition"`
			} `json:"list"`
		} `json:"templating"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if d.SchemaVersion < 36 || d.UID == "" || d.Title == "" {
		t.Errorf("schemaVersion %d, uid %q, title %q", d.SchemaVersion, d.UID, d.Title)
	}
	if len(d.Inputs) != 1 || d.Inputs[0].Name != "DS_PROMETHEUS" || d.Inputs[0].PluginID != "prometheus" {
		t.Errorf("inputs %+v", d.Inputs)
	}
	known := knownMetrics(t)
	vars := map[string]bool{}
	for _, v := range d.Templating.List {
		vars[v.Name] = true
		if v.Datasource == nil || v.Datasource.UID != "${DS_PROMETHEUS}" {
			t.Errorf("variable %s: datasource %+v", v.Name, v.Datasource)
		}
		checkExpr(t, "variable "+v.Name, v.Definition, known)
	}
	if !vars["instance"] || !vars["nickname"] || !vars["tor_instance"] {
		t.Errorf("variables %v", vars)
	}
	ids := map[int]bool{}
	queried := map[string]bool{}
	for _, p := range d.Panels {
		if ids[p.ID] {
			t.Errorf("duplicate panel id %d", p.ID)
		}
		ids[p.ID] = true
		if p.GridPos.X+p.GridPos.W > 24 || p.GridPos.W <= 0 || p.GridPos.H <= 0 {
			t.Errorf("panel %q: gridPos %+v", p.Title, p.GridPos)
		}
		if p.Type == "row" {
			continue
		}
		if p.Datasource == nil || p.Datasource.UID != "${DS_PROMETHEUS}" || len(p.Targets) == 0 {
			t.Errorf("panel %q: datasource %+v, %d targets", p.Title, p.Datasource, len(p.Targets))
		}
		for _, tg := range p.Targets {
			checkExpr(t, "panel "+p.Title, tg.Expr, known)
			if !strings.Contains(tg.Expr, `instance=~"$instance",tor_instance=~"$tor_instance"`) {
				t.Errorf("panel %q ignores $instance or $tor_instance: %s", p.Title, tg.Expr)
			}
			for _, n := range metricName.FindAllString(tg.Expr, -1) {
				queried[n] = true
			}
		}
	}
	for _, want := range []string{
		"tor_relay_setup_service_active", "tor_relay_setup_directory_running", "tor_relay_setup_reachable",
		"tor_relay_setup_consensus_weight", "tor_relay_setup_advertised_bandwidth_bytes", "tor_relay_traffic_bytes",
		"tor_relay_connections", "tor_relay_load_onionskins_total", "tor_relay_setup_warnings",
		"tor_relay_setup_family_keys_missing", "tor_relay_setup_info",
	} {
		if !queried[want] {
			t.Errorf("no panel shows %s", want)
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
