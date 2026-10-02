package monitoring_test

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/docs/monitoring"
	"github.com/ljkx/tor-relay-setup/docs/monitoring/internal/dashgen"
)

// contractNames reads every metric name from fleet-metrics.md.
func contractNames(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile("fleet-metrics.md")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	tick := regexp.MustCompile("`([a-z_]+)(\\{[^`]*\\})?`")
	for line := range strings.Lines(string(data)) {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		first := strings.SplitN(strings.ReplaceAll(line, `\|`, "/"), "|", 3)[1]
		for _, m := range tick.FindAllStringSubmatch(first, -1) {
			names["tor_relay_fleet_"+m[1]] = true
		}
	}
	if len(names) < 50 {
		t.Fatalf("parsed only %d metric names from fleet-metrics.md", len(names))
	}
	return names
}

// builtins are Prometheus's own series the dashboards and rules use.
var builtins = map[string]bool{"ALERTS": true, "up": true, "scrape_duration_seconds": true}

var promqlWords = map[string]bool{
	"by": true, "without": true, "on": true, "ignoring": true, "group_left": true, "group_right": true,
	"and": true, "or": true, "unless": true, "bool": true, "offset": true, "inf": true, "nan": true,
}

var (
	stringRE   = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	braceRE    = regexp.MustCompile(`\{[^}]*\}`)
	rangeRE    = regexp.MustCompile(`\[[^\]]*\]`)
	groupingRE = regexp.MustCompile(`\b(by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)`)
	identRE    = regexp.MustCompile(`[A-Za-z_:][A-Za-z0-9_:]*`)
)

// metricNames returns the metric names an expression selects.
func metricNames(expr string) []string {
	e := stringRE.ReplaceAllString(expr, `""`)
	e = braceRE.ReplaceAllString(e, " ")
	e = rangeRE.ReplaceAllString(e, " ")
	e = groupingRE.ReplaceAllString(e, " ")
	var out []string
	for _, loc := range identRE.FindAllStringIndex(e, -1) {
		word := e[loc[0]:loc[1]]
		rest := strings.TrimLeft(e[loc[1]:], " ")
		switch {
		case promqlWords[word], strings.HasPrefix(rest, "("):
			continue // keyword or function
		case loc[0] > 0 && (e[loc[0]-1] == '$' || (e[loc[0]-1] >= '0' && e[loc[0]-1] <= '9')):
			continue // $__rate_interval, durations
		}
		out = append(out, word)
	}
	return out
}

func TestMetricNames(t *testing.T) {
	got := metricNames(`sum by (host, as) (rate(tor_relay_fleet_relay_x_total{a="b",c=~"$host"}[$__rate_interval])) * on (host) group_left (as) up or vector(0)`)
	if !slices.Equal(got, []string{"tor_relay_fleet_relay_x_total", "up"}) {
		t.Errorf("got %q", got)
	}
}

type panel struct {
	ID          int            `json:"id"`
	Type        string         `json:"type"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	GridPos     map[string]int `json:"gridPos"`
	Datasource  map[string]any `json:"datasource"`
	Targets     []struct {
		Expr       string         `json:"expr"`
		RefID      string         `json:"refId"`
		Datasource map[string]any `json:"datasource"`
	} `json:"targets"`
	FieldConfig struct {
		Defaults struct {
			Unit string `json:"unit"`
		} `json:"defaults"`
	} `json:"fieldConfig"`
	Panels []panel `json:"panels"`
}

type dashboard struct {
	UID           string  `json:"uid"`
	Title         string  `json:"title"`
	Description   string  `json:"description"`
	SchemaVersion int     `json:"schemaVersion"`
	Editable      bool    `json:"editable"`
	Panels        []panel `json:"panels"`
	Templating    struct {
		List []struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Query any    `json:"query"`
		} `json:"list"`
	} `json:"templating"`
}

func TestDashboardsMatchGenerator(t *testing.T) {
	embedded := monitoring.Dashboards()
	all := dashgen.All()
	if len(embedded) != len(all) {
		t.Fatalf("grafana/ has %d dashboards, the generator %d", len(embedded), len(all))
	}
	for name, d := range all {
		want, err := dashgen.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(embedded[name], want) {
			t.Errorf("grafana/%s is out of date: run go generate ./docs/monitoring", name)
		}
	}
}

func TestDashboards(t *testing.T) {
	names := contractNames(t)
	files := monitoring.Dashboards()
	for _, f := range []string{monitoring.OverviewFile, monitoring.RelayFile} {
		data, ok := files[f]
		if !ok {
			t.Fatalf("%s missing", f)
		}
		var d dashboard
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if d.UID == "" || d.Title == "" || d.Description == "" || d.SchemaVersion < 39 || d.Editable {
			t.Errorf("%s: uid %q title %q schema %d editable %v", f, d.UID, d.Title, d.SchemaVersion, d.Editable)
		}
		if len(d.Templating.List) == 0 || d.Templating.List[0].Name != "datasource" || d.Templating.List[0].Type != "datasource" {
			t.Errorf("%s: the first variable must pick the data source", f)
		}
		ids, titles := map[int]bool{}, map[string]bool{}
		var walk func([]panel, bool)
		count := 0
		walk = func(ps []panel, inRow bool) {
			for _, p := range ps {
				if ids[p.ID] || p.ID == 0 {
					t.Errorf("%s: panel id %d repeated or missing (%q)", f, p.ID, p.Title)
				}
				ids[p.ID] = true
				g := p.GridPos
				if g["w"] < 1 || g["x"]+g["w"] > 24 || g["h"] < 1 {
					t.Errorf("%s: %q gridPos %v", f, p.Title, g)
				}
				if p.Type == "row" {
					if inRow {
						t.Errorf("%s: nested row %q", f, p.Title)
					}
					walk(p.Panels, true)
					continue
				}
				count++
				if titles[p.Title] {
					t.Errorf("%s: two panels titled %q", f, p.Title)
				}
				titles[p.Title] = true
				if strings.TrimSpace(p.Description) == "" {
					t.Errorf("%s: %q has no description", f, p.Title)
				}
				if !slices.Contains([]string{"stat", "timeseries", "table", "bargauge", "piechart", "geomap", "state-timeline", "gauge"}, p.Type) {
					t.Errorf("%s: %q uses panel type %q (built-in panels only)", f, p.Title, p.Type)
				}
				if p.Datasource["uid"] != "${datasource}" || len(p.Targets) == 0 {
					t.Errorf("%s: %q data source %v, %d targets", f, p.Title, p.Datasource, len(p.Targets))
				}
				for _, tg := range p.Targets {
					if tg.Datasource["uid"] != "${datasource}" || tg.RefID == "" {
						t.Errorf("%s: %q target %s data source %v", f, p.Title, tg.RefID, tg.Datasource)
					}
					for _, m := range metricNames(tg.Expr) {
						if !names[m] && !builtins[m] {
							t.Errorf("%s: %q uses %q, which is not in fleet-metrics.md:\n%s", f, p.Title, m, tg.Expr)
						}
					}
				}
			}
		}
		walk(d.Panels, false)
		if count < 30 {
			t.Errorf("%s: only %d panels", f, count)
		}
	}
}

func TestDashboardsCoverTheContract(t *testing.T) {
	used := map[string]bool{}
	for _, data := range monitoring.Dashboards() {
		for _, m := range regexp.MustCompile(`tor_relay_fleet_[a-z_]+`).FindAllString(string(data), -1) {
			used[m] = true
		}
	}
	for m := range contractNames(t) {
		if !used[m] {
			t.Errorf("no panel shows %s", m)
		}
	}
}

func TestRulesUseTheContract(t *testing.T) {
	names := contractNames(t)
	var exprs []string
	var cur *strings.Builder
	indent := 0
	alerts := 0
	for line := range strings.Lines(string(monitoring.FleetRules)) {
		trim := strings.TrimSpace(line)
		lead := len(line) - len(strings.TrimLeft(line, " "))
		if cur != nil && (trim == "" || lead > indent) {
			cur.WriteString(line)
			continue
		}
		if cur != nil {
			exprs = append(exprs, cur.String())
			cur = nil
		}
		if strings.HasPrefix(trim, "- alert: ") {
			alerts++
		}
		if v, ok := strings.CutPrefix(trim, "expr: "); ok {
			cur, indent = &strings.Builder{}, lead
			if v != "|" {
				cur.WriteString(v)
			}
		}
	}
	if cur != nil {
		exprs = append(exprs, cur.String())
	}
	if alerts < 20 || len(exprs) != alerts {
		t.Fatalf("%d alerts, %d expressions", alerts, len(exprs))
	}
	for _, e := range exprs {
		for _, m := range metricNames(e) {
			if !names[m] && !builtins[m] {
				t.Errorf("rule uses %q, which is not in fleet-metrics.md:\n%s", m, e)
			}
		}
	}
	rules := string(monitoring.FleetRules)
	if strings.Count(rules, "severity: ") != alerts || strings.Count(rules, "summary: ") != alerts {
		t.Error("every rule needs a severity label and a summary")
	}
}
