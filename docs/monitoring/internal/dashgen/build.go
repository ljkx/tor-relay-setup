// Package dashgen builds the fleet Grafana dashboards. The JSON in
// docs/monitoring/grafana is its output (go generate ./docs/monitoring);
// a test keeps the two in sync. Generating them keeps ~80 panels
// consistent: one colour scheme, units, thresholds and descriptions.
package dashgen

import (
	"bytes"
	"encoding/json"
)

// Tor's brand colours (https://styleguide.torproject.org/).
const (
	Purple      = "#7D4698"
	PurpleDark  = "#59316B"
	PurpleLight = "#B983D3"
	Green       = "#68B030"
	Yellow      = "#F5C342"
	Orange      = "#F08C2E"
	Red         = "#D93F3F"
	Grey        = "#8E8E8E"
	Blue        = "#4A90C2"
)

// SchemaVersion is the classic dashboard JSON schema of Grafana 11/12;
// Grafana 13 loads it unchanged.
const SchemaVersion = 41

// M is a JSON object.
type M = map[string]any

// All returns every dashboard by file name.
func All() map[string]M {
	return map[string]M{
		"tor-fleet-overview.json": Overview(),
		"tor-fleet-relay.json":    Relay(),
	}
}

// ds is the data source of every query: the dashboard's variable, which
// defaults to the provisioned uid tor-prometheus.
var ds = M{"type": "prometheus", "uid": "${datasource}"}

// Marshal renders a dashboard as indented JSON with a final newline.
func Marshal(d M) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Q is one PromQL query.
type Q struct {
	Expr, Legend string
	Instant      bool // instant query (stats, tables, bar gauges)
	Table        bool // format=table (tables, geomap)
	Interval     string
	Hide         bool
}

func targets(qs []Q) []any {
	out := make([]any, len(qs))
	for i, q := range qs {
		t := M{
			"refId":        string(rune('A' + i)),
			"datasource":   ds,
			"expr":         q.Expr,
			"legendFormat": q.Legend,
			"range":        !q.Instant,
			"instant":      q.Instant,
			"editorMode":   "code",
		}
		if q.Legend == "" {
			t["legendFormat"] = "__auto"
		}
		if q.Table {
			t["format"] = "table"
		} else {
			t["format"] = "time_series"
		}
		if q.Interval != "" {
			t["interval"] = q.Interval
		}
		if q.Hide {
			t["hide"] = true
		}
		out[i] = t
	}
	return out
}

// Step is one threshold step; the first one's value is the base (null).
type Step struct {
	Color string
	Value float64
}

func thresholds(steps ...Step) M {
	out := make([]any, len(steps))
	for i, s := range steps {
		var v any = s.Value
		if i == 0 {
			v = nil
		}
		out[i] = M{"color": s.Color, "value": v}
	}
	return M{"mode": "absolute", "steps": out}
}

// Neutral is a single purple threshold: a value without good or bad.
var Neutral = []Step{{Color: Purple}}

// Field is the fieldConfig defaults that vary between panels.
type Field struct {
	Unit       string
	Decimals   *int
	Min, Max   *float64
	Thresholds []Step
	ColorMode  string // thresholds (default), fixed, palette-classic, continuous-purples ...
	FixedColor string
	Mappings   []any
	NoValue    string
	Custom     M
}

func (f Field) defaults() M {
	d := M{}
	if f.Unit != "" {
		d["unit"] = f.Unit
	}
	if f.Decimals != nil {
		d["decimals"] = *f.Decimals
	}
	if f.Min != nil {
		d["min"] = *f.Min
	}
	if f.Max != nil {
		d["max"] = *f.Max
	}
	steps := f.Thresholds
	if steps == nil {
		steps = Neutral
	}
	d["thresholds"] = thresholds(steps...)
	color := M{"mode": "thresholds"}
	if f.ColorMode != "" {
		color = M{"mode": f.ColorMode}
	}
	if f.FixedColor != "" {
		color["fixedColor"] = f.FixedColor
	}
	d["color"] = color
	if f.Mappings != nil {
		d["mappings"] = f.Mappings
	} else {
		d["mappings"] = []any{}
	}
	if f.NoValue != "" {
		d["noValue"] = f.NoValue
	}
	if f.Custom != nil {
		d["custom"] = f.Custom
	}
	return d
}

func ip(i int) *int         { return &i }
func fp(f float64) *float64 { return &f }
func override(matcher M, props ...M) M {
	return M{"matcher": matcher, "properties": props}
}
func byName(name string) M    { return M{"id": "byName", "options": name} }
func byRegexp(re string) M    { return M{"id": "byRegexp", "options": re} }
func prop(id string, v any) M { return M{"id": id, "value": v} }
func fixedColor(c string) M {
	return prop("color", M{"mode": "fixed", "fixedColor": c})
}

// valueMap maps exact values to text and colour.
func valueMap(pairs ...[3]string) M {
	opts := M{}
	for i, p := range pairs {
		opts[p[0]] = M{"text": p[1], "color": p[2], "index": i}
	}
	return M{"type": "value", "options": opts}
}

// nullMap shows text for missing values.
func nullMap(text, color string) M {
	return M{"type": "special", "options": M{"match": "null", "result": M{"text": text, "color": color, "index": 0}}}
}

// Panel is one panel before layout.
type Panel struct {
	Type, Title, Desc string
	W, H              int
	Targets           []Q
	Field             Field
	Overrides         []any
	Options           M
	Transformations   []any
	Interval          string
	MaxDataPoints     int
	Links             []any
}

func (p Panel) json(id, x, y int) M {
	out := M{
		"id":          id,
		"type":        p.Type,
		"title":       p.Title,
		"description": p.Desc,
		"gridPos":     M{"h": p.H, "w": p.W, "x": x, "y": y},
		"datasource":  ds,
		"targets":     targets(p.Targets),
		"fieldConfig": M{"defaults": p.Field.defaults(), "overrides": orEmpty(p.Overrides)},
		"options":     p.Options,
	}
	if p.Options == nil {
		out["options"] = M{}
	}
	if p.Transformations != nil {
		out["transformations"] = p.Transformations
	}
	if p.Interval != "" {
		out["interval"] = p.Interval
	}
	if p.MaxDataPoints > 0 {
		out["maxDataPoints"] = p.MaxDataPoints
	}
	if p.Links != nil {
		out["links"] = p.Links
	}
	return out
}

func orEmpty(a []any) []any {
	if a == nil {
		return []any{}
	}
	return a
}

// Layout places panels left to right and wraps at 24 columns; rows are
// collapsed (holding their panels) or open (panels follow them).
type Layout struct {
	panels   []any
	id       int
	x, y, h  int
	row      M // the collapsed row being filled, if any
	rowStart int
}

func (l *Layout) nextID() int { l.id++; return l.id }

// Add places a panel.
func (l *Layout) Add(ps ...Panel) {
	for _, p := range ps {
		if l.x+p.W > 24 {
			l.x, l.y, l.h = 0, l.y+l.h, 0
		}
		j := p.json(l.nextID(), l.x, l.y)
		l.x += p.W
		l.h = max(l.h, p.H)
		if l.row != nil {
			l.row["panels"] = append(l.row["panels"].([]any), j)
		} else {
			l.panels = append(l.panels, j)
		}
	}
}

// Row starts a row. Panels of a collapsed row live inside it.
func (l *Layout) Row(title string, collapsed bool) {
	l.closeRow()
	r := M{"id": l.nextID(), "type": "row", "title": title, "collapsed": collapsed,
		"gridPos": M{"h": 1, "w": 24, "x": 0, "y": l.y}, "panels": []any{}}
	l.panels = append(l.panels, r)
	l.rowStart = l.y
	l.y++
	l.row = nil
	if collapsed {
		l.row = r
	}
}

func (l *Layout) endLine() {
	if l.x > 0 || l.h > 0 {
		l.x, l.y, l.h = 0, l.y+l.h, 0
	}
}

// closeRow ends the current line; after a collapsed row, which takes one
// grid unit on the page, the next element follows right below it.
func (l *Layout) closeRow() {
	l.endLine()
	if l.row != nil {
		l.y = l.rowStart + 1
		l.row = nil
	}
}

// Panels returns the laid-out panels.
func (l *Layout) Panels() []any { l.closeRow(); return l.panels }

// Dashboard assembles the dashboard object.
func Dashboard(uid, title, desc string, tags []string, vars []any, panels []any, links []any, timeFrom string) M {
	return M{
		"uid":                  uid,
		"title":                title,
		"description":          desc,
		"tags":                 tags,
		"editable":             false,
		"graphTooltip":         1,
		"fiscalYearStartMonth": 0,
		"liveNow":              false,
		"refresh":              "1m",
		"schemaVersion":        SchemaVersion,
		"version":              1,
		"time":                 M{"from": timeFrom, "to": "now"},
		"timepicker":           M{"refresh_intervals": []string{"30s", "1m", "5m", "15m", "1h"}},
		"timezone":             "browser",
		"weekStart":            "",
		"templating":           M{"list": vars},
		"annotations":          M{"list": []any{builtinAnnotations()}},
		"links":                links,
		"panels":               panels,
	}
}

func builtinAnnotations() M {
	return M{
		"builtIn": 1, "datasource": M{"type": "grafana", "uid": "-- Grafana --"},
		"enable": true, "hide": true, "iconColor": "rgba(0, 211, 255, 1)",
		"name": "Annotations & Alerts", "type": "dashboard",
	}
}

// DatasourceVar picks the Prometheus data source (default tor-prometheus).
func DatasourceVar() M {
	return M{
		"name": "datasource", "label": "Data source", "type": "datasource", "query": "prometheus",
		"current": M{"text": "Tor Prometheus", "value": "tor-prometheus"},
		"hide":    0, "includeAll": false, "multi": false, "refresh": 1, "regex": "", "options": []any{},
	}
}

// QueryVar is a label_values variable.
func QueryVar(name, label, query string, multi bool) M {
	v := M{
		"name": name, "label": label, "type": "query", "datasource": ds,
		"query":   M{"query": query, "refId": "PrometheusVariableQueryEditor-VariableQuery", "qryType": 1},
		"refresh": 2, "sort": 1, "hide": 0, "regex": "", "options": []any{},
		"definition": query, "includeAll": multi, "multi": multi,
	}
	if multi {
		v["allValue"] = ".*"
		v["current"] = M{"text": []string{"All"}, "value": []string{"$__all"}}
	} else {
		v["current"] = M{}
	}
	return v
}
