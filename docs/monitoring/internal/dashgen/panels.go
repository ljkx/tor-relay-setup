package dashgen

// Panel constructors with the dashboards' shared style.

func reduce(calc string) M {
	return M{"calcs": []string{calc}, "fields": "", "values": false}
}

// Stat is a single-value panel with a sparkline.
func Stat(title, desc string, w int, f Field, qs ...Q) Panel {
	return Panel{
		Type: "stat", Title: title, Desc: desc, W: w, H: 4, Targets: qs, Field: f,
		Options: M{
			"reduceOptions": reduce("lastNotNull"), "orientation": "auto", "textMode": "auto",
			"colorMode": "value", "graphMode": "area", "justifyMode": "center", "wideLayout": true,
			"showPercentChange": false, "percentChangeColorMode": "standard",
		},
	}
}

// StatNamed shows each series' name (legend) as the value: labels such as
// the tor version or flags.
func StatNamed(title, desc string, w int, f Field, qs ...Q) Panel {
	p := Stat(title, desc, w, f, qs...)
	p.Options["textMode"] = "name"
	p.Options["graphMode"] = "none"
	p.Options["colorMode"] = "background"
	return p
}

// StatState is a stat whose value maps to a word (Running, Stopped, ...).
func StatState(title, desc string, w int, mappings []any, qs ...Q) Panel {
	p := Stat(title, desc, w, Field{Mappings: mappings, Thresholds: []Step{{Color: Grey}}}, qs...)
	p.Options["graphMode"] = "none"
	p.Options["colorMode"] = "background"
	return p
}

func tsCustom(fill int, stack bool) M {
	stacking := M{"mode": "none", "group": "A"}
	if stack {
		stacking["mode"] = "normal"
	}
	return M{
		"drawStyle": "line", "lineInterpolation": "smooth", "lineWidth": 2, "fillOpacity": fill,
		"gradientMode": "opacity", "showPoints": "never", "pointSize": 4, "spanNulls": false,
		"insertNulls": false, "stacking": stacking, "axisPlacement": "auto", "axisLabel": "",
		"axisBorderShow": false, "axisCenteredZero": false, "axisColorMode": "text",
		"barAlignment": 0, "scaleDistribution": M{"type": "linear"},
		"hideFrom":        M{"legend": false, "tooltip": false, "viz": false},
		"thresholdsStyle": M{"mode": "off"},
	}
}

// Series is a time series panel.
func Series(title, desc string, w int, f Field, stack bool, qs ...Q) Panel {
	if f.ColorMode == "" {
		f.ColorMode = "palette-classic"
	}
	fill := 18
	if stack {
		fill = 40
	}
	f.Custom = mergeM(tsCustom(fill, stack), f.Custom)
	return Panel{
		Type: "timeseries", Title: title, Desc: desc, W: w, H: 8, Targets: qs, Field: f,
		Options: M{
			"legend":  M{"displayMode": "list", "placement": "bottom", "showLegend": true, "calcs": []string{}},
			"tooltip": M{"mode": "multi", "sort": "desc", "hideZeros": false},
		},
	}
}

// Bars is a time series panel drawn as bars, for per-hour or per-day sums.
func Bars(title, desc string, w int, f Field, interval string, stack bool, qs ...Q) Panel {
	p := Series(title, desc, w, f, stack, qs...)
	c := p.Field.Custom
	c["drawStyle"], c["fillOpacity"], c["lineWidth"], c["gradientMode"] = "bars", 85, 1, "none"
	c["axisSoftMin"] = 0
	p.Interval = interval
	return p
}

// withLegendTable shows a legend table with the given calculations.
func withLegendTable(p Panel, calcs ...string) Panel {
	p.Options["legend"] = M{"displayMode": "table", "placement": "bottom", "showLegend": true, "calcs": calcs, "sortBy": "Mean", "sortDesc": true}
	if len(calcs) == 0 || calcs[0] != "mean" {
		delete(p.Options["legend"].(M), "sortBy")
		delete(p.Options["legend"].(M), "sortDesc")
	}
	return p
}

// withThresholdLine draws the thresholds as dashed lines.
func withThresholdLine(p Panel) Panel {
	p.Field.Custom["thresholdsStyle"] = M{"mode": "dashed"}
	return p
}

// BarGauge is one horizontal bar per series.
func BarGauge(title, desc string, w, h int, f Field, qs ...Q) Panel {
	return Panel{
		Type: "bargauge", Title: title, Desc: desc, W: w, H: h, Targets: qs, Field: f,
		Options: M{
			"reduceOptions": reduce("lastNotNull"), "orientation": "horizontal", "displayMode": "gradient",
			"valueMode": "color", "namePlacement": "auto", "showUnfilled": true, "sizing": "auto",
			"minVizHeight": 16, "minVizWidth": 8, "maxVizHeight": 36,
			"legend": M{"displayMode": "list", "placement": "bottom", "showLegend": false, "calcs": []string{}},
		},
	}
}

// Pie is a donut chart.
func Pie(title, desc string, w, h int, f Field, qs ...Q) Panel {
	if f.ColorMode == "" {
		f.ColorMode = "palette-classic"
	}
	f.Custom = M{"hideFrom": M{"legend": false, "tooltip": false, "viz": false}}
	return Panel{
		Type: "piechart", Title: title, Desc: desc, W: w, H: h, Targets: qs, Field: f,
		Options: M{
			"reduceOptions": reduce("lastNotNull"), "pieType": "donut", "displayLabels": []string{"percent"},
			"legend":  M{"displayMode": "table", "placement": "right", "showLegend": true, "values": []string{"value", "percent"}},
			"tooltip": M{"mode": "single", "sort": "none", "hideZeros": false},
		},
	}
}

// Timeline is a state timeline.
func Timeline(title, desc string, w, h int, f Field, qs ...Q) Panel {
	if f.ColorMode == "" {
		// With thresholds colouring, the state timeline ignores the
		// mappings' colours; a fixed base colour lets them through.
		f.ColorMode, f.FixedColor = "fixed", Grey
	}
	f.Custom = M{"lineWidth": 0, "fillOpacity": 75, "hideFrom": M{"legend": false, "tooltip": false, "viz": false}}
	return Panel{
		Type: "state-timeline", Title: title, Desc: desc, W: w, H: h, Targets: qs, Field: f,
		Options: M{
			"showValue": "never", "rowHeight": 0.8, "mergeValues": true, "alignValue": "left",
			"legend":  M{"displayMode": "list", "placement": "bottom", "showLegend": true},
			"tooltip": M{"mode": "single", "sort": "none", "hideZeros": false},
		},
	}
}

// Table is a table of instant queries merged into one row per key.
func Table(title, desc string, w, h int, f Field, organize M, sortBy string, qs ...Q) Panel {
	f.Custom = mergeM(M{"align": "auto", "cellOptions": M{"type": "auto"}, "inspect": false, "filterable": true}, f.Custom)
	for i := range qs {
		qs[i].Instant, qs[i].Table = true, true
		// Aggregating drops __name__, which differs between queries and
		// would keep the merge transformation from joining the rows.
		qs[i].Expr = "max without () (" + qs[i].Expr + ")"
	}
	return Panel{
		Type: "table", Title: title, Desc: desc, W: w, H: h, Targets: qs, Field: f,
		Transformations: []any{
			M{"id": "merge", "options": M{}},
			M{"id": "organize", "options": organize},
		},
		Options: M{
			"showHeader": true, "cellHeight": "sm", "footer": M{"show": false, "reducer": []string{"sum"}, "fields": "", "countRows": false},
			"sortBy": []any{M{"displayName": sortBy, "desc": false}},
		},
	}
}

func mergeM(a, b M) M {
	for k, v := range b {
		a[k] = v
	}
	return a
}

// cellColor colours a table cell's text or background by its thresholds
// or mappings.
func cellColor(background bool) M {
	if background {
		return prop("custom.cellOptions", M{"type": "color-background", "mode": "basic", "applyToRow": false, "wrapText": false})
	}
	return prop("custom.cellOptions", M{"type": "color-text", "wrapText": false})
}
