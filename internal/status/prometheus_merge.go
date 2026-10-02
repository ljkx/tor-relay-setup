package status

import (
	"bytes"
	"io"
	"strings"
)

// WriteLoadPrometheusAll writes the load gauges of several tor instances as
// one valid exposition: each metric family gets a single # HELP/# TYPE
// header followed by the samples of every instance.
func WriteLoadPrometheusAll(w io.Writer, all []LoadMetrics) error {
	var buf bytes.Buffer
	for _, m := range all {
		if err := WriteLoadPrometheus(&buf, m); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, mergeFamilies(buf.String()))
	return err
}

// mergeFamilies regroups a Prometheus text exposition that repeats metric
// families (one block per instance) so each family appears once, in the
// order first seen, with its samples in input order.
func mergeFamilies(text string) string {
	type family struct {
		header  []string
		samples []string
	}
	var order []string
	families := map[string]*family{}
	current := ""
	get := func(name string) *family {
		f, ok := families[name]
		if !ok {
			f = &family{}
			families[name] = f
			order = append(order, name)
		}
		return f
	}
	for line := range strings.Lines(text) {
		line = strings.TrimRight(line, "\n")
		if line == "" {
			continue
		}
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "#" && (f[1] == "HELP" || f[1] == "TYPE") {
			current = f[2]
			fam := get(current)
			if len(fam.header) < 2 && !containsLine(fam.header, line) {
				fam.header = append(fam.header, line)
			}
			continue
		}
		name := line
		if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
		}
		// Samples belong to the family their header announced; _total and
		// similar suffixes keep the announced family.
		if current == "" || !strings.HasPrefix(name, current) {
			current = name
		}
		fam := get(current)
		fam.samples = append(fam.samples, line)
	}
	var b strings.Builder
	for _, name := range order {
		f := families[name]
		for _, l := range f.header {
			b.WriteString(l + "\n")
		}
		for _, l := range f.samples {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

func containsLine(lines []string, l string) bool {
	for _, x := range lines {
		if x == l {
			return true
		}
	}
	return false
}
