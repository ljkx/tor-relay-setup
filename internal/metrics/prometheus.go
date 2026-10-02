package metrics

import (
	"bytes"
	"io"
	"strconv"
	"strings"
)

// Exposition builds a Prometheus text exposition (version 0.0.4) one metric
// family at a time: call Family, then add its samples.
type Exposition struct {
	buf bytes.Buffer
}

// Label is one name="value" pair.
type Label struct{ Name, Value string }

// Family starts a metric family with its # HELP and # TYPE lines. typ is
// "gauge" or "counter".
func (e *Exposition) Family(name, typ, help string) {
	e.buf.WriteString("# HELP " + name + " " + escapeHelp(help) + "\n")
	e.buf.WriteString("# TYPE " + name + " " + typ + "\n")
}

// Uint adds an integer sample.
func (e *Exposition) Uint(name string, v uint64, labels ...Label) {
	e.sample(name, strconv.FormatUint(v, 10), labels)
}

// Float adds a sample with a fractional value.
func (e *Exposition) Float(name string, v float64, labels ...Label) {
	e.sample(name, strconv.FormatFloat(v, 'g', -1, 64), labels)
}

// Bool adds a 0/1 sample.
func (e *Exposition) Bool(name string, v bool, labels ...Label) {
	if v {
		e.sample(name, "1", labels)
	} else {
		e.sample(name, "0", labels)
	}
}

// Gauge adds a family with a single integer sample.
func (e *Exposition) Gauge(name, help string, v uint64, labels ...Label) {
	e.Family(name, "gauge", help)
	e.Uint(name, v, labels...)
}

func (e *Exposition) sample(name, value string, labels []Label) {
	e.buf.WriteString(name)
	if len(labels) > 0 {
		e.buf.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				e.buf.WriteByte(',')
			}
			e.buf.WriteString(l.Name + `="` + escapeLabel(l.Value) + `"`)
		}
		e.buf.WriteByte('}')
	}
	e.buf.WriteString(" " + value + "\n")
}

// WriteTo writes the exposition built so far.
func (e *Exposition) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(e.buf.Bytes())
	return int64(n), err
}

// escapeLabel escapes a label value: backslash, double quote, and line feed.
func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// escapeHelp escapes HELP text: backslash and line feed.
func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}
