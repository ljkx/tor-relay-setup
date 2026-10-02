// Package fleettest checks a Prometheus exposition against the fleet
// metrics contract in docs/monitoring/fleet-metrics.md. It is shared by
// the tests of fleet status and fleet serve.
package fleettest

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Prefix starts every name in the contract.
const Prefix = "tor_relay_fleet_"

// relayLabels are the labels every per-relay series carries.
var relayLabels = []string{"host", "tor_instance", "nickname", "fingerprint", "role"}

// Contract maps each metric name (with the prefix) to its sorted label
// names.
type Contract map[string][]string

// LoadContract parses the contract's tables.
func LoadContract(path string) (Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Contract{}
	section := ""
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "## "):
			section = strings.ToLower(line)
			continue
		case !strings.HasPrefix(line, "| `"):
			continue
		}
		cols := strings.Split(strings.ReplaceAll(line, `\|`, "/"), "|")
		if len(cols) < 3 {
			continue
		}
		var extra []string
		if strings.Contains(section, "per relay") {
			extra = append(extra, relayLabels...)
			extra = append(extra, ticked(parens.ReplaceAllString(cols[2], ""))...)
		}
		for _, name := range ticked(cols[1]) {
			labels := slices.Clone(extra)
			if i := strings.IndexByte(name, '{'); i >= 0 {
				for _, l := range strings.Split(strings.TrimSuffix(name[i+1:], "}"), ",") {
					l, _, _ = strings.Cut(l, "=")
					labels = append(labels, strings.TrimSpace(l))
				}
				name = name[:i]
			}
			sort.Strings(labels)
			c[Prefix+name] = labels
		}
	}
	if len(c) == 0 {
		return nil, fmt.Errorf("%s: no metric tables found", path)
	}
	return c, nil
}

var (
	parens = regexp.MustCompile(`\([^)]*\)`)
	tick   = regexp.MustCompile("`([^`]+)`")
)

func ticked(s string) []string {
	var out []string
	for _, m := range tick.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// Sample is one parsed sample line.
type Sample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// Exposition is a parsed Prometheus text exposition.
type Exposition struct {
	Types   map[string]string // family → gauge/counter
	Samples []Sample
}

// Find returns the samples of a family whose labels include all of want.
func (e Exposition) Find(name string, want map[string]string) []Sample {
	var out []Sample
	for _, s := range e.Samples {
		if s.Name != name {
			continue
		}
		ok := true
		for k, v := range want {
			if s.Labels[k] != v {
				ok = false
			}
		}
		if ok {
			out = append(out, s)
		}
	}
	return out
}

// Check parses text and returns every way it breaks the contract: a
// family outside the contract, wrong labels, a missing or repeated
// # HELP/# TYPE, a counter not ending in _total (or the reverse), samples
// of a family split up, and with requireAll any contract name that does
// not appear.
func (c Contract) Check(text string, requireAll bool) (Exposition, []string) {
	e := Exposition{Types: map[string]string{}}
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	helps := map[string]bool{}
	current := ""
	for n, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		switch {
		case line == "":
			bad("line %d: empty line", n+1)
		case strings.HasPrefix(line, "# HELP "):
			name, help, _ := strings.Cut(strings.TrimPrefix(line, "# HELP "), " ")
			if helps[name] {
				bad("%s: second # HELP", name)
			}
			if help == "" {
				bad("%s: empty help", name)
			}
			helps[name] = true
		case strings.HasPrefix(line, "# TYPE "):
			name, typ, _ := strings.Cut(strings.TrimPrefix(line, "# TYPE "), " ")
			if _, ok := e.Types[name]; ok {
				bad("%s: second # TYPE", name)
			}
			if !helps[name] {
				bad("%s: # TYPE without # HELP", name)
			}
			e.Types[name] = typ
			current = name
			if want := map[bool]string{true: "counter", false: "gauge"}[strings.HasSuffix(name, "_total")]; typ != want {
				bad("%s: type %s, want %s", name, typ, want)
			}
			if _, ok := c[name]; !ok {
				bad("%s: not in the contract", name)
			}
		case strings.HasPrefix(line, "#"):
			bad("line %d: unexpected comment %q", n+1, line)
		default:
			s, err := parseSample(line)
			if err != nil {
				bad("line %d: %v", n+1, err)
				continue
			}
			if s.Name != current {
				bad("%s: sample outside its family (after %s)", s.Name, current)
			}
			var got []string
			for k := range s.Labels {
				got = append(got, k)
			}
			sort.Strings(got)
			if want, ok := c[s.Name]; ok && !slices.Equal(got, want) {
				bad("%s: labels %v, want %v", s.Name, got, want)
			}
			e.Samples = append(e.Samples, s)
		}
	}
	if requireAll {
		var missing []string
		for name := range c {
			if _, ok := e.Types[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		for _, name := range missing {
			bad("%s: in the contract but not produced", name)
		}
	}
	return e, problems
}

// parseSample reads `name{k="v",...} value`.
func parseSample(line string) (Sample, error) {
	s := Sample{Labels: map[string]string{}}
	i := strings.IndexAny(line, "{ ")
	if i < 0 {
		return s, fmt.Errorf("no value in %q", line)
	}
	s.Name, line = line[:i], line[i:]
	if strings.HasPrefix(line, "{") {
		line = line[1:]
		for !strings.HasPrefix(line, "}") {
			eq := strings.Index(line, `="`)
			if eq <= 0 {
				return s, fmt.Errorf("bad labels in %s", s.Name)
			}
			key := line[:eq]
			line = line[eq+2:]
			var val strings.Builder
			j := 0
			for ; j < len(line) && line[j] != '"'; j++ {
				if line[j] == '\\' && j+1 < len(line) {
					j++
					switch line[j] {
					case 'n':
						val.WriteByte('\n')
					default:
						val.WriteByte(line[j])
					}
					continue
				}
				val.WriteByte(line[j])
			}
			if j >= len(line) {
				return s, fmt.Errorf("unterminated label in %s", s.Name)
			}
			if _, dup := s.Labels[key]; dup {
				return s, fmt.Errorf("%s: label %s twice", s.Name, key)
			}
			s.Labels[key] = val.String()
			line = strings.TrimPrefix(line[j+1:], ",")
		}
		line = line[1:]
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(line), 64)
	if err != nil {
		return s, fmt.Errorf("%s: bad value %q", s.Name, line)
	}
	s.Value = v
	return s, nil
}
