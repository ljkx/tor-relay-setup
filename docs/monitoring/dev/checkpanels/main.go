// Command checkpanels asks a running Grafana for every panel query of the
// provisioned fleet dashboards (through /api/ds/query, like the browser
// does) and reports panels that return no data or an error. The relay
// detail dashboard is checked for every relay; a panel passes when at
// least one relay has data for it.
//
//	go run ./docs/monitoring/dev/checkpanels -url http://127.0.0.1:3000 -user tor-admin -password-file PATH
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	base   = flag.String("url", "http://127.0.0.1:3000", "Grafana URL")
	user   = flag.String("user", "tor-admin", "Grafana user")
	pwFile = flag.String("password-file", "", "file with the password")
	from   = flag.String("from", "now-24h", "time range start")
	allow  = flag.String("allow-empty", "", "comma-separated panel titles that may be empty")
	client = &http.Client{Timeout: 30 * time.Second}
	pass   string
)

type panel struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Interval    string `json:"interval"`
	Targets     []map[string]any
	Panels      []panel `json:"panels"`
}

func main() {
	flag.Parse()
	if *pwFile != "" {
		data, err := os.ReadFile(*pwFile)
		if err != nil {
			fail(err)
		}
		pass = strings.TrimSpace(string(data))
	}
	var hits []struct{ UID, Title string }
	get("/api/search?type=dash-db&tag=tor-relay-setup", &hits)
	if len(hits) < 2 {
		fail(fmt.Errorf("expected the two fleet dashboards, found %d", len(hits)))
	}
	hosts := labelValues("host", `tor_relay_fleet_relay_info`)
	var bad int
	for _, h := range hits {
		var d struct {
			Dashboard struct {
				Panels []panel `json:"panels"`
			} `json:"dashboard"`
			Meta struct {
				FolderTitle string `json:"folderTitle"`
			} `json:"meta"`
		}
		get("/api/dashboards/uid/"+h.UID, &d)
		fmt.Printf("== %s (folder %q)\n", h.Title, d.Meta.FolderTitle)
		var vars []map[string]string
		if h.UID == "tor-fleet-relay" {
			for _, host := range hosts {
				for _, nick := range labelValues("nickname", `tor_relay_fleet_relay_info{host="`+host+`"}`) {
					vars = append(vars, map[string]string{"host": host, "relay": nick})
				}
			}
		} else {
			vars = []map[string]string{{"host": ".*", "role": ".*"}}
		}
		for _, p := range flatten(d.Dashboard.Panels) {
			if p.Type == "row" {
				continue
			}
			ok, msg := false, ""
			for _, v := range vars {
				good, m := query(p, v)
				if good {
					ok = true
					break
				}
				msg = m
			}
			switch {
			case ok:
				fmt.Printf("  ok    %s\n", p.Title)
			case strings.Contains(","+*allow+",", ","+p.Title+","):
				fmt.Printf("  empty %s (allowed): %s\n", p.Title, msg)
			default:
				bad++
				fmt.Printf("  FAIL  %s: %s\n", p.Title, msg)
			}
		}
	}
	if bad > 0 {
		fmt.Printf("%d panel(s) without data\n", bad)
		os.Exit(1)
	}
	fmt.Println("every panel returned data")
}

func flatten(ps []panel) []panel {
	var out []panel
	for _, p := range ps {
		out = append(out, p)
		out = append(out, flatten(p.Panels)...)
	}
	return out
}

func subst(s string, vars map[string]string) string {
	s = strings.ReplaceAll(s, "${datasource}", "tor-prometheus")
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		s = strings.ReplaceAll(s, "$"+k, vars[k])
	}
	return s
}

// query runs all targets of p; it passes when any returns a value.
func query(p panel, vars map[string]string) (bool, string) {
	var qs []any
	for _, t := range p.Targets {
		if h, _ := t["hide"].(bool); h {
			continue
		}
		q := map[string]any{}
		for k, v := range t {
			q[k] = v
		}
		q["expr"] = subst(fmt.Sprint(t["expr"]), vars)
		q["datasource"] = map[string]string{"type": "prometheus", "uid": "tor-prometheus"}
		q["maxDataPoints"] = 500
		q["intervalMs"] = 60000
		if p.Interval == "1d" {
			q["intervalMs"] = 86400000
		}
		if p.Interval == "1h" {
			q["intervalMs"] = 3600000
		}
		qs = append(qs, q)
	}
	body, _ := json.Marshal(map[string]any{"queries": qs, "from": *from, "to": "now"})
	var res struct {
		Results map[string]struct {
			Error  string `json:"error"`
			Frames []struct {
				Data struct {
					Values [][]any `json:"values"`
				} `json:"data"`
			} `json:"frames"`
		} `json:"results"`
	}
	if err := post("/api/ds/query", body, &res); err != nil {
		return false, err.Error()
	}
	var errs []string
	for ref, r := range res.Results {
		if r.Error != "" {
			errs = append(errs, ref+": "+r.Error)
		}
		for _, f := range r.Frames {
			for i, col := range f.Data.Values {
				if i > 0 && len(col) > 0 && hasValue(col) {
					return true, ""
				}
			}
		}
	}
	if len(errs) > 0 {
		return false, strings.Join(errs, "; ")
	}
	return false, "no data"
}

func hasValue(col []any) bool {
	for _, v := range col {
		if v != nil {
			return true
		}
	}
	return false
}

func labelValues(label, match string) []string {
	var res struct {
		Data []string `json:"data"`
	}
	get("/api/datasources/proxy/uid/tor-prometheus/api/v1/label/"+label+"/values?match[]="+url.QueryEscape(match), &res)
	return res.Data
}

func get(path string, into any) {
	req, _ := http.NewRequest(http.MethodGet, *base+path, nil)
	if err := do(req, into); err != nil {
		fail(err)
	}
}

func post(path string, body []byte, into any) error {
	req, _ := http.NewRequest(http.MethodPost, *base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return do(req, into)
}

func do(req *http.Request, into any) error {
	req.SetBasicAuth(*user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s %s", req.Method, req.URL.Path, resp.Status, bytes.TrimSpace(data))
	}
	return json.Unmarshal(data, into)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "checkpanels:", err)
	os.Exit(1)
}
