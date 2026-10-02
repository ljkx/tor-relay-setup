package onionoo

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const fp1 = "0123456789ABCDEF0123456789ABCDEF01234567"
const fp2 = "89ABCDEF0123456789ABCDEF0123456789ABCDEF"

// server serves a fixed body and records the last request.
type server struct {
	*httptest.Server
	mu     sync.Mutex
	last   *http.Request
	status int
	body   string
}

func newServer(t *testing.T, status int, body string) *server {
	s := &server{status: status, body: body}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.last = r.Clone(context.Background())
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) client() Client { return Client{HTTP: s.Client(), Base: s.URL + "/"} }

func (s *server) request() *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

const detailsBody = `{"version":"8.0","relays":[{
  "nickname":"MyRelay","fingerprint":"` + fp1 + `","running":true,
  "flags":["Fast","Guard","Running","Stable","Valid"],
  "first_seen":"2026-01-01 00:00:00","last_seen":"2026-10-01 11:00:00",
  "advertised_bandwidth":12500000,"observed_bandwidth":13000000,"consensus_weight":42000,"consensus_weight_fraction":0.0000123,
  "platform":"Tor 0.4.9.3 on Linux","contact":"email:ops[]example.org ciissversion:2",
  "or_addresses":["203.0.113.5:9001","[2001:db8::5]:9001"],
  "family_ids":["hQ3yMkBnCdE4F5g6H7i8J9k0LmNoPqRsTuVwXyZ+/ab"],
  "exit_probability":0,"guard_probability":0.0012,"middle_probability":0.0008,
  "last_restarted":"2026-09-28 04:12:33","country":"DE","country_name":"Germany","as":"AS24940","as_name":"Hetzner Online GmbH",
  "unknown_field":{"x":1}
}]}`

func TestDetails(t *testing.T) {
	s := newServer(t, http.StatusOK, detailsBody)
	r, err := s.client().Details(context.Background(), "$"+strings.ToLower(fp1[:20])+" "+fp1[20:])
	if err != nil {
		t.Fatal(err)
	}
	want := &Relay{
		Nickname: "MyRelay", Fingerprint: fp1, Running: true,
		Flags:     []string{"Fast", "Guard", "Running", "Stable", "Valid"},
		FirstSeen: "2026-01-01 00:00:00", LastSeen: "2026-10-01 11:00:00",
		AdvertisedBandwidth: 12500000, ObservedBandwidth: 13000000, ConsensusWeight: 42000, ConsensusWeightFraction: 0.0000123,
		Platform: "Tor 0.4.9.3 on Linux", Contact: "email:ops[]example.org ciissversion:2",
		ORAddresses:      []string{"203.0.113.5:9001", "[2001:db8::5]:9001"},
		FamilyIDs:        []string{"hQ3yMkBnCdE4F5g6H7i8J9k0LmNoPqRsTuVwXyZ+/ab"},
		GuardProbability: 0.0012, MiddleProbability: 0.0008,
		LastRestarted: "2026-09-28 04:12:33", Country: "de", AS: "AS24940", ASName: "Hetzner Online GmbH",
	}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("got %+v\nwant %+v", r, want)
	}
	if got := ParseTime(r.LastRestarted); !got.Equal(time.Date(2026, 9, 28, 4, 12, 33, 0, time.UTC)) {
		t.Errorf("ParseTime(last_restarted) = %v", got)
	}
	if !ParseTime("").IsZero() || !ParseTime("yesterday").IsZero() {
		t.Error("ParseTime accepted garbage")
	}
	req := s.request()
	if req.URL.Path != "/details" || req.URL.Query().Get("lookup") != fp1 {
		t.Errorf("request %s", req.URL)
	}
	if ua := req.Header.Get("User-Agent"); ua != "tor-relay-setup" {
		t.Errorf("User-Agent %q", ua)
	}
}

func TestDetailsFamilyIDShapes(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
	}{
		{``, nil},
		{`,"family_ids":null`, nil},
		{`,"family_ids":["a","","b"]`, []string{"a", "b"}},
		{`,"family_ids":"single"`, []string{"single"}},
		{`,"family_ids":{"odd":true}`, nil},
		{`,"family_ids":[1,2]`, nil},
	}
	for _, tt := range tests {
		s := newServer(t, http.StatusOK, `{"relays":[{"nickname":"x"`+tt.raw+`}]}`)
		r, err := s.client().Details(context.Background(), fp1)
		if err != nil {
			t.Fatalf("%s: %v", tt.raw, err)
		}
		if !reflect.DeepEqual(r.FamilyIDs, tt.want) {
			t.Errorf("%s: FamilyIDs = %q, want %q", tt.raw, r.FamilyIDs, tt.want)
		}
	}
}

func TestDetailsOverloadGeneral(t *testing.T) {
	// Onionoo gives milliseconds, aligned to the hour (value seen on the live API).
	s := newServer(t, http.StatusOK, `{"relays":[{"nickname":"x","overload_general_timestamp":1790924400000}]}`)
	r, err := s.client().Details(context.Background(), fp1)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 2, 7, 0, 0, 0, time.UTC)
	if !r.OverloadGeneral.Equal(want) {
		t.Fatalf("OverloadGeneral = %v, want %v", r.OverloadGeneral, want)
	}
	if !r.Overloaded(want.Add(71*time.Hour)) || r.Overloaded(want.Add(72*time.Hour)) {
		t.Error("Relay Search shows overload for 72 hours")
	}
	var none *Relay
	if none.Overloaded(want) || (&Relay{}).Overloaded(want) {
		t.Error("no timestamp means not overloaded")
	}
}

func TestDetailsNotPublished(t *testing.T) {
	s := newServer(t, http.StatusOK, `{"version":"8.0","relays":[],"bridges":[]}`)
	r, err := s.client().Details(context.Background(), fp1)
	if r != nil || err != nil {
		t.Errorf("got %+v, %v", r, err)
	}
}

func TestDetailsInvalidFingerprint(t *testing.T) {
	s := newServer(t, http.StatusOK, detailsBody)
	for _, fp := range []string{"", "xyz", fp1[:39], fp1 + "0", strings.Replace(fp1, "0", "G", 1)} {
		if _, err := s.client().Details(context.Background(), fp); err == nil {
			t.Errorf("Details(%q) accepted", fp)
		}
	}
	if s.request() != nil {
		t.Error("invalid fingerprint reached the server")
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"server error", http.StatusInternalServerError, "oops", "500"},
		{"bad request", http.StatusBadRequest, "", "400"},
		{"bad json", http.StatusOK, "{not json", "decode"},
		{"oversized", http.StatusOK, `{"relays":[],"pad":"` + strings.Repeat("x", 2<<20) + `"}`, "larger than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newServer(t, tt.status, tt.body)
			_, err := s.client().Details(context.Background(), fp1)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}

	// Transport errors and cancellation surface too.
	s := newServer(t, http.StatusOK, detailsBody)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.client().Details(ctx, fp1); err == nil {
		t.Error("cancelled request succeeded")
	}
}

func TestSearch(t *testing.T) {
	body := `{"relays":[
	  {"n":"torRelayX","f":"` + strings.Repeat("A", 40) + `","r":true,"a":["198.51.100.1"]},
	  {"n":"TorRelay","f":"` + strings.Repeat("C", 40) + `","r":false,"a":["203.0.113.9"]},
	  {"n":"torrelay","f":"` + strings.Repeat("B", 40) + `","r":false},
	  {"n":"TorRelay","f":"` + strings.Repeat("D", 40) + `","r":true,"a":["203.0.113.5","[2001:db8::5]"]},
	  {"n":"AnotherTorRelay","f":"` + strings.Repeat("E", 40) + `","r":false}
	]}`
	s := newServer(t, http.StatusOK, body)
	got, err := s.client().Search(context.Background(), "TorRelay")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, r := range got {
		order = append(order, r.Nickname+"/"+r.Fingerprint[:1])
	}
	want := []string{"TorRelay/D", "torrelay/B", "TorRelay/C", "torRelayX/A", "AnotherTorRelay/E"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("order = %q, want %q", order, want)
	}
	if !reflect.DeepEqual(got[0].Addresses, []string{"203.0.113.5", "[2001:db8::5]"}) || !got[0].Running {
		t.Errorf("first = %+v", got[0])
	}

	q := s.request().URL.Query()
	wantQ := url.Values{"type": {"relay"}, "search": {"TorRelay"}, "limit": {"20"}}
	if s.request().URL.Path != "/summary" || !reflect.DeepEqual(q, wantQ) {
		t.Errorf("request %s", s.request().URL)
	}
}

func TestSearchInvalidNickname(t *testing.T) {
	s := newServer(t, http.StatusOK, `{"relays":[]}`)
	for _, n := range []string{"", "has space", "a&b=c", strings.Repeat("a", 20), "ünicode"} {
		if _, err := s.client().Search(context.Background(), n); err == nil {
			t.Errorf("Search(%q) accepted", n)
		}
	}
	if s.request() != nil {
		t.Error("invalid nickname reached the server")
	}
}

func TestStatus(t *testing.T) {
	s := newServer(t, http.StatusOK, `{"relays":[
	  {"n":"One","f":"`+fp1+`","r":true,"a":["203.0.113.5"]},
	  {"n":"Two","f":"`+fp2+`","r":false}
	]}`)
	got, err := s.client().Status(context.Background(), []string{fp1, strings.ToLower(fp2), "$" + fp1})
	if err != nil {
		t.Fatal(err)
	}
	want := []Summary{
		{Nickname: "One", Fingerprint: fp1, Running: true, Addresses: []string{"203.0.113.5"}},
		{Nickname: "Two", Fingerprint: fp2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	q := s.request().URL.Query()
	if q.Get("type") != "relay" || q.Get("lookup") != fp1+","+fp2 {
		t.Errorf("query %v", q)
	}

	if got, err := s.client().Status(context.Background(), nil); got != nil || err != nil {
		t.Errorf("empty: %v, %v", got, err)
	}
	if _, err := s.client().Status(context.Background(), []string{fp1, "bogus"}); err == nil {
		t.Error("invalid fingerprint accepted")
	}
}

func TestZeroClientDefaults(t *testing.T) {
	var c Client
	if c.base() != DefaultBase || c.client() != defaultHTTP || defaultHTTP.Timeout.Seconds() != 10 {
		t.Error("zero Client defaults")
	}
}

const bandwidthBody = `{"version":"8.0","relays":[{"fingerprint":"` + fp1 + `",
  "write_history":{
    "1_month":{"first":"2026-09-01 12:00:00","last":"2026-09-03 12:00:00","interval":86400,"factor":1000.5,"count":3,"values":[100,null,999]},
    "6_months":{"first":"2026-04-01 12:00:00","last":"2026-09-30 12:00:00","interval":172800,"factor":2,"count":1,"values":[5]}},
  "read_history":{
    "6_months":{"first":"2026-04-01 12:00:00","last":"2026-04-03 12:00:00","interval":172800,"factor":2,"count":2,"values":[5,7]}}
}]}`

func TestBandwidth(t *testing.T) {
	s := newServer(t, http.StatusOK, bandwidthBody)
	bw, err := s.client().Bandwidth(context.Background(), "$"+strings.ToLower(fp1))
	if err != nil {
		t.Fatal(err)
	}
	req := s.request()
	if req.URL.Path != "/bandwidth" || req.URL.Query().Get("lookup") != fp1 {
		t.Fatalf("request %s", req.URL)
	}
	w := bw.Written
	if len(w.Values) != 3 || w.Values[0] != 100050 || !math.IsNaN(w.Values[1]) || w.Values[2] != 999499.5 {
		t.Fatalf("written %v", w.Values)
	}
	if w.Interval != 24*time.Hour || w.First.Day() != 1 || w.Last.Day() != 3 {
		t.Fatalf("written %+v", w)
	}
	// No 1_month read graph: fall back to 6_months.
	if r := bw.Read; len(r.Values) != 2 || r.Values[1] != 14 {
		t.Fatalf("read %v", r.Values)
	}
}

func TestBandwidthUnlisted(t *testing.T) {
	s := newServer(t, http.StatusOK, `{"relays":[]}`)
	bw, err := s.client().Bandwidth(context.Background(), fp1)
	if bw != nil || err != nil {
		t.Fatalf("got %v, %v", bw, err)
	}
	if _, err := s.client().Bandwidth(context.Background(), "nope"); err == nil {
		t.Fatal("want a fingerprint error")
	}
	e := newServer(t, http.StatusInternalServerError, "")
	if _, err := e.client().Bandwidth(context.Background(), fp1); err == nil {
		t.Fatal("want a server error")
	}
}

// lookupServer answers /details and /bandwidth for any fingerprint in the
// lookup list except those in unlisted, and records every lookup.
type lookupServer struct {
	*httptest.Server
	mu       sync.Mutex
	lookups  []string
	unlisted map[string]bool
	fail     bool
}

func newLookupServer(t *testing.T) *lookupServer {
	s := &lookupServer{unlisted: map[string]bool{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		lookup := r.URL.Query().Get("lookup")
		s.lookups = append(s.lookups, r.URL.Path+" "+lookup)
		if s.fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var relays []string
		for _, fp := range strings.Split(lookup, ",") {
			if s.unlisted[fp] {
				continue
			}
			switch r.URL.Path {
			case "/details":
				relays = append(relays, `{"nickname":"R`+fp[:4]+`","fingerprint":"`+fp+`","running":true,"consensus_weight":7,"consensus_weight_fraction":0.5}`)
			case "/bandwidth":
				relays = append(relays, `{"fingerprint":"`+fp+`","read_history":{"1_month":{"first":"2026-09-01 12:00:00","last":"2026-09-01 12:00:00","interval":86400,"factor":1,"values":[3]}}}`)
			}
		}
		_, _ = w.Write([]byte(`{"relays":[` + strings.Join(relays, ",") + `]}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *lookupServer) client() Client { return Client{HTTP: s.Client(), Base: s.URL} }

func (s *lookupServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lookups...)
}

func (s *lookupServer) set(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

func manyFingerprints(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%040X", i+1)
	}
	return out
}

func TestDetailsBulkChunks(t *testing.T) {
	s := newLookupServer(t)
	fps := manyFingerprints(85)
	s.set(func() { s.unlisted[fps[3]] = true })
	// Lower case, a "$" and a duplicate are normalized away.
	in := append(append([]string{}, fps...), "$"+strings.ToLower(fps[0]))
	got, err := s.client().DetailsBulk(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 84 || got[fps[3]] != nil || got[fps[84]] == nil {
		t.Fatalf("got %d relays", len(got))
	}
	if r := got[fps[0]]; r.Nickname != "R0000" || r.ConsensusWeight != 7 || r.ConsensusWeightFraction != 0.5 {
		t.Errorf("relay = %+v", r)
	}
	var sizes []int
	for _, l := range s.requests() {
		if !strings.HasPrefix(l, "/details ") {
			t.Errorf("request %s", l)
		}
		sizes = append(sizes, len(strings.Split(strings.TrimPrefix(l, "/details "), ",")))
	}
	if !reflect.DeepEqual(sizes, []int{BulkChunk, BulkChunk, 5}) {
		t.Errorf("chunk sizes %v", sizes)
	}
}

func TestBandwidthBulk(t *testing.T) {
	s := newLookupServer(t)
	fps := manyFingerprints(41)
	got, err := s.client().BandwidthBulk(context.Background(), fps)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 41 || len(s.requests()) != 2 || got[fps[40]].Read.Values[0] != 3 || got[fps[40]].Read.Interval != 24*time.Hour {
		t.Errorf("got %d histories in %d requests", len(got), len(s.requests()))
	}
}

func TestBulkErrors(t *testing.T) {
	s := newLookupServer(t)
	if got, err := s.client().DetailsBulk(context.Background(), nil); err != nil || len(got) != 0 || len(s.requests()) != 0 {
		t.Errorf("no fingerprints: %v %v %v", got, err, s.requests())
	}
	if _, err := s.client().DetailsBulk(context.Background(), []string{fp1, "nope"}); err == nil || len(s.requests()) != 0 {
		t.Errorf("an invalid fingerprint should fail before any request: %v", err)
	}
	s.set(func() { s.fail = true })
	if _, err := s.client().DetailsBulk(context.Background(), manyFingerprints(50)); err == nil || !strings.Contains(err.Error(), "503") || len(s.requests()) != 1 {
		t.Errorf("server error: %v after %d requests", err, len(s.requests()))
	}
	if _, err := s.client().BandwidthBulk(context.Background(), []string{fp1}); err == nil {
		t.Error("bandwidth server error")
	}
}
