package serve

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/fleet/fleettest"
)

const (
	alicePassword = "correct horse battery"
	testToken     = "trs_test_token"
	localOrigin   = "http://127.0.0.1:9850"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	t    *testing.T
	srv  *Server
	coll *Collector
	clk  *clock
}

// newHarness is a server over the demo fleet, probed once, with user
// alice and a metrics token.
func newHarness(t *testing.T, mut func(*Config)) *harness {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	cfg := Defaults()
	cfg.Users = []User{{Name: "alice", Hash: cheapHash(alicePassword)}}
	cfg.MetricsTokenSHA256 = TokenSum(testToken)
	if mut != nil {
		mut(&cfg)
	}
	demo := NewDemo(DemoSeed, clk.now)
	coll := NewCollector(CollectorOptions{Inventory: demo.Inventory(), Source: demo, Now: clk.now, Interval: 30 * time.Second})
	srv, err := NewServer(ServerOptions{Config: cfg, Collector: coll, Now: clk.now, Version: "v9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, srv: srv, coll: coll, clk: clk}
}

// probe runs one round and the Tor Metrics lookup.
func (h *harness) probe() {
	h.coll.Round(context.Background())
	h.coll.maybeDirectory(context.Background())
	h.coll.wg.Wait()
}

type req struct {
	method, target string
	form           url.Values
	cookies        []*http.Cookie
	header         map[string]string
	remote         string
	tls            bool
}

func (h *harness) do(r req) *response {
	h.t.Helper()
	var body io.Reader
	if r.form != nil {
		body = strings.NewReader(r.form.Encode())
	}
	if r.method == "" {
		r.method = http.MethodGet
	}
	hr := httptest.NewRequest(r.method, r.target, body)
	hr.Host = "127.0.0.1:9850"
	if r.form != nil {
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	for _, c := range r.cookies {
		hr.AddCookie(c)
	}
	if r.remote != "" {
		hr.RemoteAddr = r.remote
	}
	if r.tls {
		hr.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, hr)
	return recorded(w)
}

// response is a recorded response with its body already read.
type response struct {
	StatusCode int
	Header     http.Header
	body       string
	cookies    []*http.Cookie
}

func (r *response) Cookies() []*http.Cookie { return r.cookies }

func recorded(w *httptest.ResponseRecorder) *response {
	res := w.Result()
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &response{StatusCode: res.StatusCode, Header: res.Header, body: string(b), cookies: res.Cookies()}
}

func readBody(_ *testing.T, res *response) string { return res.body }

func cookie(res *response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// loginForm fetches the login page and returns its cookie and token.
func (h *harness) loginForm() (*http.Cookie, string) {
	h.t.Helper()
	res := h.do(req{target: "/"})
	body := readBody(h.t, res)
	m := csrfField.FindStringSubmatch(body)
	c := cookie(res, "__Host-trs-login")
	if res.StatusCode != http.StatusOK || m == nil || c == nil {
		h.t.Fatalf("login page: %d %v\n%s", res.StatusCode, res.Cookies(), body)
	}
	return c, m[1]
}

func (h *harness) login(user, password, remote string) *response {
	h.t.Helper()
	c, token := h.loginForm()
	return h.do(req{method: http.MethodPost, target: "/login", cookies: []*http.Cookie{c}, remote: remote,
		form: url.Values{"csrf": {token}, "username": {user}, "password": {password}}, header: map[string]string{"Origin": localOrigin}})
}

// session logs alice in and returns the session cookie.
func (h *harness) session() *http.Cookie {
	h.t.Helper()
	res := h.login("alice", alicePassword, "")
	c := cookie(res, "__Host-trs")
	if res.StatusCode != http.StatusSeeOther || c == nil {
		h.t.Fatalf("login: %d %v %s", res.StatusCode, res.Cookies(), readBody(h.t, res))
	}
	return c
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t, nil)
	for _, r := range []req{
		{target: "/"}, {target: "/nope"}, {target: "/healthz"}, {target: "/metrics"}, {target: "/api/fleet"},
		{target: "/static/app.css"}, {method: http.MethodPost, target: "/login"}, {method: http.MethodDelete, target: "/"},
	} {
		res := h.do(r)
		for k, want := range map[string]string{
			"Content-Security-Policy":    contentSecurityPolicy,
			"X-Content-Type-Options":     "nosniff",
			"Referrer-Policy":            "no-referrer",
			"X-Frame-Options":            "DENY",
			"Cross-Origin-Opener-Policy": "same-origin",
		} {
			if got := res.Header.Get(k); got != want {
				t.Errorf("%s %s: %s = %q", r.method, r.target, k, got)
			}
		}
		if !strings.Contains(res.Header.Get("Permissions-Policy"), "camera=()") {
			t.Errorf("%s: Permissions-Policy %q", r.target, res.Header.Get("Permissions-Policy"))
		}
		if res.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS over plain HTTP", r.target)
		}
	}
	if !strings.HasPrefix(contentSecurityPolicy, "default-src 'self'") || strings.Contains(contentSecurityPolicy, "unsafe") {
		t.Errorf("CSP %q", contentSecurityPolicy)
	}
	if res := h.do(req{target: "/healthz", tls: true}); res.Header.Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS over TLS")
	}
	// A trusted proxy that terminates TLS gets HSTS too; an untrusted one cannot claim it.
	trusted := newHarness(t, func(c *Config) { c.TrustedProxies = []string{"127.0.0.1"} })
	xfp := map[string]string{"X-Forwarded-Proto": "https"}
	if res := trusted.do(req{target: "/healthz", remote: "127.0.0.1:5555", header: xfp}); res.Header.Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS behind a trusted TLS proxy")
	}
	if res := trusted.do(req{target: "/healthz", remote: "192.0.2.9:5555", header: xfp}); res.Header.Get("Strict-Transport-Security") != "" {
		t.Error("an untrusted peer set X-Forwarded-Proto")
	}
}

func TestStaticFilesAndPages(t *testing.T) {
	h := newHarness(t, nil)
	for target, typ := range map[string]string{
		"/static/app.css":  "text/css; charset=utf-8",
		"/static/app.js":   "text/javascript; charset=utf-8",
		"/static/icon.svg": "image/svg+xml",
		"/":                "text/html; charset=utf-8",
	} {
		res := h.do(req{target: target})
		if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != typ {
			t.Errorf("%s: %d %q", target, res.StatusCode, res.Header.Get("Content-Type"))
		}
	}
	for _, target := range []string{"/static/", "/static/missing.js", "/static/../app.html", "/static/app.html", "/web/app.html"} {
		if res := h.do(req{target: target}); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", target, res.StatusCode)
		}
	}
	if res := h.do(req{method: http.MethodPost, target: "/api/fleet"}); res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") == "" {
		t.Errorf("POST api: %d", res.StatusCode)
	}
}

// inlineCode finds anything the CSP would block or that runs code inline.
// (Script tags without src are checked separately.)
var inlineCode = regexp.MustCompile(`(?is)<style|\sstyle\s*=|\son[a-z]+\s*=|javascript:|<link[^>]+href="https?:|<script[^>]+src="https?:|@import|url\(`)

// inlineScript finds a script element without a src attribute.
func inlineScript(page string) string {
	for _, tag := range regexp.MustCompile(`(?i)<script[^>]*>`).FindAllString(page, -1) {
		if !strings.Contains(tag, " src=") {
			return tag
		}
	}
	return ""
}

func TestEmbeddedPagesHaveNoInlineCode(t *testing.T) {
	err := fs.WalkDir(webFS, "web", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, _ := webFS.ReadFile(path)
		s := string(data)
		if strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".svg") {
			if m := inlineCode.FindString(s); m != "" {
				t.Errorf("%s: inline code or a foreign resource: %q", path, m)
			}
		}
		if strings.HasSuffix(path, ".html") {
			for _, script := range regexp.MustCompile(`<script[^>]*>`).FindAllString(s, -1) {
				if !strings.Contains(script, `src="{{.Base}}static/`) {
					t.Errorf("%s: %s is not a same-origin file", path, script)
				}
			}
		}
		for _, foreign := range []string{"fonts.googleapis", "cdn.", "unpkg", "jsdelivr", "innerHTML", "eval(", "new Function", "document.write"} {
			if strings.Contains(s, foreign) {
				t.Errorf("%s uses %q", path, foreign)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The rendered pages too.
	h := newHarness(t, nil)
	login := readBody(t, h.do(req{target: "/"}))
	app := readBody(t, h.do(req{target: "/", cookies: []*http.Cookie{h.session()}}))
	for name, page := range map[string]string{"login": login, "app": app} {
		if m := inlineCode.FindString(page); m != "" {
			t.Errorf("%s page: %q", name, m)
		}
		if m := inlineScript(page); m != "" {
			t.Errorf("%s page: inline script %q", name, m)
		}
	}
	if !strings.Contains(app, `<script src="/static/app.js" defer>`) || !strings.Contains(app, `name="trs-base" content="/"`) {
		t.Errorf("app page:\n%s", app)
	}
}

func TestLoginFlowAndCookieFlags(t *testing.T) {
	h := newHarness(t, nil)
	h.probe()
	res := h.do(req{target: "/"})
	login := cookie(res, "__Host-trs-login")
	if login == nil || !login.Secure || !login.HttpOnly || login.SameSite != http.SameSiteStrictMode || login.Path != "/" || login.Domain != "" {
		t.Errorf("login cookie %+v", login)
	}
	if body := readBody(t, res); !strings.Contains(body, `action="/login"`) || strings.Contains(body, "Relays running") {
		t.Errorf("login page:\n%s", body)
	}

	res = h.login("alice", alicePassword, "")
	sess := cookie(res, "__Host-trs")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" || sess == nil {
		t.Fatalf("login: %d %v", res.StatusCode, res.Cookies())
	}
	if !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode || sess.Path != "/" || sess.Domain != "" || len(sess.Value) < 43 {
		t.Errorf("session cookie %+v", sess)
	}
	if c := cookie(res, "__Host-trs-login"); c == nil || c.MaxAge >= 0 {
		t.Errorf("the login cookie was not cleared: %+v", c)
	}
	page := readBody(t, h.do(req{target: "/", cookies: []*http.Cookie{sess}}))
	if !strings.Contains(page, `action="/logout"`) || !strings.Contains(page, ">alice<") {
		t.Errorf("app page:\n%s", page)
	}
	res = h.do(req{target: "/api/fleet", cookies: []*http.Cookie{sess}})
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json; charset=utf-8" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("api: %d %v", res.StatusCode, res.Header)
	}

	// Logout needs the session's form token.
	m := csrfField.FindStringSubmatch(page)
	if res := h.do(req{method: http.MethodPost, target: "/logout", cookies: []*http.Cookie{sess}, form: url.Values{"csrf": {"wrong"}}}); res.StatusCode != http.StatusForbidden {
		t.Errorf("logout with a wrong token: %d", res.StatusCode)
	}
	res = h.do(req{method: http.MethodPost, target: "/logout", cookies: []*http.Cookie{sess}, form: url.Values{"csrf": {m[1]}}, header: map[string]string{"Origin": localOrigin}})
	if res.StatusCode != http.StatusSeeOther || cookie(res, "__Host-trs") == nil || cookie(res, "__Host-trs").MaxAge >= 0 {
		t.Errorf("logout: %d %v", res.StatusCode, res.Cookies())
	}
	if res := h.do(req{target: "/api/fleet", cookies: []*http.Cookie{sess}}); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("session survived logout: %d", res.StatusCode)
	}
}

func TestPlainHTTPToANamedHostUsesUnprefixedCookies(t *testing.T) {
	h := newHarness(t, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "fleet.internal:9850"
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, r)
	res := recorded(w)
	c := cookie(res, "trs-login")
	if c == nil || c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookies %v", res.Cookies())
	}
}

func TestLoginFailuresAreGeneric(t *testing.T) {
	h := newHarness(t, nil)
	wrong := h.login("alice", "wrong password!", "192.0.2.10:1000")
	unknown := h.login("mallory", alicePassword, "192.0.2.11:1000")
	wb, ub := readBody(t, wrong), readBody(t, unknown)
	if wrong.StatusCode != http.StatusUnauthorized || unknown.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d %d", wrong.StatusCode, unknown.StatusCode)
	}
	if !strings.Contains(wb, msgInvalid) || !strings.Contains(ub, msgInvalid) {
		t.Errorf("messages:\n%s\n%s", wb, ub)
	}
	strip := func(s string) string { return csrfField.ReplaceAllString(s, "") }
	if strip(wb) != strip(ub) {
		t.Error("a wrong password and an unknown user look different")
	}
	if cookie(wrong, "__Host-trs") != nil || cookie(unknown, "__Host-trs") != nil {
		t.Error("a failed login set a session")
	}
}

func TestLoginCSRFAndOrigin(t *testing.T) {
	h := newHarness(t, nil)
	c, token := h.loginForm()
	form := url.Values{"csrf": {token}, "username": {"alice"}, "password": {alicePassword}}
	tests := []struct {
		name string
		r    req
		code int
	}{
		{"no cookie", req{form: form}, http.StatusForbidden},
		{"no token", req{form: url.Values{"username": {"alice"}, "password": {alicePassword}}, cookies: []*http.Cookie{c}}, http.StatusForbidden},
		{"wrong token", req{form: url.Values{"csrf": {"x" + token}, "username": {"alice"}, "password": {alicePassword}}, cookies: []*http.Cookie{c}}, http.StatusForbidden},
		{"foreign origin", req{form: form, cookies: []*http.Cookie{c}, header: map[string]string{"Origin": "https://evil.example"}}, http.StatusForbidden},
		{"cross-site fetch", req{form: form, cookies: []*http.Cookie{c}, header: map[string]string{"Sec-Fetch-Site": "cross-site"}}, http.StatusForbidden},
		{"same origin", req{form: form, cookies: []*http.Cookie{c}, header: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": localOrigin}}, http.StatusSeeOther},
	}
	for _, tt := range tests {
		tt.r.method, tt.r.target = http.MethodPost, "/login"
		if res := h.do(tt.r); res.StatusCode != tt.code {
			t.Errorf("%s: %d, want %d", tt.name, res.StatusCode, tt.code)
		}
	}
	// Logout from another site is refused too.
	sess := h.session()
	if res := h.do(req{method: http.MethodPost, target: "/logout", cookies: []*http.Cookie{sess}, header: map[string]string{"Origin": "https://evil.example"}}); res.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin logout: %d", res.StatusCode)
	}
}

func TestLoginRateLimitAndBackoff(t *testing.T) {
	h := newHarness(t, nil)
	ip := "198.51.100.7:4000"
	for i := range freeFailures {
		if res := h.login("alice", "wrong password!", ip); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i+1, res.StatusCode)
		}
	}
	res := h.login("alice", alicePassword, ip)
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" || !strings.Contains(readBody(t, res), msgTooMany) {
		t.Fatalf("after %d failures: %d", freeFailures, res.StatusCode)
	}
	// Another client is not affected; the same /64 is.
	if res := h.login("alice", alicePassword, "198.51.100.8:4000"); res.StatusCode != http.StatusSeeOther {
		t.Errorf("other client: %d", res.StatusCode)
	}
	h.clk.add(baseBackoff + time.Millisecond)
	if res := h.login("alice", "wrong again!!", ip); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after the backoff: %d", res.StatusCode)
	}
	// The next wait doubles.
	h.clk.add(baseBackoff + time.Millisecond)
	if res := h.login("alice", alicePassword, ip); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("backoff did not double: %d", res.StatusCode)
	}
	h.clk.add(baseBackoff)
	if res := h.login("alice", alicePassword, ip); res.StatusCode != http.StatusSeeOther {
		t.Errorf("after the doubled backoff: %d", res.StatusCode)
	}
	// Success forgets the failures.
	if res := h.login("alice", "wrong password!", ip); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("after success: %d", res.StatusCode)
	}
}

func TestLimiterBackoffCapAndGlobalLimit(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	l := newLimiter(clk.now)
	a := addr("203.0.113.1")
	for range 40 {
		l.fail(a)
	}
	if ok, wait := l.allow(a); ok || wait != maxBackoff {
		t.Errorf("capped backoff: %v %v", ok, wait)
	}
	// Distributed guessing: the global bucket runs dry.
	clk.add(time.Hour)
	l = newLimiter(clk.now)
	for i := range globalBurst {
		l.fail(addr("10.0." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250)))
	}
	if ok, _ := l.allow(addr("10.9.9.9")); ok {
		t.Error("global limit not reached")
	}
	clk.add(globalEvery)
	if ok, _ := l.allow(addr("10.9.9.9")); !ok {
		t.Error("global limit does not refill")
	}
	// IPv6 clients are grouped by /64.
	l = newLimiter(clk.now)
	l.fail(addr("2001:db8::1"))
	l.fail(addr("2001:db8::2"))
	l.fail(addr("2001:db8::3"))
	if ok, _ := l.allow(addr("2001:db8::ffff")); ok {
		t.Error("IPv6 /64 not grouped")
	}
	if ok, _ := l.allow(addr("2001:db8:1::1")); !ok {
		t.Error("another /64 blocked")
	}
}

func TestSessionExpiry(t *testing.T) {
	h := newHarness(t, nil)
	sess := h.session()
	api := func() int { return h.do(req{target: "/api/fleet", cookies: []*http.Cookie{sess}}).StatusCode }
	// Use keeps the session alive past the idle timeout...
	for range 15 {
		h.clk.add(11 * time.Hour)
		if code := api(); code != http.StatusOK {
			t.Fatalf("active session expired: %d", code)
		}
	}
	// ...but not past the absolute lifetime.
	h.clk.add(SessionAbsolute - 15*11*time.Hour + time.Minute)
	if code := api(); code != http.StatusUnauthorized {
		t.Errorf("after 7 days: %d", code)
	}
	sess = h.session()
	h.clk.add(SessionIdle + time.Second)
	if code := api(); code != http.StatusUnauthorized {
		t.Errorf("idle session: %d", code)
	}
	if h.srv.sessions.get("") != nil || h.srv.sessions.get(strings.Repeat("a", 200)) != nil {
		t.Error("bogus IDs")
	}
}

func TestMetricsAuth(t *testing.T) {
	h := newHarness(t, nil)
	h.probe()
	for name, hdr := range map[string]string{"none": "", "wrong": "Bearer nope", "basic": "Basic " + testToken, "bare": testToken} {
		res := h.do(req{target: "/metrics", header: map[string]string{"Authorization": hdr}})
		if res.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: %d", name, res.StatusCode)
		}
	}
	// A session is not enough for /metrics.
	if res := h.do(req{target: "/metrics", cookies: []*http.Cookie{h.session()}}); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("session on /metrics: %d", res.StatusCode)
	}
	res := h.do(req{target: "/metrics", header: map[string]string{"Authorization": "bearer " + testToken}})
	body := readBody(t, res)
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || !strings.Contains(body, "tor_relay_fleet_relays 12\n") {
		t.Errorf("metrics: %d %q\n%.300s", res.StatusCode, res.Header.Get("Content-Type"), body)
	}
	// The bearer token also opens the API.
	if res := h.do(req{target: "/api/fleet", header: map[string]string{"Authorization": "Bearer " + testToken}}); res.StatusCode != http.StatusOK {
		t.Errorf("api with token: %d", res.StatusCode)
	}

	open := newHarness(t, func(c *Config) { off := false; c.MetricsAuth = &off })
	if res := open.do(req{target: "/metrics"}); res.StatusCode != http.StatusOK {
		t.Errorf("metrics_auth = false on loopback: %d", res.StatusCode)
	}
	// metrics_auth = false never opens a non-loopback listener, even if it got past CheckListener.
	exposed := newHarness(t, func(c *Config) { off := false; c.MetricsAuth, c.Listen = &off, "0.0.0.0:9850" })
	if res := exposed.do(req{target: "/metrics"}); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("metrics_auth = false off loopback: %d", res.StatusCode)
	}
}

func TestPrivacyMode(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Privacy = true })
	h.probe()
	h.clk.add(30 * time.Second)
	h.probe()
	body := readBody(t, h.do(req{target: "/metrics", header: map[string]string{"Authorization": "Bearer " + testToken}}))
	if strings.Contains(body, "relay_traffic_bytes_total") || strings.Contains(body, "relay_or_connections") || !strings.Contains(body, "tor_relay_fleet_traffic_bytes_total{direction=\"read\"}") {
		t.Errorf("privacy metrics:\n%s", body)
	}
	var snap struct {
		Privacy bool `json:"privacy"`
		Relays  []map[string]any
	}
	if err := json.Unmarshal([]byte(readBody(t, h.do(req{target: "/api/fleet", header: map[string]string{"Authorization": "Bearer " + testToken}}))), &snap); err != nil {
		t.Fatal(err)
	}
	for _, r := range snap.Relays {
		for _, k := range []string{"live_read", "live_written", "or_connections"} {
			if _, ok := r[k]; ok {
				t.Errorf("privacy API has %s for %v", k, r["nickname"])
			}
		}
	}
	if !snap.Privacy {
		t.Error("privacy flag")
	}
	page := readBody(t, h.do(req{target: "/", cookies: []*http.Cookie{h.session()}}))
	if !strings.Contains(page, `name="trs-privacy" content="1"`) {
		t.Error("the page does not know about privacy mode")
	}
}

func TestAPIShape(t *testing.T) {
	h := newHarness(t, nil)
	h.probe()
	res := h.do(req{target: "/api/fleet", header: map[string]string{"Authorization": "Bearer " + testToken}})
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readBody(t, res)), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"generated_at", "privacy", "last_probe", "directory_updated", "totals", "history", "tor_versions", "hosts", "relays", "attention", "version"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("api lacks %q", k)
		}
	}
	var relays []map[string]any
	_ = json.Unmarshal(doc["relays"], &relays)
	if len(relays) != 12 {
		t.Fatalf("%d relays", len(relays))
	}
	for _, k := range []string{"id", "host", "instance", "nickname", "fingerprint", "role", "state", "fresh", "warnings", "directory"} {
		if _, ok := relays[0][k]; !ok {
			t.Errorf("relay lacks %q: %v", k, relays[0])
		}
	}
	var unauth map[string]string
	res = h.do(req{target: "/api/fleet"})
	_ = json.Unmarshal([]byte(readBody(t, res)), &unauth)
	if res.StatusCode != http.StatusUnauthorized || unauth["error"] != "unauthorized" {
		t.Errorf("unauthorized api: %d %v", res.StatusCode, unauth)
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, nil)
	res := h.do(req{target: "/healthz"})
	if body := readBody(t, res); res.StatusCode != http.StatusServiceUnavailable || body != "unavailable\n" {
		t.Errorf("before a probe: %d %q", res.StatusCode, body)
	}
	h.probe()
	res = h.do(req{target: "/healthz"})
	if body := readBody(t, res); res.StatusCode != http.StatusOK || body != "ok\n" {
		t.Errorf("after a probe: %d %q", res.StatusCode, body)
	}
	h.clk.add(10 * time.Minute)
	if res := h.do(req{target: "/healthz"}); res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("stale probes: %d", res.StatusCode)
	}
}

func TestBasePath(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.BasePath = "/fleet/" })
	h.probe()
	if res := h.do(req{target: "/fleet"}); res.StatusCode != http.StatusPermanentRedirect || res.Header.Get("Location") != "/fleet/" {
		t.Errorf("/fleet: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res := h.do(req{target: "/fleet/"})
	body := readBody(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `action="/fleet/login"`) || !strings.Contains(body, `href="/fleet/static/app.css"`) {
		t.Errorf("login page under /fleet/:\n%s", body)
	}
	for _, target := range []string{"/fleet/healthz", "/fleet/static/app.js", "/healthz", "/static/app.js"} {
		if res := h.do(req{target: target}); res.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", target, res.StatusCode)
		}
	}
	for _, target := range []string{"/fleet/metrics", "/metrics"} {
		if res := h.do(req{target: target, header: map[string]string{"Authorization": "Bearer " + testToken}}); res.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", target, res.StatusCode)
		}
	}
	m := csrfField.FindStringSubmatch(body)
	res = h.do(req{method: http.MethodPost, target: "/fleet/login", cookies: res.Cookies(), header: map[string]string{"Origin": localOrigin},
		form: url.Values{"csrf": {m[1]}, "username": {"alice"}, "password": {alicePassword}}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/fleet/" {
		t.Fatalf("login under /fleet/: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	app := readBody(t, h.do(req{target: "/fleet/", cookies: []*http.Cookie{cookie(res, "__Host-trs")}}))
	if !strings.Contains(app, `name="trs-base" content="/fleet/"`) || !strings.Contains(app, `src="/fleet/static/app.js"`) {
		t.Errorf("app under /fleet/:\n%s", app)
	}
	if res := h.do(req{target: "/other/"}); res.StatusCode != http.StatusNotFound {
		t.Errorf("/other/: %d", res.StatusCode)
	}
}

func TestDemoLoginHint(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	cfg := Defaults()
	login, err := UseDemoCredentials(&cfg)
	if err != nil || !login || cfg.Users[0].Name != DemoUser || cfg.MetricsTokenSHA256 != TokenSum(DemoToken) {
		t.Fatalf("demo credentials: %v %v %+v", login, err, cfg)
	}
	if !VerifyPassword(cfg.Users[0].Hash, DemoPassword) {
		t.Error("demo password")
	}
	d := NewDemo(DemoSeed, clk.now)
	srv, err := NewServer(ServerOptions{Config: cfg, Collector: NewCollector(CollectorOptions{Inventory: d.Inventory(), Source: d, Now: clk.now}), Demo: true, DemoLogin: true})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if body := w.Body.String(); !strings.Contains(body, DemoPassword) || !strings.Contains(body, ">demo<") {
		t.Errorf("demo login page:\n%s", body)
	}
	// Not on a public address, and not over configured credentials.
	pub := Defaults()
	pub.Listen = "0.0.0.0:9850"
	if _, err := UseDemoCredentials(&pub); err == nil {
		t.Error("demo credentials on a public listener")
	}
	own := Defaults()
	own.Users, own.MetricsTokenSHA256 = []User{{Name: "alice", Hash: cheapHash(alicePassword)}}, TokenSum("t")
	if login, err := UseDemoCredentials(&own); login || err != nil || own.Users[0].Name != "alice" || own.MetricsTokenSHA256 != TokenSum("t") {
		t.Errorf("configured credentials replaced: %+v", own)
	}
}

func TestDemoMetricsCoverTheContract(t *testing.T) {
	c, err := fleettest.LoadContract("../../docs/monitoring/fleet-metrics.md")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, nil)
	h.probe()
	h.clk.add(30 * time.Second)
	h.probe()
	body := readBody(t, h.do(req{target: "/metrics", header: map[string]string{"Authorization": "Bearer " + testToken}}))
	_, problems := c.Check(body, true)
	for _, p := range problems {
		t.Error(p)
	}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// A second load of the login page (another tab, a reload) keeps the form
// token the browser already holds, so the first page still signs in.
func TestLoginPageKeepsTheBrowsersFormToken(t *testing.T) {
	h := newHarness(t, nil)
	first := cookie(h.do(req{target: "/"}), "__Host-trs-login")
	if first == nil {
		t.Fatal("no login cookie")
	}
	again := h.do(req{target: "/", cookies: []*http.Cookie{first}})
	if c := cookie(again, "__Host-trs-login"); c == nil || c.Value != first.Value {
		t.Errorf("token rotated on reload: %v", again.Cookies())
	}
	if !strings.Contains(readBody(t, again), first.Value) {
		t.Error("the page does not carry the kept token")
	}
	// A malformed cookie is replaced.
	bad := h.do(req{target: "/", cookies: []*http.Cookie{{Name: "__Host-trs-login", Value: "short"}}})
	if c := cookie(bad, "__Host-trs-login"); c == nil || c.Value == "short" || !validToken(c.Value) {
		t.Errorf("malformed token kept: %v", bad.Cookies())
	}
}
