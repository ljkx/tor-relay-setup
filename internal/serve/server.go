package serve

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
)

//go:embed web
var webFS embed.FS

// contentSecurityPolicy allows nothing but same-origin scripts, styles,
// images and fetches: no inline code, no frames, no foreign hosts.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Cookie names; the __Host- prefix makes browsers insist on Secure, Path=/
// and no Domain, so no other site or subdomain can set them.
const (
	sessionCookie = "trs"
	loginCookie   = "trs-login"
	hostPrefix    = "__Host-"
	// loginFormTTL bounds how long a login form stays usable.
	loginFormTTL = time.Hour
	// verifyParallel bounds concurrent argon2id checks (64 MiB each).
	verifyParallel = 2
	maxFormBytes   = 8 << 10
)

// Generic login messages: they never say whether the user exists.
const (
	msgInvalid  = "Invalid username or password."
	msgTooMany  = "Too many attempts. Wait a moment and try again."
	msgExpired  = "The login form expired. Please try again."
	msgRejected = "This request was refused."
)

// ServerOptions configures NewServer.
type ServerOptions struct {
	Config    Config
	Collector *Collector
	Log       *slog.Logger
	Now       func() time.Time
	Version   string
	Demo      bool
	// DemoLogin shows the fixed demo credentials on the login page.
	DemoLogin bool
}

// Server is the HTTP side of fleet serve.
type Server struct {
	cfg       Config
	coll      *Collector
	log       *slog.Logger
	now       func() time.Time
	version   string
	demo      bool
	demoLogin bool

	base      string
	users     map[string]User // by lower-case name
	dummy     string          // hash checked for unknown users, so they take as long
	tokenSum  []byte
	proxies   proxies
	sessions  *sessions
	limiter   *limiter
	verifying chan struct{}
	cop       *http.CrossOriginProtection
	pages     *template.Template
	static    fs.FS
}

// NewServer builds the handler; cfg must have passed Parse.
func NewServer(o ServerOptions) (*Server, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		cfg: o.Config, coll: o.Collector, log: o.Log, now: o.Now, version: o.Version, demo: o.Demo, demoLogin: o.DemoLogin,
		base: o.Config.BasePath, users: map[string]User{}, sessions: newSessions(o.Now), limiter: newLimiter(o.Now),
		verifying: make(chan struct{}, verifyParallel), cop: http.NewCrossOriginProtection(),
	}
	if s.base == "" {
		s.base = "/"
	}
	for _, u := range o.Config.Users {
		s.users[strings.ToLower(u.Name)] = u
	}
	// The dummy hash uses the first user's parameters, so checking it costs
	// what checking a real user costs.
	m, t, p := uint32(argonMemory), uint32(argonTime), uint8(argonThreads)
	if len(o.Config.Users) > 0 {
		if hp, err := parseHash(o.Config.Users[0].Hash); err == nil {
			m, t, p = hp.memory, hp.time, hp.threads
		}
	}
	s.dummy = hashWith(randomID(16), m, t, p)
	if o.Config.MetricsTokenSHA256 != "" {
		s.tokenSum, _ = hex.DecodeString(o.Config.MetricsTokenSHA256)
	}
	for _, tp := range o.Config.TrustedProxies {
		if pr, err := parsePrefix(tp); err == nil {
			s.proxies = append(s.proxies, pr)
		}
	}
	var err error
	if s.pages, err = template.ParseFS(webFS, "web/*.html"); err != nil {
		return nil, err
	}
	if s.static, err = fs.Sub(webFS, "web/static"); err != nil {
		return nil, err
	}
	return s, nil
}

// ServeHTTP routes a request. Paths are relative to base_path; a request
// without the prefix (a proxy that strips it) is routed the same way.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(w, r)
	p := r.URL.Path
	rel, ok := strings.CutPrefix(p, s.base)
	if !ok {
		if p+"/" == s.base {
			http.Redirect(w, r, s.base, http.StatusPermanentRedirect)
			return
		}
		rel = strings.TrimPrefix(p, "/")
	}
	switch {
	case rel == "":
		s.method(w, r, s.index, http.MethodGet, http.MethodHead)
	case rel == "login":
		s.method(w, r, s.login, http.MethodPost)
	case rel == "logout":
		s.method(w, r, s.logout, http.MethodPost)
	case rel == "api/fleet":
		s.method(w, r, s.api, http.MethodGet, http.MethodHead)
	case rel == "metrics":
		s.method(w, r, s.metrics, http.MethodGet, http.MethodHead)
	case rel == "healthz":
		s.method(w, r, s.healthz, http.MethodGet, http.MethodHead)
	case strings.HasPrefix(rel, "static/"):
		s.method(w, r, func(w http.ResponseWriter, r *http.Request) { s.serveStatic(w, strings.TrimPrefix(rel, "static/")) }, http.MethodGet, http.MethodHead)
	default:
		plain(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) method(w http.ResponseWriter, r *http.Request, h http.HandlerFunc, allowed ...string) {
	for _, m := range allowed {
		if r.Method == m {
			h(w, r)
			return
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	plain(w, http.StatusMethodNotAllowed, "method not allowed")
}

// securityHeaders go on every response.
func (s *Server) securityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if s.proxies.https(r) {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
}

func plain(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(msg + "\n"))
}

func (s *Server) cookieName(r *http.Request, name string) string {
	if s.proxies.secureCookies(r) {
		return hostPrefix + name
	}
	return name
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	// Secure is always set except for plain HTTP to a non-loopback name,
	// where a browser would drop the cookie (see secureCookies).
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see above
		Name: s.cookieName(r, name), Value: value, Path: "/", MaxAge: maxAge,
		Secure: s.proxies.secureCookies(r), HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// session returns the request's live session and its ID.
func (s *Server) session(r *http.Request) (string, *session) {
	c, err := r.Cookie(s.cookieName(r, sessionCookie))
	if err != nil {
		return "", nil
	}
	return c.Value, s.sessions.get(c.Value)
}

// bearer reports whether the request carries the metrics token.
func (s *Server) bearer(r *http.Request) bool {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	return ok && strings.EqualFold(scheme, "Bearer") && tokenMatches(strings.TrimSpace(token), s.tokenSum)
}

type pageData struct {
	Base, CSRF, User, Error, Version string
	Privacy, Demo, DemoLogin         bool
	DemoUser, DemoPassword           string
}

func (s *Server) render(w http.ResponseWriter, code int, page string, d pageData) {
	d.Base, d.Version, d.Privacy, d.Demo = s.base, s.version, s.cfg.Privacy, s.demo
	if s.demoLogin {
		d.DemoLogin, d.DemoUser, d.DemoPassword = true, DemoUser, DemoPassword
	}
	var b bytes.Buffer
	if err := s.pages.ExecuteTemplate(&b, page, d); err != nil {
		s.log.Error("template", "page", page, "err", err)
		plain(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(b.Bytes())
}

// index is the fleet overview, or the login form without a session.
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if _, se := s.session(r); se != nil {
		s.render(w, http.StatusOK, "app.html", pageData{CSRF: se.csrf, User: se.user})
		return
	}
	s.loginForm(w, r, http.StatusOK, "")
}

// loginForm renders the login page with a fresh form token, which is also
// set as a SameSite=Strict cookie (double submit).
func (s *Server) loginForm(w http.ResponseWriter, r *http.Request, code int, msg string) {
	token := randomID(32)
	s.setCookie(w, r, loginCookie, token, int(loginFormTTL.Seconds()))
	s.render(w, code, "login.html", pageData{CSRF: token, Error: msg})
}

func equal(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// login checks a username and password. Order: same-origin check, form
// token, rate limit, then argon2id (bounded concurrency, the same cost for
// unknown users), so the answer never tells whether a user exists.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := s.cop.Check(r); err != nil {
		plain(w, http.StatusForbidden, msgRejected)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		plain(w, http.StatusBadRequest, "bad request")
		return
	}
	c, err := r.Cookie(s.cookieName(r, loginCookie))
	if err != nil || !equal(c.Value, r.PostForm.Get("csrf")) {
		s.loginForm(w, r, http.StatusForbidden, msgExpired)
		return
	}
	addr := s.proxies.clientAddr(r)
	if ok, wait := s.limiter.allow(addr); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		s.loginForm(w, r, http.StatusTooManyRequests, msgTooMany)
		return
	}
	select {
	case s.verifying <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	// Re-check: requests that queued here may have been overtaken by
	// failures from the same client.
	if ok, wait := s.limiter.allow(addr); !ok {
		<-s.verifying
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		s.loginForm(w, r, http.StatusTooManyRequests, msgTooMany)
		return
	}
	user, ok := s.check(r.PostForm.Get("username"), r.PostForm.Get("password"))
	<-s.verifying
	if !ok {
		s.limiter.fail(addr)
		s.log.Warn("login failed", "client", addr.String())
		s.loginForm(w, r, http.StatusUnauthorized, msgInvalid)
		return
	}
	s.limiter.succeed(addr)
	id, _ := s.sessions.create(user)
	s.setCookie(w, r, sessionCookie, id, 0)
	s.setCookie(w, r, loginCookie, "", -1)
	s.log.Info("login", "user", user, "client", addr.String())
	http.Redirect(w, r, s.base, http.StatusSeeOther)
}

// check verifies credentials; it costs one argon2id run either way.
func (s *Server) check(name, password string) (string, bool) {
	u, known := s.users[strings.ToLower(name)]
	hash := s.dummy
	if known && len(name) <= 64 {
		hash = u.Hash
	}
	match := VerifyPassword(hash, password)
	if !known || !match {
		return "", false
	}
	return u.Name, true
}

// logout ends the session; the form carries the session's token.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.cop.Check(r); err != nil {
		plain(w, http.StatusForbidden, msgRejected)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		plain(w, http.StatusBadRequest, "bad request")
		return
	}
	id, se := s.session(r)
	if se != nil {
		if !equal(se.csrf, r.PostForm.Get("csrf")) {
			plain(w, http.StatusForbidden, msgRejected)
			return
		}
		s.sessions.remove(id)
		s.log.Info("logout", "user", se.user)
	}
	s.setCookie(w, r, sessionCookie, "", -1)
	http.Redirect(w, r, s.base, http.StatusSeeOther)
}

// api is the fleet as JSON, for the web UI (session) or scripts (token).
func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	if _, se := s.session(r); se == nil && !s.bearer(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tor-relay-setup"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var snap fleet.Snapshot
	s.coll.View(func(m *fleet.Model) { snap = m.Snapshot(s.now(), s.cfg.Privacy) })
	writeJSON(w, http.StatusOK, struct {
		fleet.Snapshot
		Demo    bool   `json:"demo,omitempty"`
		Version string `json:"version,omitempty"`
	}{snap, s.demo, s.version})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		plain(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(append(data, '\n'))
}

// metrics is the Prometheus exposition; it needs the bearer token unless
// metrics_auth = false on a loopback listener.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	open := s.cfg.MetricsOpen() && Loopback(s.cfg.Listen)
	if !open && !s.bearer(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tor-relay-setup"`)
		plain(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var b bytes.Buffer
	var err error
	s.coll.View(func(m *fleet.Model) {
		err = m.WritePrometheus(&b, fleet.PrometheusOptions{Privacy: s.cfg.Privacy, Now: s.now()})
	})
	if err != nil {
		plain(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b.Bytes())
}

// healthz says only whether probing works: no fleet data, no auth.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	if s.coll.Healthy() {
		plain(w, http.StatusOK, "ok")
		return
	}
	plain(w, http.StatusServiceUnavailable, "unavailable")
}

// staticTypes are the content types of the embedded files.
var staticTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
	".svg": "image/svg+xml",
}

func (s *Server) serveStatic(w http.ResponseWriter, name string) {
	typ, ok := staticTypes[path.Ext(name)]
	if !ok || strings.Contains(name, "/") {
		plain(w, http.StatusNotFound, "not found")
		return
	}
	data, err := fs.ReadFile(s.static, name)
	if err != nil {
		plain(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", typ)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data) //nolint:gosec // an embedded file, not user input
}
