package serve

import (
	"crypto/sha256"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Session lifetimes.
const (
	SessionIdle     = 12 * time.Hour
	SessionAbsolute = 7 * 24 * time.Hour
	maxSessions     = 10_000
)

// session is one logged-in browser.
type session struct {
	user    string
	csrf    string // the token logout (and any future form) must send
	created time.Time
	seen    time.Time
}

// sessions keeps sessions in memory, keyed by the SHA-256 of their 256-bit
// random IDs so a map lookup leaks nothing useful about valid IDs through
// timing. A restart logs everybody out.
type sessions struct {
	mu  sync.Mutex
	m   map[[32]byte]*session
	now func() time.Time
}

func newSessions(now func() time.Time) *sessions {
	return &sessions{m: map[[32]byte]*session{}, now: now}
}

func (s *sessions) expired(se *session, now time.Time) bool {
	return now.Sub(se.seen) > SessionIdle || now.Sub(se.created) > SessionAbsolute
}

// create starts a session and returns its ID.
func (s *sessions) create(user string) (string, *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.m) >= maxSessions {
		s.pruneLocked(now)
		for len(s.m) >= maxSessions { // still full: drop the oldest
			var oldest [32]byte
			var at time.Time
			for k, se := range s.m {
				if at.IsZero() || se.seen.Before(at) {
					oldest, at = k, se.seen
				}
			}
			delete(s.m, oldest)
		}
	}
	id := randomID(32)
	se := &session{user: user, csrf: randomID(32), created: now, seen: now}
	s.m[sha256.Sum256([]byte(id))] = se
	return id, se
}

// get returns the live session for an ID and marks it used; expired
// sessions are removed.
func (s *sessions) get(id string) *session {
	if id == "" || len(id) > 128 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(id))
	se := s.m[key]
	if se == nil {
		return nil
	}
	now := s.now()
	if s.expired(se, now) {
		delete(s.m, key)
		return nil
	}
	se.seen = now
	c := *se
	return &c
}

func (s *sessions) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, sha256.Sum256([]byte(id)))
}

func (s *sessions) pruneLocked(now time.Time) {
	for k, se := range s.m {
		if s.expired(se, now) {
			delete(s.m, k)
		}
	}
}

// Login rate limits.
const (
	// freeFailures is how many wrong passwords a client may send before
	// the backoff starts; each further one doubles the wait.
	freeFailures = 3
	baseBackoff  = time.Second
	maxBackoff   = 15 * time.Minute
	// globalBurst and globalEvery limit failed logins over all clients: a
	// distributed guesser gets one try every globalEvery once the burst is
	// spent.
	globalBurst = 30
	globalEvery = 2 * time.Second
	maxClients  = 10_000
)

type client struct {
	failures int
	next     time.Time // no attempt before this
	seen     time.Time
}

// limiter slows down password guessing per client address and over all
// clients, with exponential backoff.
type limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	clients map[netip.Prefix]*client
	tokens  float64
	last    time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, clients: map[netip.Prefix]*client{}, tokens: globalBurst}
}

// clientKey groups IPv6 clients by /64, since one host usually has a
// whole /64 to rotate through.
func clientKey(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p
	}
	return netip.PrefixFrom(a, 32)
}

func (l *limiter) refillLocked(now time.Time) {
	if !l.last.IsZero() {
		l.tokens = min(globalBurst, l.tokens+now.Sub(l.last).Seconds()/globalEvery.Seconds())
	}
	l.last = now
}

// allow reports whether a login attempt from addr may be checked now, and
// otherwise how long to wait.
func (l *limiter) allow(addr netip.Addr) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.refillLocked(now)
	if c := l.clients[clientKey(addr)]; c != nil && now.Before(c.next) {
		return false, c.next.Sub(now)
	}
	if l.tokens < 1 {
		return false, time.Duration((1 - l.tokens) * float64(globalEvery))
	}
	return true, 0
}

// fail records a wrong password.
func (l *limiter) fail(addr netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.refillLocked(now)
	l.tokens = max(l.tokens-1, 0)
	key := clientKey(addr)
	c := l.clients[key]
	if c == nil {
		if len(l.clients) >= maxClients {
			l.pruneLocked(now)
		}
		c = &client{}
		l.clients[key] = c
	}
	c.failures++
	c.seen = now
	if c.failures >= freeFailures {
		wait := maxBackoff
		if shift := c.failures - freeFailures; shift < 20 {
			wait = min(baseBackoff<<shift, maxBackoff)
		}
		c.next = now.Add(wait)
	}
}

// succeed forgets a client's failures.
func (l *limiter) succeed(addr netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.clients, clientKey(addr))
}

// pruneLocked forgets clients that have been quiet for a day, then, if
// still full, the oldest.
func (l *limiter) pruneLocked(now time.Time) {
	for k, c := range l.clients {
		if now.Sub(c.seen) > 24*time.Hour {
			delete(l.clients, k)
		}
	}
	for len(l.clients) >= maxClients {
		var oldest netip.Prefix
		var at time.Time
		for k, c := range l.clients {
			if at.IsZero() || c.seen.Before(at) {
				oldest, at = k, c.seen
			}
		}
		delete(l.clients, oldest)
	}
}

// proxies are the trusted reverse proxies.
type proxies []netip.Prefix

func (p proxies) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, pr := range p {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

// peer is the address of the TCP peer.
func peer(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

// clientAddr is the client's address: the TCP peer, or, when the peer is a
// trusted proxy, the right-most X-Forwarded-For entry that is not itself a
// trusted proxy. Untrusted peers cannot choose their address this way.
func (p proxies) clientAddr(r *http.Request) netip.Addr {
	a := peer(r)
	if !p.trusted(a) {
		return a
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		h, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return a
		}
		if h = h.Unmap(); !p.trusted(h) {
			return h
		}
		a = h
	}
	return a
}

// https reports whether the browser talks HTTPS to us: TLS here, or a
// trusted proxy that says so in X-Forwarded-Proto.
func (p proxies) https(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return p.trusted(peer(r)) && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// secureCookies reports whether cookies get the Secure attribute (and so
// the __Host- prefix): always, except for plain HTTP to a name that is
// not localhost, where a browser would drop a Secure cookie.
func (p proxies) secureCookies(r *http.Request) bool {
	if p.https(r) {
		return true
	}
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") || strings.HasSuffix(strings.ToLower(h), ".localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Unmap().IsLoopback()
}
