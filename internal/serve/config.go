// Package serve is `tor-relay-setup fleet serve`: a long-running,
// read-only service for a management machine that probes the fleet on a
// schedule and serves Prometheus metrics, a JSON API and a web UI.
//
// It never changes a relay: probes run `tor-relay-setup fleet-probe`,
// which only reads. Everything it writes on the management machine (the
// flag cache, ACME certificates, serve.toml for passwd and token) goes
// through internal/host.
package serve

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Defaults.
const (
	DefaultConfig        = "/etc/tor-relay-setup/serve.toml"
	DefaultListen        = "127.0.0.1:9850"
	DefaultProbeInterval = 30 * time.Second
	DefaultACMECache     = "/var/lib/tor-relay-setup/acme"

	minProbeInterval = 5 * time.Second
	maxProbeInterval = time.Hour
)

// Duration is a TOML duration string such as "30s" or "2m".
type Duration struct{ time.Duration }

// UnmarshalText accepts Go duration syntax only (never bare numbers,
// which would be nanoseconds).
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("%q is not a duration such as \"30s\" or \"2m\"", b)
	}
	d.Duration = v
	return nil
}

// User is one web UI account.
type User struct {
	Name string `toml:"name"`
	Hash string `toml:"hash"` // argon2id, PHC string format
}

// Config is serve.toml.
type Config struct {
	Listen        string   `toml:"listen"`
	BasePath      string   `toml:"base_path"`
	Inventory     string   `toml:"inventory"`
	ProbeInterval Duration `toml:"probe_interval"`
	// Privacy leaves per-relay traffic and connection counts out of
	// /metrics, the API and the web UI.
	Privacy bool `toml:"privacy"`
	// MetricsAuth = false opens /metrics without a token; only allowed on
	// a loopback listener. nil means true.
	MetricsAuth        *bool    `toml:"metrics_auth"`
	MetricsTokenSHA256 string   `toml:"metrics_token_sha256"`
	Users              []User   `toml:"users"`
	TLSCert            string   `toml:"tls_cert"`
	TLSKey             string   `toml:"tls_key"`
	ACMEDomains        []string `toml:"acme_domains"`
	ACMEEmail          string   `toml:"acme_email"`
	ACMECache          string   `toml:"acme_cache"`
	TrustedProxies     []string `toml:"trusted_proxies"`

	// Path is the file the config came from; empty for defaults.
	Path string `toml:"-"`
}

// Defaults returns the configuration of an empty serve.toml.
func Defaults() Config {
	return Config{Listen: DefaultListen, BasePath: "/", ProbeInterval: Duration{DefaultProbeInterval}}
}

// Load reads and validates serve.toml through h. The file must not be
// readable by group or others: it holds password hashes and the token
// hash, which allow offline guessing.
func Load(h host.Host, path string) (Config, error) {
	info, err := h.Stat(path)
	if err != nil {
		return Config{}, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return Config{}, fmt.Errorf("%s is readable by other users (mode %04o); run: chmod 600 %s", path, perm, path)
	}
	data, err := h.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	c, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path
	if c.Inventory != "" && !filepath.IsAbs(c.Inventory) {
		c.Inventory = filepath.Join(filepath.Dir(path), c.Inventory)
	}
	return c, nil
}

// Parse decodes serve.toml strictly (unknown keys are errors), fills in
// defaults and validates every value.
func Parse(data []byte) (Config, error) {
	c := Defaults()
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&c)
	if err != nil {
		return Config{}, fmt.Errorf("parse: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	if err := c.normalize(); err != nil {
		return Config{}, err
	}
	return c, nil
}

var (
	basePathPattern = regexp.MustCompile(`^/(?:[A-Za-z0-9._~-]+/)*$`)
	userPattern     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	domainPattern   = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
)

// ValidUserName reports whether s can name a web UI account.
func ValidUserName(s string) bool { return userPattern.MatchString(s) }

func (c *Config) normalize() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if _, port, err := net.SplitHostPort(c.Listen); err != nil {
		bad("listen: %q is not host:port (e.g. %q)", c.Listen, DefaultListen)
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		bad("listen: port %q must be 1-65535", port)
	}

	if c.BasePath == "" {
		c.BasePath = "/"
	}
	if !strings.HasSuffix(c.BasePath, "/") {
		c.BasePath += "/"
	}
	if !basePathPattern.MatchString(c.BasePath) || strings.Contains(c.BasePath, "/../") || strings.Contains(c.BasePath, "/./") {
		bad("base_path: %q must be a plain path such as \"/\" or \"/fleet/\"", c.BasePath)
	}

	if c.ProbeInterval.Duration < minProbeInterval || c.ProbeInterval.Duration > maxProbeInterval {
		bad("probe_interval: must be between %s and %s", minProbeInterval, maxProbeInterval)
	}

	if c.MetricsTokenSHA256 != "" {
		c.MetricsTokenSHA256 = strings.ToLower(c.MetricsTokenSHA256)
		if b, err := hex.DecodeString(c.MetricsTokenSHA256); err != nil || len(b) != 32 {
			bad("metrics_token_sha256: want 64 hex digits (tor-relay-setup fleet serve token writes it)")
		}
	}

	seen := map[string]bool{}
	for i, u := range c.Users {
		switch {
		case !ValidUserName(u.Name):
			bad("users[%d]: name %q must be 1-64 letters, digits, '.', '_' or '-'", i, u.Name)
		case seen[strings.ToLower(u.Name)]:
			bad("users: %q is listed twice", u.Name)
		}
		seen[strings.ToLower(u.Name)] = true
		if _, err := parseHash(u.Hash); err != nil {
			bad("users[%d] (%s): hash: %v (set it with tor-relay-setup fleet serve passwd %s)", i, u.Name, err, u.Name)
		}
	}

	if (c.TLSCert == "") != (c.TLSKey == "") {
		bad("tls_cert and tls_key go together")
	}
	if len(c.ACMEDomains) > 0 {
		if c.TLSCert != "" {
			bad("use either tls_cert/tls_key or acme_domains, not both")
		}
		for i, d := range c.ACMEDomains {
			d = strings.ToLower(strings.TrimSuffix(d, "."))
			c.ACMEDomains[i] = d
			if !domainPattern.MatchString(d) {
				bad("acme_domains: %q is not a DNS name", d)
			}
		}
		if c.ACMECache == "" {
			c.ACMECache = DefaultACMECache
		}
		if !filepath.IsAbs(c.ACMECache) {
			bad("acme_cache: must be an absolute path")
		}
	} else if c.ACMEEmail != "" || c.ACMECache != "" {
		bad("acme_email and acme_cache need acme_domains")
	}
	if c.ACMEEmail != "" && (!strings.Contains(c.ACMEEmail, "@") || strings.ContainsAny(c.ACMEEmail, " \t\r\n<>")) {
		bad("acme_email: %q is not an email address", c.ACMEEmail)
	}

	for _, p := range c.TrustedProxies {
		if _, err := parsePrefix(p); err != nil {
			bad("trusted_proxies: %q is not an IP address or CIDR range", p)
		}
	}
	return errors.Join(errs...)
}

// parsePrefix reads "203.0.113.5" or "10.0.0.0/8".
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// TLS reports whether the service terminates TLS itself.
func (c Config) TLS() bool { return c.TLSCert != "" || len(c.ACMEDomains) > 0 }

// MetricsOpen reports whether /metrics is served without a token.
func (c Config) MetricsOpen() bool { return c.MetricsAuth != nil && !*c.MetricsAuth }

// Loopback reports whether addr (host:port) listens on loopback only.
func Loopback(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Unmap().IsLoopback()
}

// CheckListener refuses setups that would expose the service carelessly:
// plain HTTP and an open /metrics are only allowed on loopback.
func (c Config) CheckListener() error {
	loop := Loopback(c.Listen)
	switch {
	case !c.TLS() && !loop:
		return fmt.Errorf("listen %s is not a loopback address, and serving plain HTTP there would expose logins and tokens: "+
			"set tls_cert/tls_key or acme_domains, or listen on 127.0.0.1 behind a TLS reverse proxy", c.Listen)
	case c.MetricsOpen() && !loop:
		return errors.New("metrics_auth = false is only allowed on a loopback listener")
	}
	return nil
}

// SetToken returns serve.toml with metrics_token_sha256 set to sum,
// keeping everything else (comments included) as it was.
func SetToken(data []byte, sum string) ([]byte, error) {
	lines := splitLines(data)
	assign := `metrics_token_sha256 = "` + sum + `"`
	tableAt := len(lines)
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			tableAt = i
			break
		}
		if keyOf(t) == "metrics_token_sha256" {
			lines[i] = assign
			return verify(joinLines(lines), func(c Config) bool { return c.MetricsTokenSHA256 == sum })
		}
	}
	// After the last top-level line, keeping the blank line before tables.
	at := tableAt
	for at > 0 && strings.TrimSpace(lines[at-1]) == "" {
		at--
	}
	lines = slices.Insert(lines, at, assign)
	if at+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[at+1]), "[") {
		lines = slices.Insert(lines, at+1, "")
	}
	return verify(joinLines(lines), func(c Config) bool { return c.MetricsTokenSHA256 == sum })
}

// SetUser returns serve.toml with the user's hash set: the existing
// [[users]] entry is updated, or a new one appended.
func SetUser(data []byte, name, hash string) ([]byte, error) {
	lines := splitLines(data)
	assign := `hash = "` + hash + `"`
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "[[users]]" {
			continue
		}
		end := len(lines)
		for j := i + 1; j < len(lines); j++ {
			if strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
				end = j
				break
			}
		}
		nameAt, hashAt := -1, -1
		for j := i + 1; j < end; j++ {
			t := strings.TrimSpace(lines[j])
			switch keyOf(t) {
			case "name":
				var v struct {
					Name string `toml:"name"`
				}
				if _, err := toml.Decode(t, &v); err == nil && strings.EqualFold(v.Name, name) {
					nameAt = j
				}
			case "hash":
				hashAt = j
			}
		}
		if nameAt < 0 {
			continue
		}
		if hashAt >= 0 {
			lines[hashAt] = assign
		} else {
			lines = slices.Insert(lines, nameAt+1, assign)
		}
		return verify(joinLines(lines), userHas(name, hash))
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	lines = append(lines, "[[users]]", `name = "`+name+`"`, assign)
	return verify(joinLines(lines), userHas(name, hash))
}

func userHas(name, hash string) func(Config) bool {
	return func(c Config) bool {
		for _, u := range c.Users {
			if strings.EqualFold(u.Name, name) {
				return u.Hash == hash
			}
		}
		return false
	}
}

// verify re-parses an edited file and checks the edit took effect, so an
// unusual layout never yields a silently wrong config.
func verify(data []byte, ok func(Config) bool) ([]byte, error) {
	c, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("the edited configuration does not parse: %w", err)
	}
	if !ok(c) {
		return nil, errors.New("could not update the configuration automatically; edit it by hand")
	}
	return data, nil
}

// keyOf returns the key of a `key = value` line, or "".
func keyOf(line string) string {
	k, _, ok := strings.Cut(line, "=")
	if !ok || strings.HasPrefix(line, "#") {
		return ""
	}
	return strings.TrimSpace(k)
}

func splitLines(data []byte) []string {
	s := strings.TrimRight(string(data), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func joinLines(lines []string) []byte { return []byte(strings.Join(lines, "\n") + "\n") }

// WriteConfig stores serve.toml with mode 0600, creating its directory
// (0750) when it does not exist yet.
func WriteConfig(h host.Host, path string, data []byte) error {
	dir := filepath.Dir(path)
	if _, err := h.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := h.MkdirAll(dir, 0o750, ""); err != nil {
			return err
		}
	}
	_, err := h.WriteFile(path, data, host.FileOptions{Mode: 0o600})
	return err
}

// ReadConfigFile returns serve.toml's bytes for an edit, or a starter file
// when it does not exist. An existing file must already be private.
func ReadConfigFile(h host.Host, path string) ([]byte, error) {
	info, err := h.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []byte(starter), nil
	}
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users (mode %04o); run: chmod 600 %s", path, perm, path)
	}
	return h.ReadFile(path)
}

// starter is the serve.toml passwd and token create when there is none.
const starter = `# tor-relay-setup fleet serve configuration (see docs/examples/serve.toml).
listen = "127.0.0.1:9850"
inventory = "/etc/tor-relay-setup/fleet.toml"
`
