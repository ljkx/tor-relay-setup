package proof

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

// Result is the outcome of fetching one published proof file.
type Result struct {
	URL     string   `json:"url"`
	OK      bool     `json:"ok"` // reachable and lists every wanted entry
	Found   []string `json:"found,omitempty"`
	Missing []string `json:"missing,omitempty"`
	// Notes are problems that do not fail the check (wrong content type).
	Notes []string `json:"notes,omitempty"`
	Error string   `json:"error,omitempty"`
}

// ErrCrossDomain reports a redirect to another domain, which CIISS forbids.
var ErrCrossDomain = errors.New("redirects to another domain (CIISS forbids that)")

// Client returns an HTTP client for Check: it follows at most five
// redirects, only over HTTPS and only within the original domain. base may
// carry a custom transport (tests); nil uses a 15-second default.
func Client(base *http.Client) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if base != nil {
		cp := *base
		c = &cp
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("redirects away from HTTPS")
		}
		if !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
			return fmt.Errorf("%w: %s", ErrCrossDomain, req.URL.Hostname())
		}
		return nil
	}
	return c
}

// Check fetches a proof file over HTTPS and reports which of want it lists.
// FamilyIds compare case-sensitively; RSA fingerprints do not. Comment and
// blank lines are ignored. A file that contains a secret family key fails
// loudly.
func Check(ctx context.Context, c *http.Client, k Kind, rawURL string, want []string) Result {
	res := Result{URL: rawURL}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		res.Error = "not an https:// URL"
		return res
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "tor-relay-setup")
	resp, err := c.Do(req)
	if err != nil {
		res.Error = err.Error()
		if errors.Is(err, ErrCrossDomain) {
			res.Error = ErrCrossDomain.Error()
		}
		return res
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize+1))
	switch {
	case err != nil:
		res.Error = "read: " + err.Error()
		return res
	case resp.StatusCode != http.StatusOK:
		res.Error = "HTTP " + resp.Status
		return res
	case len(body) > MaxSize:
		res.Error = "larger than 1 MByte"
		return res
	case strings.Contains(string(body), "ed25519v1-secret"):
		res.Error = "the file contains a SECRET key: remove it from the web server now and generate a new family key"
		return res
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/plain" {
		res.Notes = append(res.Notes, fmt.Sprintf("served as %q; proposal 326 asks for text/plain", resp.Header.Get("Content-Type")))
	}
	var listed []string
	for line := range strings.Lines(string(body)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k == Fingerprints {
			line = relay.NormalizeFingerprint(line)
		}
		listed = append(listed, line)
	}
	for _, w := range want {
		if k == Fingerprints {
			w = relay.NormalizeFingerprint(w)
		}
		if slices.Contains(listed, w) {
			res.Found = append(res.Found, w)
		} else {
			res.Missing = append(res.Missing, w)
		}
	}
	res.OK = len(res.Missing) == 0
	return res
}

// CheckSite fetches both proof files of a site; a file with nothing to
// prove (no FamilyId yet, no fingerprint) is skipped.
func CheckSite(ctx context.Context, c *http.Client, s Site) []Result {
	var out []Result
	for _, f := range s.Files {
		if f.URL == "" || len(f.Entries) == 0 {
			continue
		}
		out = append(out, Check(ctx, c, f.Kind, f.URL, f.Entries))
	}
	return out
}

// Local reads the proof-relevant facts of the local relay instances.
func Local(h host.Host, instances []relay.InstanceConfig) []Relay {
	out := make([]Relay, 0, len(instances))
	for _, ic := range instances {
		doc := ic.Doc
		r := Relay{Name: ic.Name, FamilyIDs: doc.FamilyIDs()}
		if n, ok := doc.Get("Nickname"); ok && n != "" {
			r.Name = n
		}
		if c, ok := doc.Get("ContactInfo"); ok {
			r.Contact = relay.Unquote(c)
		}
		_, r.Bridge = doc.BridgeSettings()
		r.Fingerprint = status.ReadFingerprint(h, ic.DataDirectory())
		out = append(out, r)
	}
	return out
}

// Advice returns hints for a site: a missing url: field or proof value.
func Advice(s Site) []string {
	var a []string
	switch {
	case s.Domain == "":
		a = append(a, "the ContactInfo has no url: field; add url:https://YOUR-DOMAIN and proof:uri-familyid-ed25519 (Edit settings) to use these files")
	case s.Proof == "":
		a = append(a, "CIISS requires a proof: field when url: is set; add proof:uri-familyid-ed25519 to the ContactInfo")
	case s.Proof == "uri-rsa":
		a = append(a, "proof:uri-rsa is CIISS v2; v3 uses proof:uri-familyid-ed25519 with a relay family")
	}
	if len(s.Files) > 0 && len(s.Files[0].Entries) == 0 {
		a = append(a, "no FamilyId is configured: create a relay family (Relay family) to use proof:uri-familyid-ed25519")
	}
	return a
}
