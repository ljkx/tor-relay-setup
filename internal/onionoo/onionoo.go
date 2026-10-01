// Package onionoo is a small client for Tor Metrics' Onionoo API: relay
// details for the local fingerprint, nickname search for family candidates,
// and published status of a set of fingerprints.
package onionoo

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// DefaultBase is the public Onionoo endpoint.
const DefaultBase = "https://onionoo.torproject.org"

const (
	userAgent   = "tor-relay-setup"
	maxBody     = 2 << 20 // 2 MiB
	searchLimit = "20"
)

// defaultHTTP serves the zero Client.
var defaultHTTP = &http.Client{Timeout: 10 * time.Second}

var (
	fingerprintPattern = regexp.MustCompile(`^[0-9A-F]{40}$`)
	nicknamePattern    = regexp.MustCompile(`^[A-Za-z0-9]{1,19}$`)
)

// Client queries Onionoo. The zero value uses a 10-second-timeout HTTP
// client and DefaultBase.
type Client struct {
	HTTP *http.Client
	Base string
}

// Relay is the subset of an Onionoo details document the installer shows.
type Relay struct {
	Nickname, Fingerprint string
	Running               bool
	Flags                 []string
	FirstSeen, LastSeen   string

	AdvertisedBandwidth, ObservedBandwidth, ConsensusWeight int64

	Platform, Contact string
	ORAddresses       []string
	FamilyIDs         []string // Onionoo "family_ids" (Tor 0.4.9 FamilyId), when published

	ExitProbability, GuardProbability, MiddleProbability float64
}

// Summary is one relay of an Onionoo summary document.
type Summary struct {
	Nickname, Fingerprint string
	Running               bool
	Addresses             []string
}

// NormalizeFingerprint upper-cases a relay fingerprint and removes spaces
// and a leading '$'. It returns an error unless 40 hex digits remain.
func NormalizeFingerprint(fp string) (string, error) {
	n := strings.ToUpper(strings.TrimPrefix(strings.Join(strings.Fields(fp), ""), "$"))
	if !fingerprintPattern.MatchString(n) {
		return "", fmt.Errorf("invalid relay fingerprint %q: want 40 hex digits", fp)
	}
	return n, nil
}

// ValidNickname reports whether s is Tor nickname syntax (1–19 letters or
// digits).
func ValidNickname(s string) bool { return nicknamePattern.MatchString(s) }

func (c Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTP
}

func (c Client) base() string {
	if c.Base == "" {
		return DefaultBase
	}
	return strings.TrimRight(c.Base, "/")
}

// get fetches base+path?query and decodes the JSON body into out.
func (c Client) get(ctx context.Context, path string, query url.Values, out any) error {
	u := c.base() + path + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("onionoo: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("onionoo: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("onionoo: %s returned %s", path, resp.Status)
	}
	if len(body) > maxBody {
		return fmt.Errorf("onionoo: response larger than %d bytes", maxBody)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("onionoo: decode %s response: %w", path, err)
	}
	return nil
}

// detailsRelay mirrors the Onionoo details fields used here.
type detailsRelay struct {
	Nickname            string          `json:"nickname"`
	Fingerprint         string          `json:"fingerprint"`
	Running             bool            `json:"running"`
	Flags               []string        `json:"flags"`
	FirstSeen           string          `json:"first_seen"`
	LastSeen            string          `json:"last_seen"`
	AdvertisedBandwidth int64           `json:"advertised_bandwidth"`
	ObservedBandwidth   int64           `json:"observed_bandwidth"`
	ConsensusWeight     int64           `json:"consensus_weight"`
	Platform            string          `json:"platform"`
	Contact             string          `json:"contact"`
	ORAddresses         []string        `json:"or_addresses"`
	FamilyIDs           json.RawMessage `json:"family_ids"`
	ExitProbability     float64         `json:"exit_probability"`
	GuardProbability    float64         `json:"guard_probability"`
	MiddleProbability   float64         `json:"middle_probability"`
}

// familyIDs accepts family_ids as a list of strings or a single string and
// ignores any other shape, since the field is new in Onionoo.
func familyIDs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return slices.DeleteFunc(list, func(s string) bool { return s == "" })
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return []string{one}
	}
	return nil
}

// Details returns the published details of the relay with this
// fingerprint, or (nil, nil) when Onionoo does not list it (new relays take
// about three hours to appear).
func (c Client) Details(ctx context.Context, fingerprint string) (*Relay, error) {
	fp, err := NormalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Relays []detailsRelay `json:"relays"`
	}
	if err := c.get(ctx, "/details", url.Values{"lookup": {fp}}, &doc); err != nil {
		return nil, err
	}
	if len(doc.Relays) == 0 {
		return nil, nil
	}
	d := doc.Relays[0]
	return &Relay{
		Nickname:            d.Nickname,
		Fingerprint:         d.Fingerprint,
		Running:             d.Running,
		Flags:               d.Flags,
		FirstSeen:           d.FirstSeen,
		LastSeen:            d.LastSeen,
		AdvertisedBandwidth: d.AdvertisedBandwidth,
		ObservedBandwidth:   d.ObservedBandwidth,
		ConsensusWeight:     d.ConsensusWeight,
		Platform:            d.Platform,
		Contact:             d.Contact,
		ORAddresses:         d.ORAddresses,
		FamilyIDs:           familyIDs(d.FamilyIDs),
		ExitProbability:     d.ExitProbability,
		GuardProbability:    d.GuardProbability,
		MiddleProbability:   d.MiddleProbability,
	}, nil
}

// summaryDoc is an Onionoo summary document (short keys).
type summaryDoc struct {
	Relays []struct {
		N string   `json:"n"`
		F string   `json:"f"`
		R bool     `json:"r"`
		A []string `json:"a"`
	} `json:"relays"`
}

func (d summaryDoc) summaries() []Summary {
	out := make([]Summary, 0, len(d.Relays))
	for _, r := range d.Relays {
		out = append(out, Summary{Nickname: r.N, Fingerprint: r.F, Running: r.R, Addresses: r.A})
	}
	return out
}

// Search finds relays whose nickname (or other searchable field) matches
// nickname, at most 20. Results are ordered: exact nickname matches
// (case-insensitive) first, then running relays, then by nickname and
// fingerprint.
func (c Client) Search(ctx context.Context, nickname string) ([]Summary, error) {
	if !ValidNickname(nickname) {
		return nil, fmt.Errorf("invalid nickname %q: Tor nicknames are 1-19 letters or digits", nickname)
	}
	var doc summaryDoc
	q := url.Values{"type": {"relay"}, "search": {nickname}, "limit": {searchLimit}}
	if err := c.get(ctx, "/summary", q, &doc); err != nil {
		return nil, err
	}
	out := doc.summaries()
	want := strings.ToLower(nickname)
	slices.SortStableFunc(out, func(a, b Summary) int {
		an, bn := strings.ToLower(a.Nickname), strings.ToLower(b.Nickname)
		return cmp.Or(
			boolFirst(an == want, bn == want),
			boolFirst(a.Running, b.Running),
			cmp.Compare(an, bn),
			cmp.Compare(a.Fingerprint, b.Fingerprint),
		)
	})
	return out, nil
}

// boolFirst orders true before false.
func boolFirst(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	default:
		return 1
	}
}

// Status returns the published summaries of the given relays (in Onionoo's
// order); relays Onionoo does not list are absent. No fingerprints means no
// request.
func (c Client) Status(ctx context.Context, fingerprints []string) ([]Summary, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	fps := make([]string, 0, len(fingerprints))
	for _, f := range fingerprints {
		n, err := NormalizeFingerprint(f)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(fps, n) {
			fps = append(fps, n)
		}
	}
	var doc summaryDoc
	q := url.Values{"type": {"relay"}, "lookup": {strings.Join(fps, ",")}}
	if err := c.get(ctx, "/summary", q, &doc); err != nil {
		return nil, err
	}
	return doc.summaries(), nil
}
