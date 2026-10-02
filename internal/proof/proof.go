// Package proof builds and checks the files that prove a relay operator
// controls the website named in the ContactInfo (CIISS).
//
// CIISS version 3 knows two proofs, both for the relay family's ed25519
// FamilyId: proof:uri-familyid-ed25519, a file at
// https://DOMAIN/.well-known/tor-relay/ed25519-family-id.txt, and the DNS
// variant. The domain is the one in the ContactInfo's url: field; the file
// must be reachable over HTTPS with a publicly trusted certificate and must
// not redirect to another domain. Each non-comment line is one 43-character
// FamilyId (several during a key rollover); the secret family key must never
// be published. Proposal 326 (tor-relay well-known URIs) defines the format
// and the legacy rsa-fingerprint.txt (one relay RSA fingerprint per line,
// used by CIISS v2's proof:uri-rsa, never bridge fingerprints); both are at
// most 1 MByte of text/plain.
//
// Sources: https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/
// and torspec proposals/326-tor-relay-well-known-uri-rfc8615.md.
package proof

import (
	"slices"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// Well-known paths.
const (
	FamilyIDPath = "/.well-known/tor-relay/ed25519-family-id.txt"
	RSAPath      = "/.well-known/tor-relay/rsa-fingerprint.txt"
)

// MaxSize is the largest proof file proposal 326 allows.
const MaxSize = 1 << 20

// Kind names a proof file.
type Kind string

// Proof files.
const (
	FamilyIDs    Kind = "uri-familyid-ed25519" // CIISS v3
	Fingerprints Kind = "uri-rsa"              // CIISS v2, legacy
)

// Path is the well-known path of a proof file.
func (k Kind) Path() string {
	if k == Fingerprints {
		return RSAPath
	}
	return FamilyIDPath
}

// FileName is the proof file's base name.
func (k Kind) FileName() string { return k.Path()[strings.LastIndexByte(k.Path(), '/')+1:] }

// FamilyIDFile returns ed25519-family-id.txt for ids: a comment, then each
// valid FamilyId once, in order.
func FamilyIDFile(ids []string) []byte {
	return render("# Tor relay family ID(s) of this operator (CIISS proof:uri-familyid-ed25519).\n", uniq(ids, relay.ValidFamilyID, nil))
}

// RSAFingerprintFile returns rsa-fingerprint.txt for fps: a comment, then
// each valid relay fingerprint once, upper-case and without '$'. Never pass
// bridge fingerprints: the file is public.
func RSAFingerprintFile(fps []string) []byte {
	return render("# Tor relay RSA fingerprints of this operator (legacy CIISS v2 proof:uri-rsa).\n", uniq(fps, relay.ValidFingerprint, relay.NormalizeFingerprint))
}

func render(comment string, entries []string) []byte {
	var b strings.Builder
	b.WriteString(comment)
	for _, e := range entries {
		b.WriteString(e + "\n")
	}
	return []byte(b.String())
}

func uniq(in []string, valid func(string) bool, norm func(string) string) []string {
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if !valid(v) {
			continue
		}
		if norm != nil {
			v = norm(v)
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// Field returns the value of a CIISS field ("url", "proof", ...) in a
// ContactInfo string, or "".
func Field(contact, name string) string {
	for _, f := range strings.Fields(contact) {
		if v, ok := strings.CutPrefix(f, name+":"); ok {
			return v
		}
	}
	return ""
}

// Domain returns the domain of the ContactInfo's url: field (CIISS allows
// omitting the scheme), lower-case and without port or path; "" when the
// ContactInfo has no url.
func Domain(contact string) string {
	u := Field(contact, "url")
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	u, _, _ = strings.Cut(u, "/")
	if host, _, ok := strings.Cut(u, ":"); ok {
		u = host
	}
	return strings.ToLower(u)
}

// URL is where a proof file of this kind is published for domain.
func URL(domain string, k Kind) string { return "https://" + domain + k.Path() }

// File is one proof file to publish.
type File struct {
	Kind    Kind
	URL     string // empty when the ContactInfo names no domain
	Content []byte
	Entries []string
}

// Site is what one domain publishes: the proof files for every local relay
// whose ContactInfo points at it.
type Site struct {
	Domain string   // "" for relays without a url: field
	Relays []string // nicknames (instance names for unnamed relays)
	Proof  string   // the proof: value of the first relay, if any
	Files  []File
}

// Relay is the proof-relevant part of one relay.
type Relay struct {
	Name        string // nickname, or the instance name
	Contact     string
	FamilyIDs   []string
	Fingerprint string
	Bridge      bool
}

// Sites groups relays by the domain in their ContactInfo and returns the
// files each domain should publish. Bridges are skipped: neither file may
// list them. Fleet tooling can call it with every relay of a fleet.
func Sites(relays []Relay) []Site {
	var out []Site
	index := map[string]int{}
	ids := map[string][]string{}
	fps := map[string][]string{}
	for _, r := range relays {
		if r.Bridge {
			continue
		}
		d := Domain(r.Contact)
		i, ok := index[d]
		if !ok {
			i = len(out)
			index[d] = i
			out = append(out, Site{Domain: d, Proof: Field(r.Contact, "proof")})
		}
		out[i].Relays = append(out[i].Relays, r.Name)
		ids[d] = append(ids[d], r.FamilyIDs...)
		if r.Fingerprint != "" {
			fps[d] = append(fps[d], r.Fingerprint)
		}
	}
	for i := range out {
		d := out[i].Domain
		out[i].Files = []File{
			newFile(d, FamilyIDs, FamilyIDFile(ids[d]), uniq(ids[d], relay.ValidFamilyID, nil)),
			newFile(d, Fingerprints, RSAFingerprintFile(fps[d]), uniq(fps[d], relay.ValidFingerprint, relay.NormalizeFingerprint)),
		}
	}
	return out
}

func newFile(domain string, k Kind, content []byte, entries []string) File {
	f := File{Kind: k, Content: content, Entries: entries}
	if domain != "" {
		f.URL = URL(domain, k)
	}
	return f
}
