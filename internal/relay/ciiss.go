package relay

import "strings"

// BuildCIISS builds a ContactInfo string following the ContactInfo
// Information Sharing Specification v3
// (https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/).
//
// The email's '@' is written as "[]". CIISS requires a proof whenever url is
// set; v3 proves ownership with the relay FamilyId published under the
// site's /.well-known path, so "proof:uri-familyid-ed25519" follows the url.
// Empty fields are omitted; "ciissversion:3" always ends the string.
func BuildCIISS(email, url, hoster string) string {
	var fields []string
	if email != "" {
		fields = append(fields, "email:"+strings.ReplaceAll(email, "@", "[]"))
	}
	if url != "" {
		fields = append(fields, "url:"+url, "proof:uri-familyid-ed25519")
	}
	if hoster != "" {
		fields = append(fields, "hoster:"+hoster)
	}
	fields = append(fields, "ciissversion:3")
	return strings.Join(fields, " ")
}

// URLDomain returns the host part of an https:// URL, e.g. "example.org" for
// "https://example.org/relays". The FamilyId proof lives at
// https://<domain>/.well-known/tor-relay/ed25519-family-id.txt.
func URLDomain(url string) string {
	domain := strings.TrimPrefix(url, "https://")
	domain, _, _ = strings.Cut(domain, "/")
	return domain
}
