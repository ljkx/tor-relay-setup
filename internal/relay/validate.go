package relay

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	nicknameRe      = regexp.MustCompile(`^[A-Za-z0-9]{1,19}$`)
	hostLabelRe     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)
	fingerprintRe   = regexp.MustCompile(`^\$?[A-Fa-f0-9]{40}$`)
	familyIDRe      = regexp.MustCompile(`^[A-Za-z0-9+/]{43}$`)
	familyKeyNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	emailRe         = regexp.MustCompile(`^[^\s@#]+@[^\s@#]+\.[^\s@#]+$`)
	httpsURLRe      = regexp.MustCompile(`^https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/[^\s#]*)?$`)
	hosterDomainRe  = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
)

// ValidNickname reports whether s is a Tor relay nickname: 1-19 ASCII
// letters and digits.
func ValidNickname(s string) bool { return nicknameRe.MatchString(s) }

// ValidContactInfo reports whether s can be written as ContactInfo: non-empty,
// at most 250 characters, a single line, and free of '#' (which older
// parsers treat as a comment start).
func ValidContactInfo(s string) bool {
	return s != "" &&
		utf8.RuneCountInString(s) <= 250 &&
		!strings.ContainsAny(s, "\r\n#")
}

// ValidPort reports whether p is a usable TCP port (1-65535).
func ValidPort(p int) bool { return p >= 1 && p <= 65535 }

// ValidHostname reports whether s is a DNS hostname made of valid labels
// (at most 253 characters, labels of 1-63 letters, digits and inner hyphens).
// localhost and localhost.localdomain are rejected.
func ValidHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	lower := strings.ToLower(s)
	if lower == "localhost" || lower == "localhost.localdomain" {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) > 63 || !hostLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}

// ValidIPv6 reports whether s is a plain IPv6 address suitable for a public
// ORPort: no brackets, prefix length or zone; not IPv4-mapped; not loopback,
// link-local, multicast or unspecified. Documentation addresses
// (2001:db8::/32) are accepted.
func ValidIPv6(s string) bool {
	if strings.ContainsAny(s, "[]/% ") {
		return false
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() || a.Is4In6() {
		return false
	}
	return !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsUnspecified()
}

// ValidFingerprint reports whether s is a relay fingerprint: 40 hex digits
// with an optional leading '$'.
func ValidFingerprint(s string) bool { return fingerprintRe.MatchString(s) }

// NormalizeFingerprint strips a leading '$' and upper-cases s.
func NormalizeFingerprint(s string) string {
	return strings.ToUpper(strings.TrimPrefix(s, "$"))
}

// ValidFamilyID reports whether s is a Tor 0.4.9 FamilyId: 43 unpadded
// base64 characters (an ed25519 public key).
func ValidFamilyID(s string) bool { return familyIDRe.MatchString(s) }

// ValidFamilyKeyName reports whether s is safe as a family key file base name.
func ValidFamilyKeyName(s string) bool { return familyKeyNameRe.MatchString(s) }

// ValidEmail reports whether s looks like an email address suitable for a
// CIISS email: field (no whitespace or '#').
func ValidEmail(s string) bool { return emailRe.MatchString(s) }

// ValidHTTPSURL reports whether s is https://host[/path] without spaces or '#'.
func ValidHTTPSURL(s string) bool { return httpsURLRe.MatchString(s) }

// ValidHosterDomain reports whether s is a bare domain such as hetzner.com,
// without scheme or path.
func ValidHosterDomain(s string) bool { return hosterDomainRe.MatchString(s) }
