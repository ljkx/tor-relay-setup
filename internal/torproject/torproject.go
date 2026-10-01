// Package torproject knows everything specific to the official Tor Project
// Debian/Ubuntu repository: where it lives, which OpenPGP key signs it, the
// apt source and unattended-upgrades snippets that enable it, and how to
// tell whether apt's tor candidate really comes from it.
//
// The package is pure: it builds file contents and parses command output,
// but never writes files or runs commands itself. The only I/O is the HTTP
// in FetchSigningKey and SuiteAvailable, and the caller supplies the client.
package torproject

import (
	"bufio"
	"fmt"
	"strings"
)

// Repository locations and installed file paths.
const (
	// RepoURL is the base URL of the official Tor Project apt repository.
	RepoURL = "https://deb.torproject.org/torproject.org"
	// SigningKeyFingerprint is the primary-key fingerprint (upper-case hex)
	// of the key that signs the repository's Release files.
	SigningKeyFingerprint = "A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89"
	// KeyringPath is where the verified binary keyring is installed; the
	// apt source restricts the repository to it with Signed-By.
	KeyringPath = "/usr/share/keyrings/deb.torproject.org-keyring.gpg"
	// SourcesPath is the deb822 apt source for the repository.
	SourcesPath = "/etc/apt/sources.list.d/tor.sources"
	// LegacySourcesPath is the one-line-style source older guides create.
	// Its presence may mean the repository is configured twice.
	LegacySourcesPath = "/etc/apt/sources.list.d/tor.list"
	// UnattendedPath holds the unattended-upgrades origins for Tor.
	UnattendedPath = "/etc/apt/apt.conf.d/52tor-relay-unattended-upgrades"
	// AutoUpgradesPath enables the periodic apt jobs.
	AutoUpgradesPath = "/etc/apt/apt.conf.d/20auto-upgrades"
	// MinVersion is the oldest tor release the network accepts for relays.
	MinVersion = "0.4.9"
)

// managedBy names the tool in the header comment of generated apt snippets.
const managedBy = "tor-relay-setup"

// KeyURL returns the URL of the armored repository signing key.
func KeyURL() string {
	return RepoURL + "/" + SigningKeyFingerprint + ".asc"
}

// Sources returns the deb822 apt source for codename, restricted to the
// keyring at KeyringPath.
func Sources(codename string) []byte {
	return fmt.Appendf(nil,
		"Types: deb deb-src\nURIs: %s/\nSuites: %s\nComponents: main\nSigned-By: %s\n",
		RepoURL, codename, KeyringPath)
}

// UnattendedConfig returns the unattended-upgrades snippet that allows
// security updates for the distribution and all Tor Project updates.
// Debian needs Origins-Pattern (its security suite is labelled
// separately); Ubuntu and everything else use Allowed-Origins. The
// ${distro_*} placeholders are unattended-upgrades macros, not Go or shell.
func UnattendedConfig(osID string) []byte {
	var b strings.Builder
	b.WriteString("// Managed by " + managedBy + ". Enables unattended upgrades for Tor Project packages.\n")
	if osID == "debian" {
		// Since bullseye the Debian security suite is "<codename>-security".
		b.WriteString("Unattended-Upgrade::Origins-Pattern {\n")
		b.WriteString(`    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";` + "\n")
		b.WriteString(`    "origin=TorProject";` + "\n")
	} else {
		b.WriteString("Unattended-Upgrade::Allowed-Origins {\n")
		b.WriteString(`    "${distro_id}:${distro_codename}-security";` + "\n")
		b.WriteString(`    "TorProject:${distro_codename}";` + "\n")
	}
	b.WriteString("};\n")
	return []byte(b.String())
}

// AutoUpgradesConfig returns the APT::Periodic settings that refresh package
// lists and run unattended-upgrades daily.
func AutoUpgradesConfig() []byte {
	return []byte(`APT::Periodic::Update-Package-Lists "1";
APT::Periodic::AutocleanInterval "5";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Verbose "1";
`)
}

// CandidateFromTorProject reports whether the candidate version in
// `apt-cache policy tor` output is offered by the Tor Project repository.
//
// It finds the "Candidate:" version, then looks at that version's block in
// the version table: the line naming the version (prefixed with "***" when
// it is also the installed one) followed by one line per source. At least
// one of those sources must be RepoURL. This rejects a higher-priority or
// higher-versioned tor from any other repository even when the Tor Project
// also offers some other version.
//
// Compared with the Bash original, which matched the text
// "deb.torproject.org/torproject.org" anywhere in the line, the source URI
// must match exactly, so a look-alike such as
// https://evil.example/deb.torproject.org/torproject.org is rejected.
func CandidateFromTorProject(policyOutput string) bool {
	var candidate string
	inCandidate := false
	sc := bufio.NewScanner(strings.NewReader(policyOutput))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) == 0:
			continue
		case f[0] == "Candidate:":
			if len(f) > 1 {
				candidate = f[1]
			}
			continue
		case candidate == "" || candidate == "(none)":
			continue
		case f[0] == "***":
			inCandidate = len(f) > 1 && f[1] == candidate
			continue
		case len(f) >= 2 && startsWithDigit(f[0]) && allDigits(f[1]):
			// A version line: "<version> <priority>".
			inCandidate = f[0] == candidate
			continue
		}
		// A source line: "<priority> <uri> <suite/component> <arch> Packages".
		if inCandidate && len(f) >= 2 && isTorProjectURI(f[1]) {
			return true
		}
	}
	return false
}

// isTorProjectURI reports whether uri (as printed by apt-cache policy) is the
// Tor Project repository, over any transport apt can use for it.
func isTorProjectURI(uri string) bool {
	rest, ok := strings.CutPrefix(uri, "tor+")
	if !ok {
		rest = uri
	}
	for _, scheme := range []string{"https://", "http://"} {
		if hostPath, ok := strings.CutPrefix(rest, scheme); ok {
			return strings.TrimSuffix(hostPath, "/") == strings.TrimPrefix(RepoURL, "https://")
		}
	}
	return false
}

func startsWithDigit(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
