package relay

import (
	"regexp"
	"strings"
)

// SelfTest summarises Tor's ORPort reachability self-test notices.
type SelfTest struct {
	IPv4   bool // the IPv4 ORPort (or an unaddressed legacy notice) was confirmed
	IPv6   bool // the bracketed IPv6 ORPort was confirmed
	Failed bool // Tor gave up confirming reachability
}

var (
	// Tor 0.4.5+ includes the tested address, e.g. "Self-testing indicates
	// your ORPort 203.0.113.5:9001 is reachable from the outside. Excellent."
	// (src/feature/relay/selftest.c). Older releases omit the address.
	selfTestOKRe = regexp.MustCompile(`Self-testing indicates your ORPort (\S+ )?is reachable from the outside\. Excellent\.`)
	// Current wording lives in src/feature/relay/relay_periodic.c; the older
	// "confirm that its ORPort is reachable" wording is kept for old relays,
	// which also printed the address as "Your server (addr:port) has not...".
	selfTestFailRe = regexp.MustCompile(`Your server (\([^)]*\) )?has not managed to confirm (reachability for its ORPort|that its ORPort is reachable)`)
)

// ParseSelfTest scans a Tor log for ORPort self-test results. A success
// notice whose address is bracketed ([addr]:port) counts as IPv6; any other
// success notice, including the legacy form without an address, as IPv4.
func ParseSelfTest(log string) SelfTest {
	var st SelfTest
	for line := range strings.Lines(log) {
		if m := selfTestOKRe.FindStringSubmatch(line); m != nil {
			if strings.HasPrefix(m[1], "[") {
				st.IPv6 = true
			} else {
				st.IPv4 = true
			}
		}
		if selfTestFailRe.MatchString(line) {
			st.Failed = true
		}
	}
	return st
}
