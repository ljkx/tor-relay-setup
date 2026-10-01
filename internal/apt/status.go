package apt

import (
	"strconv"
	"strings"
)

// Progress is one step of apt's machine-readable progress (APT::Status-Fd).
type Progress struct {
	Phase   string  // "download" or "install"
	Percent float64 // 0–100 within the phase
	Package string  // package being processed (install phase only), e.g. "tor:amd64"
	Detail  string  // human-readable description from apt
}

// Progress phases.
const (
	PhaseDownload = "download"
	PhaseInstall  = "install"
)

// ParseStatusLine parses one APT::Status-Fd line. It understands
//
//	dlstatus:<item>:<percent>:<description>
//	pmstatus:<package>:<percent>:<description>
//
// where <package> may carry an architecture suffix ("tor:amd64") and the
// description may itself contain colons. Any other line (pmerror,
// pmconffile, media-change, garbage) reports ok=false; see
// ParseStatusError for pmerror.
func ParseStatusLine(line string) (Progress, bool) {
	line = strings.TrimRight(line, "\r\n")
	var phase string
	rest, ok := strings.CutPrefix(line, "dlstatus:")
	if ok {
		phase = PhaseDownload
	} else if rest, ok = strings.CutPrefix(line, "pmstatus:"); ok {
		phase = PhaseInstall
	} else {
		return Progress{}, false
	}
	subject, percent, detail, ok := splitStatus(rest)
	if !ok {
		return Progress{}, false
	}
	p := Progress{Phase: phase, Percent: percent, Detail: detail}
	if phase == PhaseInstall {
		// dlstatus's first field is an item counter, not a package.
		p.Package = subject
	}
	return p, true
}

// ParseStatusError parses a "pmerror:<package>:<percent>:<message>" line,
// which dpkg emits when a package fails to unpack or configure. <package>
// may be a package name or the path of a .deb file.
func ParseStatusError(line string) (pkg, msg string, ok bool) {
	rest, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), "pmerror:")
	if !ok {
		return "", "", false
	}
	pkg, _, msg, ok = splitStatus(rest)
	return pkg, msg, ok
}

// splitStatus splits "<subject>:<percent>[:<detail>]". The subject may
// contain colons, so the percent is the first field, scanning from the left
// after the first, that is a plain decimal number; everything after it is
// the detail, colons included.
func splitStatus(s string) (subject string, percent float64, detail string, ok bool) {
	fields := strings.Split(s, ":")
	for i := 1; i < len(fields); i++ {
		if !isDecimal(fields[i]) {
			continue
		}
		pct, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			continue
		}
		subject = strings.Join(fields[:i], ":")
		if subject == "" {
			return "", 0, "", false
		}
		return subject, min(max(pct, 0), 100), strings.Join(fields[i+1:], ":"), true
	}
	return "", 0, "", false
}

// isDecimal reports whether s looks like "12", "12.5" or ".5" (no sign,
// exponent, hex, Inf or NaN, which strconv.ParseFloat would also accept).
func isDecimal(s string) bool {
	digits, dots := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c == '.':
			dots++
		default:
			return false
		}
	}
	return digits > 0 && dots <= 1
}
