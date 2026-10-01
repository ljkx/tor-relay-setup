package update

import (
	"strconv"
	"strings"
)

type semver struct {
	major, minor, patch int
	pre                 []string // dot-separated pre-release identifiers
}

// parseSemver parses "v1.2.3", "1.2.3", "v1.2.3-rc.1" and Go pseudo
// versions; build metadata ("+dirty") is ignored.
func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v semver
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || (len(p) > 1 && p[0] == '0') {
			return semver{}, false
		}
		nums[i] = n
	}
	v.major, v.minor, v.patch = nums[0], nums[1], nums[2]
	if hasPre {
		if pre == "" {
			return semver{}, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

// Compare compares two versions by semver precedence: -1 when a < b, 0 when
// equal, 1 when a > b. ok is false when either is not a version.
func Compare(a, b string) (cmp int, ok bool) {
	va, okA := parseSemver(a)
	vb, okB := parseSemver(b)
	if !okA || !okB {
		return 0, false
	}
	for _, d := range [][2]int{{va.major, vb.major}, {va.minor, vb.minor}, {va.patch, vb.patch}} {
		if c := compareInt(d[0], d[1]); c != 0 {
			return c, true
		}
	}
	return comparePre(va.pre, vb.pre), true
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// comparePre orders pre-release identifiers: a release (no identifiers)
// ranks above any pre-release; numeric identifiers compare numerically and
// below alphanumeric ones.
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		na, errA := strconv.Atoi(a[i])
		nb, errB := strconv.Atoi(b[i])
		switch {
		case errA == nil && errB == nil:
			if c := compareInt(na, nb); c != 0 {
				return c
			}
		case errA == nil:
			return -1
		case errB == nil:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return compareInt(len(a), len(b))
}
