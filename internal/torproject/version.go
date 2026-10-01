package torproject

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseTorVersion extracts the version from `tor --version` output, e.g.
// "Tor version 0.4.9.13." gives "0.4.9.13" and
// "Tor version 0.4.9.4-rc (git-abc)." gives "0.4.9.4-rc". Only the first
// line is considered.
func ParseTorVersion(torVersionOutput string) (string, error) {
	first, _, _ := strings.Cut(torVersionOutput, "\n")
	f := strings.Fields(first)
	if len(f) < 3 || f[0] != "Tor" || f[1] != "version" {
		return "", fmt.Errorf("unrecognised tor --version output %q", strings.TrimSpace(first))
	}
	v := strings.TrimSuffix(f[2], ".")
	if _, _, ok := splitVersion(v); !ok {
		return "", fmt.Errorf("unrecognised tor version %q", f[2])
	}
	return v, nil
}

// VersionAtLeast reports whether version >= min. The leading dotted numeric
// components are compared numerically; when all shared components are equal
// the version with more components is newer (0.4.9.4 >= 0.4.9). A
// pre-release suffix such as "-rc" or "-alpha" only matters when the numeric
// parts are identical, and then ranks below the plain release
// (0.4.9.4-rc < 0.4.9.4). Unparseable input reports false.
func VersionAtLeast(version, min string) bool {
	vNums, vSuffix, ok := splitVersion(version)
	if !ok {
		return false
	}
	mNums, mSuffix, ok := splitVersion(min)
	if !ok {
		return false
	}
	for i := 0; i < len(vNums) && i < len(mNums); i++ {
		if vNums[i] != mNums[i] {
			return vNums[i] > mNums[i]
		}
	}
	if len(vNums) != len(mNums) {
		return len(vNums) > len(mNums)
	}
	switch {
	case vSuffix == mSuffix:
		return true
	case vSuffix == "":
		return true // release >= its pre-release
	case mSuffix == "":
		return false // pre-release < its release
	default:
		return vSuffix >= mSuffix // "-alpha" < "-beta" < "-rc"
	}
}

// splitVersion splits "0.4.9.4-rc" into [0 4 9 4] and "-rc".
func splitVersion(v string) (nums []int, suffix string, ok bool) {
	rest := v
	for {
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end == 0 {
			return nil, "", false
		}
		n, err := strconv.Atoi(rest[:end])
		if err != nil {
			return nil, "", false
		}
		nums = append(nums, n)
		rest = rest[end:]
		if len(rest) < 2 || rest[0] != '.' || rest[1] < '0' || rest[1] > '9' {
			return nums, rest, true
		}
		rest = rest[1:]
	}
}
