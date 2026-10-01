//go:build !linux

package system

import "errors"

// DiskFree is only implemented on Linux, the installer's target.
func DiskFree(path string) (freeMiB int, freeInodes uint64, err error) {
	return 0, 0, errors.ErrUnsupported
}
