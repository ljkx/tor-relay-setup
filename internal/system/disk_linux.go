//go:build linux

package system

import (
	"math"
	"syscall"
)

// DiskFree reports the space (MiB) and inodes available to unprivileged
// users on the filesystem holding path, like `df -P` and `df -Pi`.
func DiskFree(path string) (freeMiB int, freeInodes uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(max(st.Bsize, 0)) // block size is never negative
	free := min(st.Bavail*bsize/(1<<20), math.MaxInt32)
	return int(free), st.Ffree, nil
}
