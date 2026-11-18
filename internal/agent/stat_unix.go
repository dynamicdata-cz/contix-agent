//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// fileGID returns the owning group id of a file (-1 if unknown).
func fileGID(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Gid)
	}
	return -1
}

// fileUID returns the owning user id of a file (-1 if unknown).
func fileUID(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
