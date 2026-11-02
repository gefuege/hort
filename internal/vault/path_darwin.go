package vault

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// F_GETPATH returns the filesystem's spelling of every path component, as
// well as resolving symlinks. EvalSymlinks alone preserves case aliases on macOS.
func canonicalExistingPath(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_EVTONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	var buf [unix.PathMax]byte
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		// An opened vnode disappearing during atomic replacement must fail,
		// rather than take canonicalVaultPath's missing-file branch.
		return "", fmt.Errorf("F_GETPATH: %s", errno)
	}
	return unix.ByteSliceToString(buf[:]), nil
}
