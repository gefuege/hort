//go:build windows

package vault

import (
	"errors"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readFile opens with FILE_SHARE_DELETE, which os.ReadFile leaves out on
// Windows: an open reader must not block a writer from replacing the vault.
func readFile(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	return io.ReadAll(file)
}

// fileRenameInfo is FILE_RENAME_INFO with the Flags member of its union.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// replaceFile renames with POSIX semantics, so readers that still hold the old
// file keep reading it, as on Unix. MoveFileEx, behind os.Rename, refuses to
// replace a file any process has open. File systems without POSIX rename
// support (FAT, some network shares) keep the MoveFileEx behavior.
func replaceFile(from, to string) error {
	name, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	target, err := windows.UTF16FromString(to)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	handle, err := windows.CreateFile(name, windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}

	var info fileRenameInfo
	size := int(unsafe.Offsetof(info.FileName)) + len(target)*2
	buf := make([]byte, size)
	header := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	header.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	header.FileNameLength = uint32((len(target) - 1) * 2)
	copy(unsafe.Slice(&header.FileName[0], len(target)), target)
	err = windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buf[0], uint32(size))
	_ = windows.CloseHandle(handle)
	if errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return os.Rename(from, to)
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}
