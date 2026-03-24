// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build linux || freebsd

package acl

// #include <stdlib.h>
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"
)

// GetFd returns the access ACL associated with the open file f.
// This is equivalent to GetFileAccess but avoids a TOCTOU race when
// the caller already holds an open file descriptor.
func GetFd(f *os.File) (*ACL, error) {
	fd := C.int(f.Fd())
	cacl, err := C.acl_get_fd(fd)
	runtime.KeepAlive(f)
	if cacl == nil {
		return nil, fmt.Errorf("unable to get ACL from fd: %w", cgoErrno(err))
	}
	return &ACL{cacl}, nil
}

// SetFd applies the access ACL to the open file f.
// This is equivalent to SetFileAccess but avoids a TOCTOU race when
// the caller already holds an open file descriptor.
func (acl *ACL) SetFd(f *os.File) error {
	fd := C.int(f.Fd())
	rv, err := C.acl_set_fd(fd, acl.a)
	runtime.KeepAlive(f)
	if rv < 0 {
		return fmt.Errorf("unable to set ACL on fd: %w", cgoErrno(err))
	}
	return nil
}

// DeleteDefaultACL removes the default ACL from the specified path.
func DeleteDefaultACL(path string) error {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	rv, err := C.acl_delete_def_file(cpath)
	if rv < 0 {
		return fmt.Errorf("unable to delete default ACL from file: %w", cgoErrno(err))
	}
	return nil
}

// CalcMask recalculates the effective rights mask for the ACL.
func (acl *ACL) CalcMask() error {
	rv, err := C.acl_calc_mask(&acl.a)
	if rv < 0 {
		return fmt.Errorf("unable to calculate mask: %w", cgoErrno(err))
	}
	return nil
}

func (acl *ACL) setFile(path string, tp C.acl_type_t) error {
	if !acl.Valid() {
		if err := acl.addBaseEntries(path); err != nil {
			return err
		}
		if !acl.Valid() {
			return fmt.Errorf("invalid ACL: %s", acl)
		}
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	rv, err := C.acl_set_file(cpath, tp, acl.a)
	if rv < 0 {
		return fmt.Errorf("unable to apply ACL to file: %w", cgoErrno(err))
	}
	return nil
}

// SetFileAccess applies the access ACL to a file.
func (acl *ACL) SetFileAccess(path string) error {
	return acl.setFile(path, C.ACL_TYPE_ACCESS)
}

// SetFileDefault applies the default ACL to a file.
func (acl *ACL) SetFileDefault(path string) error {
	return acl.setFile(path, C.ACL_TYPE_DEFAULT)
}

func getFile(path string, tp C.acl_type_t) (*ACL, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	cacl, err := C.acl_get_file(cpath, tp)
	if cacl == nil {
		return nil, fmt.Errorf("unable to get ACL from file: %w", cgoErrno(err))
	}
	return &ACL{cacl}, nil
}

// GetFileAccess returns the access ACL associated with the given file path.
func GetFileAccess(path string) (*ACL, error) {
	return getFile(path, C.ACL_TYPE_ACCESS)
}

// GetFileDefault returns the default ACL associated with the given file path.
func GetFileDefault(path string) (*ACL, error) {
	return getFile(path, C.ACL_TYPE_DEFAULT)
}
