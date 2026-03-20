// Copyright (c) 2015 Joseph Naegele. See LICENSE file.

package acl

// #include <sys/types.h>
// #include <sys/acl.h>
import "C"

import (
	"fmt"
	"syscall"
)

func (acl *ACL) addBaseEntries(path string) error {
	return nil
}

// CalcMask is not supported on macOS (acl_calc_mask returns ENOTSUP).
func (acl *ACL) CalcMask() error {
	return fmt.Errorf("CalcMask is not supported on macOS")
}

// DeleteDefaultACL is not supported on macOS (acl_delete_def_file returns ENOTSUP).
func DeleteDefaultACL(path string) error {
	return fmt.Errorf("DeleteDefaultACL is not supported on macOS")
}

// GetFileAccess returns the extended ACL associated with the given file path.
// macOS does not support POSIX.1e access ACLs; this uses ACL_TYPE_EXTENDED
// (NFSv4) instead. Files that have no extended ACL return an empty ACL.
func GetFileAccess(path string) (*ACL, error) {
	cacl, err := C.acl_get_file(C.CString(path), C.ACL_TYPE_EXTENDED)
	if cacl == nil {
		if err == syscall.ENOENT {
			// No extended ACL on this file — return an empty ACL.
			return New(), nil
		}
		return nil, fmt.Errorf("unable to get ACL from file")
	}
	return &ACL{cacl}, nil
}

// GetFileDefault returns an empty ACL. Default ACLs are not supported on macOS.
func GetFileDefault(path string) (*ACL, error) {
	return New(), nil
}

// SetFileAccess sets the extended ACL on a file.
// macOS only supports ACL_TYPE_EXTENDED; POSIX.1e access ACLs are not supported.
func (acl *ACL) SetFileAccess(path string) error {
	rv, _ := C.acl_set_file(C.CString(path), C.ACL_TYPE_EXTENDED, acl.a)
	if rv < 0 {
		return fmt.Errorf("unable to apply ACL to file")
	}
	return nil
}

// SetFileDefault is a no-op on macOS. Default ACLs are not supported.
func (acl *ACL) SetFileDefault(path string) error {
	return nil
}

