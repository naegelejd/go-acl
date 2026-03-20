//go:build linux || freebsd

package acl

// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"

import "fmt"

// DeleteDefaultACL removes the default ACL from the specified path.
func DeleteDefaultACL(path string) error {
	rv, _ := C.acl_delete_def_file(C.CString(path))
	if rv < 0 {
		return fmt.Errorf("unable to delete default ACL from file")
	}
	return nil
}

// CalcMask recalculates the effective rights mask for the ACL.
func (acl *ACL) CalcMask() error {
	rv, _ := C.acl_calc_mask(&acl.a)
	if rv < 0 {
		return fmt.Errorf("unable to calculate mask")
	}
	return nil
}

func (acl *ACL) setFile(path string, tp C.acl_type_t) error {
	if !acl.Valid() {
		if err := acl.addBaseEntries(path); err != nil {
			return err
		}
		if !acl.Valid() {
			return fmt.Errorf("Invalid ACL: %s", acl)
		}
	}
	rv, _ := C.acl_set_file(C.CString(path), tp, acl.a)
	if rv < 0 {
		return fmt.Errorf("unable to apply ACL to file")
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
	cacl, _ := C.acl_get_file(C.CString(path), tp)
	if cacl == nil {
		return nil, fmt.Errorf("unable to get ACL from file")
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
