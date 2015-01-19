// Package acl provides an interface to Posix.1e Access Control Lists
// as well as additional ACL implementations (NFS).
package acl

// #ifdef __APPLE__
//  #include <sys/types.h>
// #endif
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"

import (
	"unsafe"
)

// UID/GID values are returned as ints in package "os".
type Uid int
type Gid int

type Tag int
type Type int

// ACL represents an Access Control List.
type ACL struct {
	a C.acl_t
}

// DeleteDefaultACL removes the default ACL from the specified path.
// Unsupported on Mac OS X.
func DeleteDefaultACL(path string) error {
	rv, err := C.acl_delete_def_file(C.CString(path))
	if rv < 0 {
		return err
	}
	return nil
}

// Unsupported on Mac OS X?
func (acl *ACL) CalcMask() error {
	rv, err := C.acl_calc_mask(&acl.a)
	if rv < 0 {
		return err
	}
	return nil
}

// String returns the string representation of the ACL.
func (acl *ACL) String() string {
	s, _ := C.acl_to_text(acl.a, nil)
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

// Valid checks if the ACL is valid.
func (acl *ACL) Valid() bool {
	rv := C.acl_valid(acl.a)
	if rv < 0 {
		return false
	}
	return true
}

// AddEntry adds a new Entry to the ACL.
func (acl *ACL) AddEntry(entry *Entry) error {
	a := C.acl_t(acl.a)
	var e C.acl_entry_t
	rv, err := C.acl_create_entry(&a, &e)
	if rv < 0 {
		return err
	}
	rv, err = C.acl_copy_entry(e, entry.e)
	if rv < 0 {
		return err
	}
	return nil
}

// DeleteEntry removes a specific Entry from the ACL.
func (acl *ACL) DeleteEntry(entry *Entry) error {
	rv, err := C.acl_delete_entry(acl.a, entry.e)
	if rv < 0 {
		return err
	}
	return nil
}

// Dup makes a copy of the ACL.
func (acl *ACL) Dup() (*ACL, error) {
	cdup, err := C.acl_dup(acl.a)
	if cdup == nil {
		return nil, err
	}
	return &ACL{cdup}, nil
}

// New returns a new, initialized ACL.
func New() *ACL {
	cacl, _ := C.acl_init(C.int(1))
	if cacl == nil {
		// If acl_init fails, *ACL is invalid
		return nil
	}
	return &ACL{cacl}
}

// FirstEntry returns the first entry in the ACL,
// or nil of there are no more entries.
func (acl *ACL) FirstEntry() *Entry {
	var e C.acl_entry_t
	rv, _ := C.acl_get_entry(acl.a, C.ACL_FIRST_ENTRY, &e)
	if rv <= 0 {
		// either error obtaining entry or entries at all
		return nil
	}
	return &Entry{e}
}

// NextEntry returns the next entry in the ACL,
// or nil of there are no more entries.
func (acl *ACL) NextEntry() *Entry {
	var e C.acl_entry_t
	rv, _ := C.acl_get_entry(acl.a, C.ACL_NEXT_ENTRY, &e)
	if rv <= 0 {
		// either error obtaining entry or no more entries
		return nil
	}
	return &Entry{e}
}

func (acl *ACL) addDefaults() error {
	var u, g, o Entry
	var rv C.int
	var err error

	rv, err = C.acl_create_entry(&acl.a, &u.e)
	if rv < 0 {
		return err
	}
	rv, _ = C.acl_create_entry(&acl.a, &g.e)
	if rv < 0 {
		return err
	}
	rv, _ = C.acl_create_entry(&acl.a, &o.e)
	if rv < 0 {
		return err
	}

	u.SetTagType(USER)
	g.SetTagType(GROUP)
	o.SetTagType(OTHER)

	var rw, r Permset
	rw.AddPerm(READ)
	rw.AddPerm(WRITE)
	r.AddPerm(READ)
	u.SetPermset(rw)
	g.SetPermset(r)
	o.SetPermset(r)

	return nil
}

// SetFd applies the ACL to a file descriptor.
func (acl *ACL) SetFd(fd int) error {
	if err := acl.addDefaults(); err != nil {
		return err
	}
	rv, err := C.acl_set_fd(C.int(fd), acl.a)
	if rv < 0 {
		return err
	}
	return nil
}

func (acl *ACL) setFile(path string, tp C.acl_type_t) error {
	if err := acl.addDefaults(); err != nil {
		return err
	}
	rv, err := C.acl_set_file(C.CString(path), tp, acl.a)
	if rv < 0 {
		return err
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

// Free releases the memory used by the ACL.
func (acl *ACL) Free() {
	C.acl_free(unsafe.Pointer(acl.a))
}

// Parse constructs and ACL from a string representation.
func Parse(s string) (*ACL, error) {
	cs := C.CString(s)
	cacl, err := C.acl_from_text(cs)
	if cacl == nil {
		return nil, err
	}
	return &ACL{cacl}, nil
}

// GetFd returns the ACL associated with the given file descriptor.
func GetFd(fd uintptr) (*ACL, error) {
	cacl, err := C.acl_get_fd(C.int(fd))
	if cacl == nil {
		return nil, err
	}
	return &ACL{cacl}, nil
}

func getFile(path string, tp C.acl_type_t) (*ACL, error) {
	cacl, err := C.acl_get_file(C.CString(path), tp)
	if cacl == nil {
		return nil, err
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
