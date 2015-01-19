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

const (
	TYPE_ACCESS  Type = C.ACL_TYPE_ACCESS
	TYPE_DEFAULT Type = C.ACL_TYPE_DEFAULT
	TYPE_NFS4

	UNDEFINED_TAG Tag = C.ACL_UNDEFINED_TAG
	USER_OBJ      Tag = C.ACL_USER_OBJ
	USER          Tag = C.ACL_USER
	GROUP_OBJ     Tag = C.ACL_GROUP_OBJ
	GROUP         Tag = C.ACL_GROUP
	MASK          Tag = C.ACL_MASK
	OTHER         Tag = C.ACL_OTHER
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

// Unsupported on Mac OS X.
func DeleteDefFile(path string) error {
	cs := C.CString(path)
	i, err := C.acl_delete_def_file(cs)
	if i < 0 {
		return err
	}
	return nil
}

// Unsupported on Mac OS X?
func (acl ACL) CalcMask() error {
	a := C.acl_t(acl.a)
	i, err := C.acl_calc_mask(&a)
	if i < 0 {
		return err
	}
	return nil
}

// GetEntry returns the ACL Entry at the given index.
func (acl ACL) GetEntry(eid int) (Entry, error) {
	a := C.acl_t(acl.a)
	var entry Entry
	e := C.acl_entry_t(entry.e)
	i, err := C.acl_get_entry(a, C.int(eid), &e)
	if i < 0 {
		return entry, err
	}
	entry.e = e
	return entry, nil
}

// ToText returns the string representation of the ACL.
func (acl ACL) ToText() (string, error) {
	a := C.acl_t(acl.a)
	s, err := C.acl_to_text(a, nil)
	if s == nil {
		return "", err
	}
	return C.GoString(s), nil
}

// Valid checks if the ACL is valid.
func (acl ACL) Valid() bool {
	a := C.acl_t(acl.a)
	v := C.acl_valid(a)
	if v < 0 {
		return false
	}
	return true
}

// CreateEntry adds a new Entry to the ACL.
func (acl ACL) CreateEntry() (Entry, error) {
	a := C.acl_t(acl.a)
	var entry Entry
	e := C.acl_entry_t(entry.e)
	i, err := C.acl_create_entry(&a, &e)
	if i < 0 {
		return entry, err
	}
	return entry, nil
}

// DeleteEntry removes a specific Entry from the ACL.
func (acl ACL) DeleteEntry(entry Entry) error {
	a := C.acl_t(acl.a)
	e := C.acl_entry_t(entry.e)
	i, err := C.acl_delete_entry(a, e)
	if i < 0 {
		return err
	}
	return nil
}

// Dup copies the ACL.
func (acl ACL) Dup() (ACL, error) {
	a := C.acl_t(acl.a)
	var dup ACL
	cdup, err := C.acl_dup(a)
	if cdup == nil {
		return dup, err
	}
	dup.a = cdup
	return dup, nil
}

// Init creates and initializes at least count ACLs.
func Init(count int) (ACL, error) {
	var acl ACL
	cacl, err := C.acl_init(C.int(count))
	if cacl == nil {
		return acl, err
	}
	acl.a = cacl
	return acl, nil
}

// SetFd applies the ACL to a file descriptor.
func (acl ACL) SetFd(fd int) error {
	a := C.acl_t(acl.a)
	i, err := C.acl_set_fd(C.int(fd), a)
	if i < 0 {
		return err
	}
	return nil
}

// SetFile applies the ACL to a file.
func (acl ACL) SetFile(path string, tp Type) error {
	a := C.acl_t(acl.a)
	t := C.acl_type_t(tp)
	p := C.CString(path)
	i, err := C.acl_set_file(p, t, a)
	if i < 0 {
		return err
	}
	return nil
}

// Free releases the memory used by the ACL.
func (acl ACL) Free() error {
	a := unsafe.Pointer(C.acl_t(acl.a))
	i, err := C.acl_free(a)
	if i < 0 {
		return err
	}
	return nil
}

// FromText constructs and ACL from a string representation.
func FromText(buffer string) (ACL, error) {
	cs := C.CString(buffer)
	var acl ACL
	cacl, err := C.acl_from_text(cs)
	if cacl == nil {
		return acl, err
	}
	acl.a = cacl
	return acl, nil
}

// GetFd returns the ACL associated with the given file descriptor.
func GetFd(fd uintptr) (ACL, error) {
	var acl ACL
	cacl, err := C.acl_get_fd(C.int(fd))
	if cacl == nil {
		return acl, err
	}
	acl.a = cacl
	return acl, nil
}

// GetFile returns the ACL associated with the given file path.
func GetFile(path string, t Type) (ACL, error) {
	var acl ACL
	cs := C.CString(path)
	cacl, err := C.acl_get_file(cs, C.acl_type_t(t))
	if cacl == nil {
		return acl, err
	}
	acl.a = cacl
	return acl, nil
}
