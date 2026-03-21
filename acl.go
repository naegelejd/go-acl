// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

// Package acl provides POSIX.1e ACL bindings for Linux and FreeBSD, and
// NFSv4 (extended) ACL bindings for macOS via the system acl(3) library.
package acl

// #ifdef __APPLE__
//  #include <sys/types.h>
// #endif
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
//
// /*
//  * FreeBSD does not contain acl_size and even when it was there, it seemed
//  * to have been non-functional anyway. See FreeBSD r274722.
//  */
// #ifdef __FreeBSD__
// #include <errno.h>
// # endif
// ssize_t acl_size_wrapper(acl_t acl) {
// #ifdef __FreeBSD__
//     errno = ENOSYS;
//     return (-1);
// #else
//     return acl_size(acl);
// #endif
// }
//
// /*
//  * Normalize acl_get_entry return values to POSIX semantics:
//  *   1  = entry returned
//  *   0  = end of list (or error — caller stops iteration either way)
//  *  -1  = hard error (unused here; treated as 0 for simplicity)
//  *
//  * macOS deviates from POSIX: it returns 0 on success and -1 when the
//  * list is exhausted (errno=EINVAL). Linux and FreeBSD already follow
//  * POSIX (1 = found, 0 = end).
//  */
// static int acl_get_entry_posix(acl_t acl, int eid, acl_entry_t *ep) {
//     int rv = acl_get_entry(acl, eid, ep);
// #ifdef __APPLE__
//     return (rv == 0) ? 1 : 0;
// #else
//     return rv;
// #endif
// }
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	otherExec  = 1 << iota
	otherWrite = 1 << iota
	otherRead  = 1 << iota
	groupExec  = 1 << iota
	groupWrite = 1 << iota
	groupRead  = 1 << iota
	userExec   = 1 << iota
	userWrite  = 1 << iota
	userRead   = 1 << iota
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

// String returns the string representation of the ACL.
func (acl *ACL) String() string {
	cs, _ := C.acl_to_text(acl.a, nil)
	if cs == nil {
		return ""
	}
	defer C.acl_free(unsafe.Pointer(cs))
	return C.GoString(cs)
}

// Valid checks if the ACL is valid.
func (acl *ACL) Valid() bool {
	rv := C.acl_valid(acl.a)
	return rv >= 0
}

// CreateEntry creates a new, empty Entry in the ACL.
func (acl *ACL) CreateEntry() (*Entry, error) {
	var e C.acl_entry_t
	rv, _ := C.acl_create_entry(&acl.a, &e)
	if rv < 0 {
		return nil, fmt.Errorf("unable to create entry")
	}
	return &Entry{e}, nil
}

// AddEntry adds an Entry to the ACL.
func (acl *ACL) AddEntry(entry *Entry) error {
	newEntry, err := acl.CreateEntry()
	if err != nil {
		return err
	}
	rv, _ := C.acl_copy_entry(newEntry.e, entry.e)
	if rv < 0 {
		return fmt.Errorf("unable to copy entry while adding new entry")
	}
	return nil
}

// DeleteEntry removes a specific Entry from the ACL.
func (acl *ACL) DeleteEntry(entry *Entry) error {
	rv, _ := C.acl_delete_entry(acl.a, entry.e)
	if rv < 0 {
		return fmt.Errorf("unable to delete entry")
	}
	return nil
}

// Dup makes a copy of the ACL.
func (acl *ACL) Dup() (*ACL, error) {
	cdup, _ := C.acl_dup(acl.a)
	if cdup == nil {
		return nil, fmt.Errorf("unable to dup ACL")
	}
	return &ACL{cdup}, nil
}

// New returns a new, initialized ACL.
func New() *ACL {
	cacl, _ := C.acl_init(C.int(1))
	if cacl == nil {
		return nil
	}
	return &ACL{cacl}
}

// FirstEntry returns the first entry in the ACL,
// or nil if there are no entries.
func (acl *ACL) FirstEntry() *Entry {
	var e C.acl_entry_t
	rv := C.acl_get_entry_posix(acl.a, C.ACL_FIRST_ENTRY, &e)
	if rv <= 0 {
		return nil
	}
	return &Entry{e}
}

// NextEntry returns the next entry in the ACL,
// or nil if there are no more entries.
func (acl *ACL) NextEntry() *Entry {
	var e C.acl_entry_t
	rv := C.acl_get_entry_posix(acl.a, C.ACL_NEXT_ENTRY, &e)
	if rv <= 0 {
		return nil
	}
	return &Entry{e}
}

// Free releases the memory used by the ACL.
func (acl *ACL) Free() {
	C.acl_free(unsafe.Pointer(acl.a))
}

// Parse constructs an ACL from a string representation.
func Parse(s string) (*ACL, error) {
	cs := C.CString(s)
	cacl, _ := C.acl_from_text(cs)
	if cacl == nil {
		return nil, fmt.Errorf("unable to parse ACL")
	}
	return &ACL{cacl}, nil
}

func (acl *ACL) Size() int64 {
	return int64(C.acl_size_wrapper(acl.a))
}

func (acl *ACL) CopyExt(buffer []byte) (int64, error) {
	p := unsafe.Pointer(&buffer[0])
	l := C.ssize_t(len(buffer))
	i, err := C.acl_copy_ext(p, acl.a, l)
	if i < 0 {
		return int64(i), err
	}
	return int64(i), nil
}

func CopyInt(buffer []byte) (*ACL, error) {
	p := unsafe.Pointer(&buffer[0])
	cacl, err := C.acl_copy_int(p)
	if cacl == nil {
		return nil, err
	}
	return &ACL{cacl}, nil
}
