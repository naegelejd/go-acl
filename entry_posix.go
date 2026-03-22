// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build linux || freebsd

package acl

// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"
import (
	"fmt"
	"unsafe"
)

// SetQualifier sets the qualifier (uid or gid as int) for the entry.
// On Linux and FreeBSD qualifiers are uid or gid integers.
// Returns an error if the entry's tag does not carry a qualifier (i.e. is not
// TagUser or TagGroup).
func (entry *Entry) SetQualifier(id int) error {
	tag, err := entry.GetTag()
	if err != nil {
		return err
	}
	switch tag {
	case TagGroup:
		cid := C.gid_t(id)
		rv, _ := C.acl_set_qualifier(entry.e, unsafe.Pointer(&cid))
		if rv < 0 {
			return fmt.Errorf("unable to set qualifier")
		}
		return nil
	case TagUser:
		cid := C.uid_t(id)
		rv, _ := C.acl_set_qualifier(entry.e, unsafe.Pointer(&cid))
		if rv < 0 {
			return fmt.Errorf("unable to set qualifier")
		}
		return nil
	default:
		return fmt.Errorf("tag %v does not carry a qualifier", tag)
	}
}

// GetQualifier returns the qualifier (uid or gid as int) for the entry.
// On Linux and FreeBSD qualifiers are uid or gid integers.
func (entry *Entry) GetQualifier() (int, error) {
	tag, err := entry.GetTag()
	if err != nil {
		return -1, err
	}
	q := C.acl_get_qualifier(entry.e)
	if q == nil {
		return -1, fmt.Errorf("unable to get qualifier")
	}
	defer C.acl_free(q)
	if tag == TagGroup {
		return int(*(*C.gid_t)(q)), nil
	}
	return int(*(*C.uid_t)(q)), nil
}
