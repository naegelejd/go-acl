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
func (entry *Entry) SetQualifier(id int) error {
	rv, _ := C.acl_set_qualifier(entry.e, unsafe.Pointer(&id))
	if rv < 0 {
		return fmt.Errorf("unable to set qualifier")
	}
	return nil
}

// GetQualifier returns the qualifier (uid or gid as int) for the entry.
// On Linux and FreeBSD qualifiers are uid or gid integers.
func (entry *Entry) GetQualifier() (int, error) {
	q := C.acl_get_qualifier(entry.e)
	if q == nil {
		return -1, fmt.Errorf("unable to get qualifier")
	}
	return *(*int)(q), nil
}
