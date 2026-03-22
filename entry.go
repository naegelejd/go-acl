// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

package acl

// #ifdef __APPLE__
//  #include <sys/types.h>
// #endif
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"
import "fmt"

const (
	TagUndefined Tag = C.ACL_UNDEFINED_TAG
)

// Entry is an entry in an ACL.
type Entry struct {
	e C.acl_entry_t
}

// SetPermset sets the permissions for an ACL Entry.
func (entry *Entry) SetPermset(pset *Permset) error {
	rv, _ := C.acl_set_permset(entry.e, pset.p)
	if rv < 0 {
		return fmt.Errorf("unable to set permset on entry")
	}
	return nil
}

// Copy copies the entry into dst, creating a new entry in that ACL and
// returning it. This wraps acl_copy_entry(3).
func (entry *Entry) Copy(dst *ACL) (*Entry, error) {
	newEntry, err := dst.CreateEntry()
	if err != nil {
		return nil, err
	}
	rv, _ := C.acl_copy_entry(newEntry.e, entry.e)
	if rv < 0 {
		return nil, fmt.Errorf("unable to copy entry")
	}
	return newEntry, nil
}

// GetPermset returns the permission for an Entry.
func (entry *Entry) GetPermset() (*Permset, error) {
	var ps C.acl_permset_t
	rv, _ := C.acl_get_permset(entry.e, &ps)
	if rv < 0 {
		return nil, fmt.Errorf("unable to get permset")
	}
	return &Permset{ps}, nil
}

// GetTag returns the Tag for an Entry.
func (entry *Entry) GetTag() (Tag, error) {
	var t C.acl_tag_t
	rv, _ := C.acl_get_tag_type(entry.e, &t)
	if rv < 0 {
		return TagUndefined, fmt.Errorf("unable to get tag")
	}
	return Tag(t), nil
}

// SetTag sets the Tag for an Entry.
func (entry *Entry) SetTag(t Tag) error {
	rv, _ := C.acl_set_tag_type(entry.e, C.acl_tag_t(t))
	if rv < 0 {
		return fmt.Errorf("unable to set tag")
	}
	return nil
}
