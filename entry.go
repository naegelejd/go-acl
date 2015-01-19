package acl

// #ifdef __APPLE__
//  #include <sys/types.h>
// #endif
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"

// Entry is an entry in an ACL.
type Entry struct {
	e C.acl_entry_t
}

// SetPermset sets the permissions for an ACL Entry.
func (entry Entry) SetPermset(pset Permset) error {
	e := C.acl_entry_t(entry.e)
	p := C.acl_permset_t(pset.p)
	i, err := C.acl_set_permset(e, p)
	if i < 0 {
		return err
	}
	return nil
}

// Copy copies an Entry.
func (entry Entry) Copy() (Entry, error) {
	csrc := C.acl_entry_t(entry.e)
	var dst Entry
	cdst := C.acl_entry_t(dst.e)

	i, err := C.acl_copy_entry(cdst, csrc)
	if i < 0 {
		return dst, err
	}
	return dst, nil
}

// func (entry Entry) SetQualifier(tag_qualifier_p *constvoid) int {
// 	return 0
// }

// func (entry Entry) GetQualifier() error {
// 	return nil
// }

// GetPermset returns the permission for an Entry.
func (entry Entry) GetPermset() (Permset, error) {
	e := C.acl_entry_t(entry.e)
	var pset Permset
	ps := C.acl_permset_t(pset.p)
	i, err := C.acl_get_permset(e, &ps)
	if i < 0 {
		return pset, err
	}
	return pset, nil
}

// GetTagType returns the Tag for an Entry.
func (entry Entry) GetTagType() (Tag, error) {
	e := C.acl_entry_t(entry.e)
	var tag Tag
	t := C.acl_tag_t(tag)
	i, err := C.acl_get_tag_type(e, &t)
	if i < 0 {
		return tag, err
	}
	return tag, nil
}

// SetTagType sets the Tag for an Entry.
func (entry Entry) SetTagType(t Tag) error {
	e := C.acl_entry_t(entry.e)
	i, err := C.acl_set_tag_type(e, C.acl_tag_t(t))
	if i < 0 {
		return err
	}
	return nil
}
