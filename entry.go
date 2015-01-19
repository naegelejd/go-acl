package acl

// #ifdef __APPLE__
//  #include <sys/types.h>
// #endif
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"

const (
	UNDEFINED_TAG Tag = C.ACL_UNDEFINED_TAG
	USER_OBJ      Tag = C.ACL_USER_OBJ
	USER          Tag = C.ACL_USER
	GROUP_OBJ     Tag = C.ACL_GROUP_OBJ
	GROUP         Tag = C.ACL_GROUP
	MASK          Tag = C.ACL_MASK
	OTHER         Tag = C.ACL_OTHER
)

// Entry is an entry in an ACL.
type Entry struct {
	e C.acl_entry_t
}

// SetPermset sets the permissions for an ACL Entry.
func (entry *Entry) SetPermset(pset Permset) error {
	rv, err := C.acl_set_permset(entry.e, pset.p)
	if rv < 0 {
		return err
	}
	return nil
}

// Copy copies an Entry.
func (entry *Entry) Copy() (*Entry, error) {
	var cdst C.acl_entry_t
	rv, err := C.acl_copy_entry(cdst, entry.e)
	if rv < 0 {
		return nil, err
	}
	return &Entry{cdst}, nil
}

// func (entry Entry) SetQualifier(tag_qualifier_p *constvoid) int {
// 	return 0
// }

// func (entry Entry) GetQualifier() error {
// 	return nil
// }

// GetPermset returns the permission for an Entry.
func (entry *Entry) GetPermset() (Permset, error) {
	var pset Permset
	ps := C.acl_permset_t(pset.p)
	_, err := C.acl_get_permset(entry.e, &ps)
	return pset, err
}

// GetTagType returns the Tag for an Entry.
func (entry *Entry) GetTagType() (Tag, error) {
	var t C.acl_tag_t
	_, err := C.acl_get_tag_type(entry.e, &t)
	return Tag(t), err
}

// SetTagType sets the Tag for an Entry.
func (entry *Entry) SetTagType(t Tag) error {
	_, err := C.acl_set_tag_type(entry.e, C.acl_tag_t(t))
	return err
}
