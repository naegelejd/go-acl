package acl

// #ifdef __APPLE__
//  #include <sys/types.h>
// #endif
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"

const (
	EXECUTE Perm = C.ACL_EXECUTE
	WRITE   Perm = C.ACL_WRITE
	READ    Perm = C.ACL_READ
)

// Perm represents a permission.
type Perm int

// Permset is a collection of permissions.
type Permset struct {
	p C.acl_permset_t
}

// AddPerm adds a new permission to a Permset.
func (pset Permset) AddPerm(perm Perm) error {
	p := C.acl_perm_t(perm)
	rv, err := C.acl_add_perm(pset.p, p)
	if rv < 0 {
		return err
	}
	return nil
}

// ClearPerms removes all permissions from a Permset.
func (pset Permset) ClearPerms() error {
	rv, err := C.acl_clear_perms(pset.p)
	if rv < 0 {
		return err
	}
	return nil
}

// DeletePerm removes a single permission from a Permset.
func (pset Permset) DeletePerm(perm Perm) error {
	p := C.acl_perm_t(perm)
	rv, err := C.acl_delete_perm(pset.p, p)
	if rv < 0 {
		return err
	}
	return nil
}
