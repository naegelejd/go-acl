package acls

// #ifdef __APPLE__
//  #include <sys/types.h>
// #endif
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"

func (pset Permset) AddPerm(perm Perm) error {
    ps := C.acl_permset_t(pset.p)
    p := C.acl_perm_t(perm)
    i, err := C.acl_add_perm(ps, p)
    if i < 0 {
        return err
    }
    return nil
}

func (pset Permset) ClearPerms() error {
    ps := C.acl_permset_t(pset.p)
    i, err := C.acl_clear_perms(ps)
    if i < 0 {
        return err
    }
    return nil
}

func (pset Permset) DeletePerm(perm Perm) error {
    ps := C.acl_permset_t(pset.p)
    p := C.acl_perm_t(perm)
    i, err := C.acl_delete_perm(ps, p)
    if i < 0 {
        return err
    }
    return nil
}
