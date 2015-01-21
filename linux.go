package acl

// #include <sys/acl.h>
// #include <acl/libacl.h>
// #cgo linux LDFLAGS: -lacl
import "C"
import "fmt"

func (pset *Permset) String() string {
	r, w, e := '-', '-', '-'

	rv, _ := C.acl_get_perm(pset.p, C.ACL_READ)
	if rv > 0 {
		r = 'r'
	}
	rv, _ = C.acl_get_perm(pset.p, C.ACL_WRITE)
	if rv > 0 {
		w = 'w'
	}
	rv, _ = C.acl_get_perm(pset.p, C.ACL_EXECUTE)
	if rv > 0 {
		e = 'e'
	}

	return fmt.Sprintf("%c%c%c", r, w, e)
}
