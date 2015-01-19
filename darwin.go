package acl

// #include <sys/types.h>
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"

import (
	"unsafe"
)

func (acl ACL) Size() int64 {
	a := C.acl_t(acl.a)
	return int64(C.acl_size(a))
}

func (acl ACL) CopyExt(buffer []byte) (int64, error) {
	a := C.acl_t(acl.a)
	p := unsafe.Pointer(&buffer[0])
	l := C.ssize_t(len(buffer))
	i, err := C.acl_copy_ext(p, a, l)
	if i < 0 {
		return int64(i), err
	}
	return int64(i), nil
}

func CopyInt(buffer []byte) (ACL, error) {
	var acl ACL
	p := unsafe.Pointer(&buffer[0])
	cacl, err := C.acl_copy_int(p)
	if cacl == nil {
		return acl, err
	}
	acl.a = cacl
	return acl, nil
}
