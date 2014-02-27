package acls

// #ifdef __APPLE__
//  #include <sys/types.h>
// #endif
// #include <sys/acl.h>
// #cgo linux LDFLAGS: -lacl
import "C"

import (
    "unsafe"
)

/*
* From FreeBSD acl.h:
* 254 Entries makes the acl struct exactly one 4KB page in size.
* NFSv4 halves this number (just for reference)
*/
const MAX_ENTRIES = 254

const (
    TYPE_ACCESS_OLD Type = iota
    TYPE_DEFAULT_OLD
    TYPE_ACCESS
    TYPE_DEFAULT
    TYPE_NFS4
)

const (
    USER_OBJ Tag = iota
    USER
    GROUP_OBJ
    GROUP
    MASK
    OTHER
    OTHER_OBJ
    EVERYONE
)

const (
    NONE Perm = 0
    EXECUTE Perm = 1 << iota
    WRITE
    READ
)

/* type uid_t uint32 // FIXME: where is this defined? */
/* type gid_t uint32 // FIXME: where is this defined? */

type Tag int
type Type int
type Perm int

type Permset struct {
    p C.acl_permset_t
}

type Entry struct {
    e C.acl_entry_t
}

type ACL struct {
    a C.acl_t
}

/* type entry_t struct { */
/*     ae_tag tag_t; */
/*     ae_id uid_t; */
/*     ae_perm perm_t; */
/*     /1* ae_entry_type entry_type_t; *1/ */
/*     /1* ae_flags flag_t; *1/ */
/* } */

/* type acl struct { */
/*     mxcnt uint */
/*     cnt uint */
/*     spare [4]int */
/*     entry [MAX_ENTRIES]entry_t */
/* } */


// Only supported on Mac OS X?
/* func copy_ext(buf_p *void, acl acl_t, size ssize_t) ssize_t { */
/*     return 0 */
/* } */

// Only supported on Mac OS X?
/* func copy_int(buf_p *constvoid) acl_t { */
/*     return acl_t{}; */
/* } */

// Unsupported on Mac OS X
/* func delete_def_file(path_p *constchar) int { */
/*     acl_delete_def_file */
/*     return 0 */
/* } */


// Unsupported on Mac OS X
func (acl ACL) CalcMask() error {
    a := C.acl_t(acl.a)
    i, err := C.acl_calc_mask(&a)
    if i < 0 {
        return err
    }
    return nil
}

func (acl ACL) GetEntry(eid int) (Entry, error) {
    a := C.acl_t(acl.a)
    var entry Entry
    e := C.acl_entry_t(entry.e)
    i, err := C.acl_get_entry(a, C.int(eid), &e)
    if i < 0 {
        return entry, err
    }
    entry.e= e
    return entry, nil
}

func (acl ACL) Size() uint64 {
    a := C.acl_t(acl.a)
    return uint64(C.acl_size(a))
}

func (acl ACL) ToText() (string, error) {
    a := C.acl_t(acl.a)
    s, err := C.acl_to_text(a, nil)
    if s == nil {
        return "", err
    }
    return C.GoString(s), nil
}

func (acl ACL) Valid() bool {
    a := C.acl_t(acl.a)
    v := C.acl_valid(a)
    if v < 0 {
        return false
    }
    return true
}

func (acl ACL) CreateEntry() (Entry, error) {
    a := C.acl_t(acl.a)
    var entry Entry
    e := C.acl_entry_t(entry.e)
    i, err := C.acl_create_entry(&a, &e)
    if i < 0 {
        return entry, err
    }
    return entry, nil
}

func (acl ACL) DeleteEntry(entry Entry) error {
    a := C.acl_t(acl.a)
    e := C.acl_entry_t(entry.e)
    i, err := C.acl_delete_entry(a, e)
    if i < 0 {
        return err
    }
    return nil
}

func (acl ACL) Dup() (ACL, error) {
    a := C.acl_t(acl.a)
    var dup ACL
    cdup, err := C.acl_dup(a)
    if cdup == nil {
        return dup, err
    }
    dup.a = cdup
    return dup, nil
}


func Init(count int) (ACL, error) {
    var acl ACL
    cacl, err := C.acl_init(C.int(count))
    if cacl == nil {
        return acl, err
    }
    acl.a = cacl
    return acl, nil
}

func SetFd(fd int, acl ACL) error {
    a := C.acl_t(acl.a)
    i, err := C.acl_set_fd(C.int(fd), a)
    if i < 0 {
        return err
    }
    return nil
}

func SetFile(path string, tp Type, acl ACL) error {
    a := C.acl_t(acl.a)
    t := C.acl_type_t(tp)
    p := C.CString(path)
    i, err := C.acl_set_file(p, t, a)
    if i < 0 {
        return err
    }
    return nil
}

func Free(acl ACL) error {
    a := unsafe.Pointer(C.acl_t(acl.a))
    i, err := C.acl_free(a)
    if i < 0 {
        return err
    }
    return nil
}

func FromText(buffer string) (ACL, error) {
    cs := C.CString(buffer)
    var acl ACL
    cacl, err := C.acl_from_text(cs)
    if cacl == nil {
        return acl, err
    }
    acl.a = cacl
    return acl, nil
}

func GetFd(fd int) (ACL, error) {
    var acl ACL
    cacl, err := C.acl_get_fd(C.int(fd))
    if cacl == nil {
        return acl, err
    }
    acl.a = cacl
    return acl, nil
}

func GetFile(path string, t Type) (ACL, error) {
    var acl ACL
    cs := C.CString(path)
    cacl, err := C.acl_get_file(cs, C.acl_type_t(t))
    if cacl == nil {
        return acl, err
    }
    acl.a = cacl
    return acl, nil
}
