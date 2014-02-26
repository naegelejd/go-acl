package acl

// #ifdef __linux__
//  #cgo LDFLAGS: -lacl
// #elif defined __FreeBSD__
//
// #elif defined __APPLE__
//  #cgo LDFLAGS: -lacl
//  #include <sys/types.h>
// #endif
// #include <sys/acl.h>
import "C"

import (
)

/*
* From FreeBSD acl.h:
* 254 Entries makes the acl struct exactly one 4KB page in size.
* NFSv4 halves this number (just for reference)
*/
const MAX_ENTRIES = 254

const (
    TYPE_ACCESS_OLD = iota
    TYPE_DEFAULT_OLD
    TYPE_ACCESS
    TYPE_DEFAULT
    TYPE_NFS4
)

const (
    NONE = 0
    EXECUTE = 1 << iota
    WRITE
    READ
)

type tag_t uint32
type perm_t uint32
type entry_type_t uint16
/* type flag_t uint16 */
type type_t int
type permset_t int
/* type flagset_t int16 */
type uid_t uint32 // FIXME: where is this defined?

// FIXME: these are stubs until func signatures are fixed
type void uint
type constvoid uint
type constchar string
type ssize_t uint64



type entry_t struct {
    ae_tag tag_t;
    ae_id uid_t;
    ae_perm perm_t;
    /* ae_entry_type entry_type_t; */
    /* ae_flags flag_t; */
}

type acl_t struct {
    mxcnt uint
    cnt uint
    spare [4]int
    entry [MAX_ENTRIES]entry_t
}


func add_perm(permset permset_t, perm perm_t) int {
    return 0
}

func calc_mask(acl_p *acl_t) int {
    return 0
}

func clear_perms(permset permset_t) int {
    return 0
}

func copy_entry(dest entry_t, src entry_t) int {
    return 0
}

func copy_ext(buf_p *void, acl acl_t, size ssize_t) ssize_t {
    return 0
}

func copy_int(buf_p *constvoid) acl_t {
    return acl_t{};
}

func create_entry(acl_p *acl_t, entry_p *entry_t) int {
    return 0
}

func delete_entry(acl acl_t, entry entry_t) int {
    return 0
}

func delete_def_file(path_p *constchar) int {
    return 0
}

func delete_perm(permset permset_t, perm perm_t) int {
    return 0
}

func dup(acl acl_t) acl_t {
    return acl_t{}
}

func free(obj_p *void) int {
    return 0
}

func from_text(buf_p *constchar) acl_t {
    return acl_t{}
}

func get_entry(acl acl_t, entry_id int, entry_p *entry_t) int {
    return 0
}

func get_fd(fd int) acl_t {
    return acl_t{}
}

func get_file(path_p *constchar, typ type_t) acl_t {
    return acl_t{}
}

func get_qualifier(entry entry_t) error {
    return nil
}

func get_permset(entry entry_t, permset_p *permset_t) int {
    return 0
}

func get_tag_type(entry entry_t, tag_type_p *tag_t) int {
    return 0
}

func initialize(count int) acl_t {
    return acl_t{}
}

func set_fd(fd int, acl acl_t) int {
    return 0
}

func set_file(path_p *constchar, typ type_t, acl acl_t) int {
    return 0
}

func set_permset(entry entry_t, permset permset_t) int {
    return 0
}

func set_qualifier(entry entry_t, tag_qualifier_p *constvoid) int {
    return 0
}

func set_tag_type(entry entry_t, tag_type tag_t) int {
    return 0
}

func acl_size(acl acl_t) ssize_t {
    return 0
}

func to_text(acl acl_t, len_p *ssize_t) []byte {
    return []byte("")
}

func valid(acl acl_t) int {
    return 0
}
