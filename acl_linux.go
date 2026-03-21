// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

package acl

// #include <sys/acl.h>
// #include <acl/libacl.h>
// #cgo linux LDFLAGS: -lacl
import "C"
import (
	"fmt"
	"os"
)

const (
	TagUserObj  Tag = C.ACL_USER_OBJ
	TagUser     Tag = C.ACL_USER
	TagGroupObj Tag = C.ACL_GROUP_OBJ
	TagGroup    Tag = C.ACL_GROUP
	TagMask     Tag = C.ACL_MASK
	TagOther    Tag = C.ACL_OTHER

	PermRead  Perm = C.ACL_READ
	PermWrite Perm = C.ACL_WRITE
)

// FromMode creates a minimal three-entry ACL (user, group, other) equivalent
// to the given Unix permission bits, using acl_from_mode(3).
func FromMode(mode os.FileMode) (*ACL, error) {
	cacl, _ := C.acl_from_mode(C.mode_t(mode))
	if cacl == nil {
		return nil, fmt.Errorf("acl_from_mode failed")
	}
	return &ACL{cacl}, nil
}

// EquivMode reports whether the ACL is equivalent to a simple Unix mode
// (i.e. contains no named user or group entries). If it is, the equivalent
// os.FileMode bits are returned along with true. If the ACL has extended
// entries, the zero mode and false are returned.
func (acl *ACL) EquivMode() (os.FileMode, bool, error) {
	var mode C.mode_t
	rv, _ := C.acl_equiv_mode(acl.a, &mode)
	if rv < 0 {
		return 0, false, fmt.Errorf("acl_equiv_mode failed")
	}
	return os.FileMode(mode), rv == 0, nil
}

func (acl *ACL) addBaseEntries(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := fi.Mode().Perm()
	var r, w, e bool

	// Set USER_OBJ entry
	r = mode&userRead == userRead
	w = mode&userWrite == userWrite
	e = mode&userExec == userExec
	if err := acl.addBaseEntryFromMode(TagUserObj, r, w, e); err != nil {
		return err
	}

	// Set GROUP_OBJ entry
	r = mode&groupRead == groupRead
	w = mode&groupWrite == groupWrite
	e = mode&groupExec == groupExec
	if err := acl.addBaseEntryFromMode(TagGroupObj, r, w, e); err != nil {
		return err
	}

	// Set OTHER entry
	r = mode&otherRead == otherRead
	w = mode&otherWrite == otherWrite
	e = mode&otherExec == otherExec
	if err := acl.addBaseEntryFromMode(TagOther, r, w, e); err != nil {
		return err
	}

	return nil
}

func (acl *ACL) addBaseEntryFromMode(tag Tag, read, write, execute bool) error {
	e, err := acl.CreateEntry()
	if err != nil {
		return err
	}
	if err = e.SetTag(tag); err != nil {
		return err
	}
	p, err := e.GetPermset()
	if err != nil {
		return err
	}
	if err := p.addPermsFromMode(read, write, execute); err != nil {
		return err
	}
	return nil
}

func (p *Permset) addPermsFromMode(read, write, execute bool) error {
	if read {
		if err := p.AddPerm(PermRead); err != nil {
			return err
		}
	}
	if write {
		if err := p.AddPerm(PermWrite); err != nil {
			return err
		}
	}
	if execute {
		if err := p.AddPerm(PermExecute); err != nil {
			return err
		}
	}
	return nil
}

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
		e = 'x'
	}

	return fmt.Sprintf("%c%c%c", r, w, e)
}
