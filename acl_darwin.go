// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

package acl

// #include <sys/types.h>
// #include <sys/acl.h>
// #include <membership.h>
//
// /* Convert uid to guid_t and set as entry qualifier. */
// static int qualifier_set_uid(acl_entry_t entry, int uid) {
//     guid_t guid;
//     if (mbr_uid_to_uuid((uid_t)uid, guid.g_guid) != 0) return -1;
//     return acl_set_qualifier(entry, &guid);
// }
// /* Convert gid to guid_t and set as entry qualifier. */
// static int qualifier_set_gid(acl_entry_t entry, int gid) {
//     guid_t guid;
//     if (mbr_gid_to_uuid((gid_t)gid, guid.g_guid) != 0) return -1;
//     return acl_set_qualifier(entry, &guid);
// }
// /* Get qualifier UUID and resolve back to a uid/gid int. */
// static int qualifier_get_id(acl_entry_t entry, int *id_out, int *type_out) {
//     void *q = acl_get_qualifier(entry);
//     if (q == NULL) return -1;
//     uid_t uid = 0;
//     int rv = mbr_uuid_to_id((unsigned char *)q, &uid, type_out);
//     acl_free(q);
//     if (rv != 0) return -1;
//     *id_out = (int)uid;
//     return 0;
// }
// /* Wrapper for acl_get_flagset_np (takes void* in the C API). */
// static int get_flagset(acl_entry_t entry, acl_flagset_t *fs) {
//     return acl_get_flagset_np((void *)entry, fs);
// }
import "C"

import (
	"fmt"
	"strings"
	"syscall"
)

const (
	// Tag types for macOS NFSv4 ACLs.
	TagExtendedAllow Tag = C.ACL_EXTENDED_ALLOW
	TagExtendedDeny  Tag = C.ACL_EXTENDED_DENY

	// NFSv4 permission constants for macOS.
	// PermExecute (= ACL_EXECUTE = ACL_SEARCH) is defined in perms.go and is
	// valid on all platforms.
	PermReadData           Perm = C.ACL_READ_DATA
	PermListDirectory      Perm = C.ACL_LIST_DIRECTORY      // = PermReadData (directory alias)
	PermWriteData          Perm = C.ACL_WRITE_DATA
	PermAddFile            Perm = C.ACL_ADD_FILE            // = PermWriteData (directory alias)
	PermDelete             Perm = C.ACL_DELETE
	PermAppendData         Perm = C.ACL_APPEND_DATA
	PermAddSubdirectory    Perm = C.ACL_ADD_SUBDIRECTORY    // = PermAppendData (directory alias)
	PermDeleteChild        Perm = C.ACL_DELETE_CHILD
	PermReadAttributes     Perm = C.ACL_READ_ATTRIBUTES
	PermWriteAttributes    Perm = C.ACL_WRITE_ATTRIBUTES
	PermReadExtAttributes  Perm = C.ACL_READ_EXTATTRIBUTES
	PermWriteExtAttributes Perm = C.ACL_WRITE_EXTATTRIBUTES
	PermReadSecurity       Perm = C.ACL_READ_SECURITY
	PermWriteSecurity      Perm = C.ACL_WRITE_SECURITY
	PermChangeOwner        Perm = C.ACL_CHANGE_OWNER
	PermSynchronize        Perm = C.ACL_SYNCHRONIZE

	// QualifierTypeUID and QualifierTypeGID match the macOS membership.h
	// ID_TYPE_UID / ID_TYPE_GID values returned by GetQualifierID.
	QualifierTypeUID = 0
	QualifierTypeGID = 1

	// Inheritance flag constants for macOS ACL entries.
	FlagFileInherit      Flag = C.ACL_ENTRY_FILE_INHERIT
	FlagDirectoryInherit Flag = C.ACL_ENTRY_DIRECTORY_INHERIT
	FlagLimitInherit     Flag = C.ACL_ENTRY_LIMIT_INHERIT
	FlagOnlyInherit      Flag = C.ACL_ENTRY_ONLY_INHERIT
)

// Flag is a Darwin-specific ACL entry inheritance flag.
type Flag int

// Flagset holds a reference to the inheritance flags on a Darwin ACL entry.
// Obtained via Entry.GetFlagset; valid as long as the parent Entry is alive.
// Mutations via AddFlag/DeleteFlag/ClearFlags take effect on the entry immediately.
type Flagset struct {
	f C.acl_flagset_t
}

// AddFlag adds an inheritance flag to the Flagset.
func (fs *Flagset) AddFlag(flag Flag) error {
	rv, _ := C.acl_add_flag_np(fs.f, C.acl_flag_t(flag))
	if rv < 0 {
		return fmt.Errorf("unable to add flag")
	}
	return nil
}

// DeleteFlag removes an inheritance flag from the Flagset.
func (fs *Flagset) DeleteFlag(flag Flag) error {
	rv, _ := C.acl_delete_flag_np(fs.f, C.acl_flag_t(flag))
	if rv < 0 {
		return fmt.Errorf("unable to delete flag")
	}
	return nil
}

// ClearFlags removes all inheritance flags from the Flagset.
func (fs *Flagset) ClearFlags() error {
	rv, _ := C.acl_clear_flags_np(fs.f)
	if rv < 0 {
		return fmt.Errorf("unable to clear flags")
	}
	return nil
}

// HasFlag reports whether the given inheritance flag is set.
func (fs *Flagset) HasFlag(flag Flag) bool {
	rv, _ := C.acl_get_flag_np(fs.f, C.acl_flag_t(flag))
	return rv > 0
}

// GetFlagset returns the inheritance flagset for the entry.
// The Flagset is a reference into the entry; it remains valid as long as the
// entry is alive and mutations take effect immediately.
func (entry *Entry) GetFlagset() (*Flagset, error) {
	var fs C.acl_flagset_t
	rv, _ := C.get_flagset(entry.e, &fs)
	if rv < 0 {
		return nil, fmt.Errorf("unable to get flagset")
	}
	return &Flagset{fs}, nil
}

// SetQualifierUID sets the entry qualifier from a uid, converting it to the
// 16-byte UUID (guid_t) required by macOS.
func (entry *Entry) SetQualifierUID(uid int) error {
	rv, _ := C.qualifier_set_uid(entry.e, C.int(uid))
	if rv < 0 {
		return fmt.Errorf("unable to set qualifier from uid %d", uid)
	}
	return nil
}

// SetQualifierGID sets the entry qualifier from a gid, converting it to the
// 16-byte UUID (guid_t) required by macOS.
func (entry *Entry) SetQualifierGID(gid int) error {
	rv, _ := C.qualifier_set_gid(entry.e, C.int(gid))
	if rv < 0 {
		return fmt.Errorf("unable to set qualifier from gid %d", gid)
	}
	return nil
}

// GetQualifierID returns the uid or gid encoded in the entry's UUID qualifier,
// along with its type (QualifierTypeUID or QualifierTypeGID).
// Uses mbr_uuid_to_id from <membership.h>.
func (entry *Entry) GetQualifierID() (id int, idType int, err error) {
	var cid, ctype C.int
	rv, _ := C.qualifier_get_id(entry.e, &cid, &ctype)
	if rv < 0 {
		return 0, 0, fmt.Errorf("unable to resolve qualifier UUID to id")
	}
	return int(cid), int(ctype), nil
}

// String returns a comma-separated list of the permissions set in the Permset,
// using the NFSv4 permission names. Uses acl_get_perm_np (macOS extension).
func (pset *Permset) String() string {
	checks := []struct {
		p    Perm
		name string
	}{
		{PermReadData, "read_data"},
		{PermWriteData, "write_data"},
		{PermExecute, "execute"},
		{PermDelete, "delete"},
		{PermAppendData, "append_data"},
		{PermDeleteChild, "delete_child"},
		{PermReadAttributes, "readattr"},
		{PermWriteAttributes, "writeattr"},
		{PermReadExtAttributes, "readextattr"},
		{PermWriteExtAttributes, "writeextattr"},
		{PermReadSecurity, "readsecurity"},
		{PermWriteSecurity, "writesecurity"},
		{PermChangeOwner, "chown"},
		{PermSynchronize, "sync"},
	}
	var set []string
	for _, c := range checks {
		rv, _ := C.acl_get_perm_np(pset.p, C.acl_perm_t(c.p))
		if rv > 0 {
			set = append(set, c.name)
		}
	}
	return strings.Join(set, ",")
}

func (acl *ACL) addBaseEntries(path string) error {
	return nil
}

// CalcMask is not supported on macOS (acl_calc_mask returns ENOTSUP).
func (acl *ACL) CalcMask() error {
	return fmt.Errorf("CalcMask is not supported on macOS")
}

// DeleteDefaultACL is not supported on macOS (acl_delete_def_file returns ENOTSUP).
func DeleteDefaultACL(path string) error {
	return fmt.Errorf("DeleteDefaultACL is not supported on macOS")
}

// GetFileAccess returns the extended ACL for the given path.
// macOS does not support POSIX.1e access ACLs; this uses ACL_TYPE_EXTENDED
// (NFSv4) instead. Files that have no extended ACL return an empty ACL.
func GetFileAccess(path string) (*ACL, error) {
	cacl, err := C.acl_get_file(C.CString(path), C.ACL_TYPE_EXTENDED)
	if cacl == nil {
		if err == syscall.ENOENT {
			// No extended ACL on this file — return an empty ACL.
			return New(), nil
		}
		return nil, fmt.Errorf("unable to get ACL from file")
	}
	return &ACL{cacl}, nil
}

// GetFileDefault returns an empty ACL. Default ACLs are not supported on macOS.
func GetFileDefault(path string) (*ACL, error) {
	return New(), nil
}

// SetFileAccess sets the extended ACL on a file.
// macOS only supports ACL_TYPE_EXTENDED; POSIX.1e access ACLs are not supported.
func (acl *ACL) SetFileAccess(path string) error {
	rv, _ := C.acl_set_file(C.CString(path), C.ACL_TYPE_EXTENDED, acl.a)
	if rv < 0 {
		return fmt.Errorf("unable to apply ACL to file")
	}
	return nil
}

// SetFileDefault is a no-op on macOS. Default ACLs are not supported.
func (acl *ACL) SetFileDefault(path string) error {
	return nil
}

