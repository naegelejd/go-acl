// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build darwin

package main

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/naegelejd/go-acl"
)

// calculateMask is a no-op on macOS; acl_calc_mask is not supported.
func calculateMask(a *acl.ACL) error {
	return nil
}

// clearExtendedEntries removes all NFSv4 ACL entries from path by setting an
// empty ACL. On macOS, acl_set_file(ACL_TYPE_EXTENDED, empty) is sufficient
// because an empty ACL is valid and the three base entries do not exist.
func clearExtendedEntries(path string) error {
	empty := acl.New()
	defer empty.Free()
	return empty.SetFileAccess(path)
}

// clearDefaultACL is a no-op on macOS; default ACLs are not supported.
func clearDefaultACL(_ string) error {
	return nil
}

// entriesMatch reports whether two ACL entries have the same tag and qualifier.
// Uses GetQualifierID to compare the (id, type) pair encoded in each UUID qualifier.
func entriesMatch(a, b *acl.Entry) bool {
	tagA, errA := a.GetTag()
	tagB, errB := b.GetTag()
	if errA != nil || errB != nil || tagA != tagB {
		return false
	}
	idA, typeA, errA := a.GetQualifierID()
	idB, typeB, errB := b.GetQualifierID()
	if errA != nil || errB != nil {
		return false
	}
	return idA == idB && typeA == typeB
}

// parseACLArg parses a Darwin NFSv4 ACL entry specification.
//
// Format: type:name:action:perm1,perm2,...
//
//	type:   user (u) or group (g)
//	name:   username or group name
//	action: allow or deny
//	perms:  comma-separated list from:
//	        read, write, execute, delete, append, delete_child,
//	        readattr, writeattr, readextattr, writeextattr,
//	        readsecurity, writesecurity, chown, sync
//
// Multiple entries may be separated by newlines.
func parseACLArg(s string) (*acl.ACL, error) {
	a := acl.New()
	if a == nil {
		return nil, fmt.Errorf("unable to create ACL")
	}
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := parseDarwinEntry(a, line); err != nil {
			a.Free()
			return nil, err
		}
	}
	return a, nil
}

func parseDarwinEntry(a *acl.ACL, s string) error {
	parts := strings.SplitN(s, ":", 4)
	if len(parts) != 4 {
		return fmt.Errorf("invalid entry %q: expected type:name:action:perms", s)
	}
	entryType, name, action, permsStr := parts[0], parts[1], parts[2], parts[3]

	// Resolve tag first — must be set before SetQualifierUID/GID on macOS.
	var tag acl.Tag
	switch strings.ToLower(action) {
	case "allow":
		tag = acl.TagExtendedAllow
	case "deny":
		tag = acl.TagExtendedDeny
	default:
		return fmt.Errorf("unknown action %q: expected allow or deny", action)
	}

	e, err := a.CreateEntry()
	if err != nil {
		return err
	}
	if err := e.SetTag(tag); err != nil {
		return err
	}

	// Resolve qualifier.
	switch strings.ToLower(entryType) {
	case "user", "u":
		u, err := user.Lookup(name)
		if err != nil {
			return fmt.Errorf("unknown user %q: %w", name, err)
		}
		uid, _ := strconv.Atoi(u.Uid)
		if err := e.SetQualifierUID(uid); err != nil {
			return fmt.Errorf("unable to set qualifier for user %q: %w", name, err)
		}
	case "group", "g":
		g, err := user.LookupGroup(name)
		if err != nil {
			return fmt.Errorf("unknown group %q: %w", name, err)
		}
		gid, _ := strconv.Atoi(g.Gid)
		if err := e.SetQualifierGID(gid); err != nil {
			return fmt.Errorf("unable to set qualifier for group %q: %w", name, err)
		}
	default:
		return fmt.Errorf("unknown entry type %q: expected user or group", entryType)
	}

	// Set permissions.
	ps, err := e.GetPermset()
	if err != nil {
		return err
	}
	for _, p := range strings.Split(permsStr, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		perm, ok := darwinPermByName(p)
		if !ok {
			return fmt.Errorf("unknown permission %q", p)
		}
		if err := ps.AddPerm(perm); err != nil {
			return err
		}
	}
	return nil
}

var darwinPermNames = map[string]acl.Perm{
	"read":                acl.PermReadData,
	"read_data":           acl.PermReadData,
	"list_directory":      acl.PermListDirectory,
	"write":               acl.PermWriteData,
	"write_data":          acl.PermWriteData,
	"add_file":            acl.PermAddFile,
	"execute":             acl.PermExecute,
	"search":              acl.PermExecute,
	"delete":              acl.PermDelete,
	"append":              acl.PermAppendData,
	"append_data":         acl.PermAppendData,
	"add_subdirectory":    acl.PermAddSubdirectory,
	"delete_child":        acl.PermDeleteChild,
	"readattr":            acl.PermReadAttributes,
	"read_attributes":     acl.PermReadAttributes,
	"writeattr":           acl.PermWriteAttributes,
	"write_attributes":    acl.PermWriteAttributes,
	"readextattr":         acl.PermReadExtAttributes,
	"read_extattributes":  acl.PermReadExtAttributes,
	"writeextattr":        acl.PermWriteExtAttributes,
	"write_extattributes": acl.PermWriteExtAttributes,
	"readsecurity":        acl.PermReadSecurity,
	"read_security":       acl.PermReadSecurity,
	"writesecurity":       acl.PermWriteSecurity,
	"write_security":      acl.PermWriteSecurity,
	"chown":               acl.PermChangeOwner,
	"change_owner":        acl.PermChangeOwner,
	"sync":                acl.PermSynchronize,
	"synchronize":         acl.PermSynchronize,
}

func darwinPermByName(name string) (acl.Perm, bool) {
	p, ok := darwinPermNames[strings.ToLower(name)]
	return p, ok
}
