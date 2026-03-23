// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build linux || freebsd

package main

import "github.com/naegelejd/go-acl"

// calculateMask recalculates the effective rights mask if the -mask flag is set.
func calculateMask(a *acl.ACL) error {
	if calcMask {
		if err := a.CalcMask(); err != nil {
			return err
		}
	}
	return nil
}

// clearExtendedEntries removes all named-user, named-group, and mask entries
// from the access ACL of path, leaving only the three base entries
// (TagUserObj, TagGroupObj, TagOther). Reading the existing ACL is essential
// because Linux stomps the file mode's group bits with the current mask value,
// so reconstructing from mode bits would produce wrong group permissions.
func clearExtendedEntries(path string) error {
	x, err := acl.GetFileAccess(path)
	if err != nil {
		return err
	}
	defer x.Free()

	// First pass: collect entries to delete (must not delete during iteration).
	var toDelete []*acl.Entry
	for e := x.FirstEntry(); e != nil; e = x.NextEntry() {
		tag, err := e.GetTag()
		if err != nil {
			return err
		}
		if tag == acl.TagUser || tag == acl.TagGroup || tag == acl.TagMask {
			toDelete = append(toDelete, e)
		}
	}
	// Second pass: delete.
	for _, e := range toDelete {
		if err := x.DeleteEntry(e); err != nil {
			return err
		}
	}
	return x.SetFileAccess(path)
}

// clearDefaultACL removes the default ACL from the given directory path.
func clearDefaultACL(path string) error {
	return acl.DeleteDefaultACL(path)
}

// entriesMatch reports whether two entries have the same tag and uid/gid qualifier.
// Tags that do not carry a qualifier (TagMask, TagUserObj, TagGroupObj, TagOther)
// are matched by tag alone; qualifier comparison is only done for TagUser/TagGroup.
func entriesMatch(a, b *acl.Entry) (bool, error) {
	tagA, err := a.GetTag()
	if err != nil {
		return false, err
	}
	tagB, err := b.GetTag()
	if err != nil {
		return false, err
	}
	if tagA != tagB {
		return false, nil
	}
	if tagA != acl.TagUser && tagA != acl.TagGroup {
		return true, nil
	}
	qA, err := a.GetQualifier()
	if err != nil {
		return false, err
	}
	qB, err := b.GetQualifier()
	if err != nil {
		return false, err
	}
	return qA == qB, nil
}

// parseACLArg parses the POSIX.1e text representation of an ACL (e.g. "user:alice:rwx").
func parseACLArg(s string) (*acl.ACL, error) {
	return acl.Parse(s)
}
