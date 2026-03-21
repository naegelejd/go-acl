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

// entriesMatch reports whether two entries have the same tag and uid/gid qualifier.
func entriesMatch(a, b *acl.Entry) bool {
	tagA, errA := a.GetTag()
	tagB, errB := b.GetTag()
	if errA != nil || errB != nil || tagA != tagB {
		return false
	}
	qA, errA := a.GetQualifier()
	qB, errB := b.GetQualifier()
	if errA != nil || errB != nil {
		return false
	}
	return qA == qB
}

// parseACLArg parses the POSIX.1e text representation of an ACL (e.g. "user:alice:rwx").
func parseACLArg(s string) (*acl.ACL, error) {
	return acl.Parse(s)
}
