// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build darwin

package acl

import "testing"

// tagExtendedAllow is ACL_EXTENDED_ALLOW (1), confirmed by probe/darwin_probe.c.
const tagExtendedAllow Tag = 1

func TestCalcMaskError(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	if err := acl.CalcMask(); err == nil {
		t.Fatal("expected CalcMask to return an error on Darwin")
	}
}

func TestDeleteDefaultACLError(t *testing.T) {
	if err := DeleteDefaultACL("."); err == nil {
		t.Fatal("expected DeleteDefaultACL to return an error on Darwin")
	}
}

func TestEntrySetGetTag(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetTag(tagExtendedAllow); err != nil {
		t.Fatal(err)
	}
	tag, err := e.GetTag()
	if err != nil {
		t.Fatal(err)
	}
	if tag != tagExtendedAllow {
		t.Fatalf("expected tag %d, got %d", tagExtendedAllow, tag)
	}
}
