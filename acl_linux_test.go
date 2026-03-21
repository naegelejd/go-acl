// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build linux

package acl

import (
	"os"
	"testing"
)

func checkForBaseEntries(t *testing.T, acl *ACL) {
	// the base access entries on a normal file should have
	// a USER_OBJ, GROUP_OBJ, and OTHER entry
	var u, g, o bool
	for e := acl.FirstEntry(); e != nil; e = acl.NextEntry() {
		tag, err := e.GetTag()
		if err != nil {
			t.Fatal(err)
		}
		switch tag {
		case TagUserObj:
			u = true
		case TagGroupObj:
			g = true
		case TagOther:
			o = true
		}
	}
	if !u || !g || !o {
		t.Fail()
	}
}

func TestGetEntries(t *testing.T) {
	acl := getACLFromTmpFile(t)
	defer acl.Free()
	checkForBaseEntries(t, acl)
}

func TestAddEntry(t *testing.T) {
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(tmpfile)

	acl, err := GetFileAccess(tmpfile)
	if err != nil {
		t.Fatal("Failed to get ACL from file: ", err)
	}
	defer acl.Free()

	empty := New()
	if empty == nil {
		t.Fatal("unable to create new ACL")
	}
	for e := acl.FirstEntry(); e != nil; e = acl.NextEntry() {
		if err := empty.AddEntry(e); err != nil {
			t.Fatal(err)
		}
	}

	checkForBaseEntries(t, empty)
}

func TestCalcMask(t *testing.T) {
	acl := getACLFromTmpFile(t)
	defer acl.Free()
	if err := acl.CalcMask(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteDefaultACL(t *testing.T) {
	if err := os.Mkdir(tmpdir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpdir)
	if err := DeleteDefaultACL(tmpdir); err != nil {
		t.Fatal(err)
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
	if err := e.SetTag(TagUser); err != nil {
		t.Fatal(err)
	}
	tag, err := e.GetTag()
	if err != nil {
		t.Fatal(err)
	}
	if tag != TagUser {
		t.Fatalf("expected TagUser (%d), got %d", TagUser, tag)
	}
}

func TestEntrySetGetQualifier(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	// qualifier is only meaningful on ACL_USER / ACL_GROUP entries
	if err := e.SetTag(TagUser); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if err := e.SetQualifier(uid); err != nil {
		t.Fatal(err)
	}
	got, err := e.GetQualifier()
	if err != nil {
		t.Fatal(err)
	}
	if got != uid {
		t.Fatalf("expected qualifier %d, got %d", uid, got)
	}
}
