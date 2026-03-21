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
