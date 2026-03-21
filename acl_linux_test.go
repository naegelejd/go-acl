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
	acl, err := GetFileAccess(makeTmpFile(t))
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
	if err := DeleteDefaultACL(makeTmpDir(t)); err != nil {
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

func TestPermsetString(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetTag(TagUserObj); err != nil {
		t.Fatal(err)
	}
	p, err := e.GetPermset()
	if err != nil {
		t.Fatal(err)
	}
	if s := p.String(); s != "---" {
		t.Fatalf("expected \"---\", got %q", s)
	}
	if err := p.AddPerm(PermRead); err != nil {
		t.Fatal(err)
	}
	if err := p.AddPerm(PermWrite); err != nil {
		t.Fatal(err)
	}
	if s := p.String(); s != "rw-" {
		t.Fatalf("expected \"rw-\", got %q", s)
	}
	if err := p.AddPerm(PermExecute); err != nil {
		t.Fatal(err)
	}
	if s := p.String(); s != "rwx" {
		t.Fatalf("expected \"rwx\", got %q", s)
	}
}

func TestMaskEntry(t *testing.T) {
	acl, err := GetFileAccess(makeTmpFile(t))
	if err != nil {
		t.Fatal(err)
	}
	defer acl.Free()

	// Add a named user entry; CalcMask should then create a mask entry.
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetTag(TagUser); err != nil {
		t.Fatal(err)
	}
	if err := e.SetQualifier(os.Getuid()); err != nil {
		t.Fatal(err)
	}
	if err := acl.CalcMask(); err != nil {
		t.Fatal(err)
	}

	var hasMask bool
	for entry := acl.FirstEntry(); entry != nil; entry = acl.NextEntry() {
		tag, err := entry.GetTag()
		if err != nil {
			t.Fatal(err)
		}
		if tag == TagMask {
			hasMask = true
			break
		}
	}
	if !hasMask {
		t.Fatal("expected TagMask entry after CalcMask with named user entry")
	}
}

func TestNamedUserRoundTrip(t *testing.T) {
	path := makeTmpFile(t)
	acl, err := GetFileAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	defer acl.Free()

	// Add named user entry with read+execute permissions.
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetTag(TagUser); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if err := e.SetQualifier(uid); err != nil {
		t.Fatal(err)
	}
	p, err := e.GetPermset()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddPerm(PermRead); err != nil {
		t.Fatal(err)
	}
	if err := p.AddPerm(PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := acl.CalcMask(); err != nil {
		t.Fatal(err)
	}
	if err := acl.SetFileAccess(path); err != nil {
		t.Fatal(err)
	}

	got, err := GetFileAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Free()

	var found bool
	for entry := got.FirstEntry(); entry != nil; entry = got.NextEntry() {
		tag, err := entry.GetTag()
		if err != nil {
			t.Fatal(err)
		}
		if tag != TagUser {
			continue
		}
		q, err := entry.GetQualifier()
		if err != nil {
			t.Fatal(err)
		}
		if q != uid {
			continue
		}
		pset, err := entry.GetPermset()
		if err != nil {
			t.Fatal(err)
		}
		if s := pset.String(); s != "r-x" {
			t.Fatalf("expected perms \"r-x\", got %q", s)
		}
		found = true
	}
	if !found {
		t.Fatalf("named user entry for uid %d not found in ACL after round-trip", uid)
	}
}

func TestDefaultACLRoundTrip(t *testing.T) {
	dir := makeTmpDir(t)

	// Build a minimal valid default ACL: user, group, mask, other.
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()

	addEntry := func(tag Tag, r, w, x bool) {
		t.Helper()
		e, err := acl.CreateEntry()
		if err != nil {
			t.Fatal(err)
		}
		if err := e.SetTag(tag); err != nil {
			t.Fatal(err)
		}
		p, err := e.GetPermset()
		if err != nil {
			t.Fatal(err)
		}
		if r {
			if err := p.AddPerm(PermRead); err != nil {
				t.Fatal(err)
			}
		}
		if w {
			if err := p.AddPerm(PermWrite); err != nil {
				t.Fatal(err)
			}
		}
		if x {
			if err := p.AddPerm(PermExecute); err != nil {
				t.Fatal(err)
			}
		}
	}
	addEntry(TagUserObj, true, true, true)
	addEntry(TagGroupObj, true, false, true)
	addEntry(TagMask, true, false, true)
	addEntry(TagOther, true, false, true)

	if err := acl.SetFileDefault(dir); err != nil {
		t.Fatal(err)
	}

	got, err := GetFileDefault(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Free()

	if !got.Valid() {
		t.Fatal("retrieved default ACL is not valid")
	}

	present := make(map[Tag]bool)
	for e := got.FirstEntry(); e != nil; e = got.NextEntry() {
		tag, err := e.GetTag()
		if err != nil {
			t.Fatal(err)
		}
		present[tag] = true
	}
	for _, expected := range []Tag{TagUserObj, TagGroupObj, TagMask, TagOther} {
		if !present[expected] {
			t.Errorf("default ACL missing tag %d", expected)
		}
	}
}

func TestGetFd(t *testing.T) {
	path := makeTmpFile(t)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	acl, err := GetFd(f)
	if err != nil {
		t.Fatal(err)
	}
	defer acl.Free()

	if !acl.Valid() {
		t.Fatal("ACL retrieved via GetFd is not valid")
	}
}

func TestSetFd(t *testing.T) {
	path := makeTmpFile(t)

	// Build an ACL with a named user entry so the result is distinguishable.
	base, err := GetFileAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Free()

	e, err := base.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetTag(TagUser); err != nil {
		t.Fatal(err)
	}
	if err := e.SetQualifier(os.Getuid()); err != nil {
		t.Fatal(err)
	}
	p, err := e.GetPermset()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddPerm(PermRead); err != nil {
		t.Fatal(err)
	}
	if err := base.CalcMask(); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if err := base.SetFd(f); err != nil {
		t.Fatal(err)
	}

	// Read back via path and verify the named user entry is present.
	got, err := GetFileAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Free()

	var found bool
	for entry := got.FirstEntry(); entry != nil; entry = got.NextEntry() {
		tag, _ := entry.GetTag()
		if tag == TagUser {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("named user entry not found after SetFd")
	}
}

func TestFromMode(t *testing.T) {
	// 0755 → user:rwx group:r-x other:r-x
	acl, err := FromMode(0755)
	if err != nil {
		t.Fatal(err)
	}
	defer acl.Free()

	if !acl.Valid() {
		t.Fatal("ACL from FromMode(0755) is not valid")
	}

	// Expect exactly 3 base entries.
	count := 0
	tags := make(map[Tag]string)
	for e := acl.FirstEntry(); e != nil; e = acl.NextEntry() {
		count++
		tag, _ := e.GetTag()
		pset, _ := e.GetPermset()
		tags[tag] = pset.String()
	}
	if count != 3 {
		t.Fatalf("expected 3 entries from FromMode, got %d", count)
	}
	if tags[TagUserObj] != "rwx" {
		t.Errorf("user entry: expected rwx, got %q", tags[TagUserObj])
	}
	if tags[TagGroupObj] != "r-x" {
		t.Errorf("group entry: expected r-x, got %q", tags[TagGroupObj])
	}
	if tags[TagOther] != "r-x" {
		t.Errorf("other entry: expected r-x, got %q", tags[TagOther])
	}
}

func TestEquivMode(t *testing.T) {
	// A base-only ACL (no named entries) should be equivalent to a mode.
	base, err := GetFileAccess(makeTmpFile(t))
	if err != nil {
		t.Fatal(err)
	}
	defer base.Free()

	mode, equiv, err := base.EquivMode()
	if err != nil {
		t.Fatal(err)
	}
	if !equiv {
		t.Fatal("expected base ACL to be equivalent to a Unix mode")
	}
	if mode == 0 {
		t.Fatal("expected non-zero mode from EquivMode")
	}

	// Add a named user entry — now it should NOT be equivalent.
	e, err := base.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetTag(TagUser); err != nil {
		t.Fatal(err)
	}
	if err := e.SetQualifier(os.Getuid()); err != nil {
		t.Fatal(err)
	}
	if err := base.CalcMask(); err != nil {
		t.Fatal(err)
	}

	_, equiv, err = base.EquivMode()
	if err != nil {
		t.Fatal(err)
	}
	if equiv {
		t.Fatal("expected ACL with named user entry to NOT be equivalent to a Unix mode")
	}
}
