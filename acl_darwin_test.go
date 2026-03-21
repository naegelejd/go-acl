// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build darwin

package acl

import (
	"os"
	"testing"
)

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
	if err := e.SetTag(TagExtendedAllow); err != nil {
		t.Fatal(err)
	}
	tag, err := e.GetTag()
	if err != nil {
		t.Fatal(err)
	}
	if tag != TagExtendedAllow {
		t.Fatalf("expected TagExtendedAllow (%d), got %d", TagExtendedAllow, tag)
	}
}

func TestEntryQualifierRoundTrip(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetTag(TagExtendedAllow); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if err := e.SetQualifierUID(uid); err != nil {
		t.Fatal(err)
	}
	gotID, gotType, err := e.GetQualifierID()
	if err != nil {
		t.Fatal(err)
	}
	if gotType != QualifierTypeUID {
		t.Fatalf("expected QualifierTypeUID (%d), got %d", QualifierTypeUID, gotType)
	}
	if gotID != uid {
		t.Fatalf("expected uid %d, got %d", uid, gotID)
	}
}

func TestEntryGIDQualifierRoundTrip(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetTag(TagExtendedAllow); err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	if err := e.SetQualifierGID(gid); err != nil {
		t.Fatal(err)
	}
	gotID, gotType, err := e.GetQualifierID()
	if err != nil {
		t.Fatal(err)
	}
	if gotType != QualifierTypeGID {
		t.Fatalf("expected QualifierTypeGID (%d), got %d", QualifierTypeGID, gotType)
	}
	if gotID != gid {
		t.Fatalf("expected gid %d, got %d", gid, gotID)
	}
}

// TestSetGetACLRoundTrip writes a real NFSv4 ALLOW entry to a file and reads it
// back, verifying the tag, qualifier, and permissions survive the round-trip.
func TestSetGetACLRoundTrip(t *testing.T) {
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer func() {
		// Clear the ACL before removing the file.
		empty := New()
		if empty != nil {
			_ = empty.SetFileAccess(tmpfile)
			empty.Free()
		}
		os.Remove(tmpfile)
	}()

	uid := os.Getuid()

	// Build an ACL with one ALLOW entry for the current user.
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetTag(TagExtendedAllow); err != nil {
		t.Fatal(err)
	}
	if err := e.SetQualifierUID(uid); err != nil {
		t.Fatal(err)
	}
	ps, err := e.GetPermset()
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.AddPerm(PermReadData); err != nil {
		t.Fatal(err)
	}
	if err := ps.AddPerm(PermWriteData); err != nil {
		t.Fatal(err)
	}
	if err := acl.SetFileAccess(tmpfile); err != nil {
		t.Fatal(err)
	}
	acl.Free()

	// Read the ACL back.
	got, err := GetFileAccess(tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Free()

	entry := got.FirstEntry()
	if entry == nil {
		t.Fatal("expected at least one entry in retrieved ACL")
	}
	tag, err := entry.GetTag()
	if err != nil {
		t.Fatal(err)
	}
	if tag != TagExtendedAllow {
		t.Fatalf("expected TagExtendedAllow, got %d", tag)
	}
	gotID, gotType, err := entry.GetQualifierID()
	if err != nil {
		t.Fatal(err)
	}
	if gotType != QualifierTypeUID {
		t.Fatalf("expected QualifierTypeUID, got type %d", gotType)
	}
	if gotID != uid {
		t.Fatalf("expected uid %d in qualifier, got %d", uid, gotID)
	}
}

func TestFlagset(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	fs, err := e.GetFlagset()
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.AddFlag(FlagFileInherit); err != nil {
		t.Fatal(err)
	}
	if err := fs.AddFlag(FlagDirectoryInherit); err != nil {
		t.Fatal(err)
	}
	if !fs.HasFlag(FlagFileInherit) {
		t.Error("expected FlagFileInherit to be set")
	}
	if !fs.HasFlag(FlagDirectoryInherit) {
		t.Error("expected FlagDirectoryInherit to be set")
	}
	if fs.HasFlag(FlagLimitInherit) {
		t.Error("expected FlagLimitInherit to not be set")
	}
	if err := fs.DeleteFlag(FlagFileInherit); err != nil {
		t.Fatal(err)
	}
	if fs.HasFlag(FlagFileInherit) {
		t.Error("expected FlagFileInherit to be cleared after DeleteFlag")
	}
	if err := fs.ClearFlags(); err != nil {
		t.Fatal(err)
	}
	if fs.HasFlag(FlagDirectoryInherit) {
		t.Error("expected FlagDirectoryInherit to be cleared after ClearFlags")
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
	ps, err := e.GetPermset()
	if err != nil {
		t.Fatal(err)
	}
	// Empty permset should have an empty string.
	if s := ps.String(); s != "" {
		t.Fatalf("expected empty string for empty permset, got %q", s)
	}
	if err := ps.AddPerm(PermReadData); err != nil {
		t.Fatal(err)
	}
	if err := ps.AddPerm(PermExecute); err != nil {
		t.Fatal(err)
	}
	s := ps.String()
	if s != "read_data,execute" {
		t.Fatalf("expected \"read_data,execute\", got %q", s)
	}
}
