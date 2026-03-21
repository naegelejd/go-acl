// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

package acl

import (
	"os"
	"runtime"
	"testing"
)

const (
	tmpfile = "acl-tmp-test-file"
	tmpdir  = "acl-tmp-test-dir"
)

func getACLFromTmpFile(t *testing.T) *ACL {
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
	return acl
}

func TestGetFile(t *testing.T) {
	acl := getACLFromTmpFile(t)
	acl.Free()
}

func TestSetFile(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create new ACL")
	}

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(tmpfile)

	if err := acl.SetFileAccess(tmpfile); err != nil {
		t.Fatal(err)
	}
}

func TestACLValid(t *testing.T) {
	acl := getACLFromTmpFile(t)
	defer acl.Free()
	if !acl.Valid() {
		t.Fatal("expected ACL from file to be valid")
	}
}

func TestACLString(t *testing.T) {
	acl := getACLFromTmpFile(t)
	defer acl.Free()
	_ = acl.String()
}

func TestACLStringParse(t *testing.T) {
	acl := getACLFromTmpFile(t)
	defer acl.Free()
	text := acl.String()
	if text == "" {
		t.Skip("String() returned empty; skipping Parse round-trip")
	}
	parsed, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Free()
}

func TestACLDup(t *testing.T) {
	acl := getACLFromTmpFile(t)
	defer acl.Free()
	dup, err := acl.Dup()
	if err != nil {
		t.Fatal(err)
	}
	defer dup.Free()
	if !dup.Valid() {
		t.Fatal("dup'd ACL is not valid")
	}
}

func TestACLCreateDeleteEntry(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if err := acl.DeleteEntry(e); err != nil {
		t.Fatal(err)
	}
}

func TestACLIteration(t *testing.T) {
	acl := getACLFromTmpFile(t)
	defer acl.Free()
	for e := acl.FirstEntry(); e != nil; e = acl.NextEntry() {
		_ = e
	}
}

// TestACLIterationWithEntries explicitly creates entries so that NextEntry is
// exercised on platforms where getACLFromTmpFile returns an empty ACL (Darwin).
func TestACLIterationWithEntries(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	for i := 0; i < 2; i++ {
		if _, err := acl.CreateEntry(); err != nil {
			t.Fatal(err)
		}
	}
	count := 0
	for e := acl.FirstEntry(); e != nil; e = acl.NextEntry() {
		count++
	}
	if count != 2 {
		t.Fatalf("expected 2 entries, got %d", count)
	}
}

func TestACLAddEntry(t *testing.T) {
	src := New()
	if src == nil {
		t.Fatal("unable to create src ACL")
	}
	defer src.Free()
	if _, err := src.CreateEntry(); err != nil {
		t.Fatal(err)
	}

	dst := New()
	if dst == nil {
		t.Fatal("unable to create dst ACL")
	}
	defer dst.Free()
	e := src.FirstEntry()
	if e == nil {
		t.Fatal("expected to find an entry in src ACL")
	}
	if err := dst.AddEntry(e); err != nil {
		t.Fatal(err)
	}
}

func TestGetFileDefault(t *testing.T) {
	if err := os.Mkdir(tmpdir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpdir)
	acl, err := GetFileDefault(tmpdir)
	if err != nil {
		t.Fatal(err)
	}
	defer acl.Free()
}

func TestSetFileDefault(t *testing.T) {
	if err := os.Mkdir(tmpdir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpdir)
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	if err := acl.SetFileDefault(tmpdir); err != nil {
		t.Fatal(err)
	}
}

// TestACLSizeCopyExtInt exercises Size, CopyExt, and CopyInt.
// acl_size is non-functional on FreeBSD (see FreeBSD r274722) so the test
// is skipped there at runtime.
func TestACLSizeCopyExtInt(t *testing.T) {
	if runtime.GOOS == "freebsd" {
		t.Skip("acl_size is non-functional on FreeBSD")
	}
	acl := getACLFromTmpFile(t)
	defer acl.Free()
	size := acl.Size()
	if size <= 0 {
		t.Skipf("acl_size returned %d; skipping CopyExt/CopyInt test", size)
	}
	buf := make([]byte, size)
	n, err := acl.CopyExt(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n <= 0 {
		t.Fatalf("CopyExt wrote %d bytes", n)
	}
	restored, err := CopyInt(buf)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Free()
	if !restored.Valid() {
		t.Fatal("restored ACL is not valid")
	}
}

func TestEntryGetTag(t *testing.T) {
	acl := New()
	if acl == nil {
		t.Fatal("unable to create ACL")
	}
	defer acl.Free()
	e, err := acl.CreateEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.GetTag(); err != nil {
		t.Fatal(err)
	}
}

// TestEntryPermsetOps exercises GetPermset, AddPerm, DeletePerm, ClearPerms,
// and SetPermset using PermExecute which is defined on all platforms.
func TestEntryPermsetOps(t *testing.T) {
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
	if err := ps.AddPerm(PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := ps.DeletePerm(PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := ps.AddPerm(PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := ps.ClearPerms(); err != nil {
		t.Fatal(err)
	}
	if err := e.SetPermset(ps); err != nil {
		t.Fatal(err)
	}
}
