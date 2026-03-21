// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

package acl

import (
	"os"
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
