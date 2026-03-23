// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build darwin

package acl_test

import (
	"fmt"
	"os"

	acl "github.com/naegelejd/go-acl"
)

// ExampleACL_SetFileAccess demonstrates adding an NFSv4 allow entry for the
// current user to a file's extended ACL.
func ExampleACL_SetFileAccess() {
	f, err := os.CreateTemp("", "go-acl-example-*")
	if err != nil {
		panic(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	a, err := acl.GetFileAccess(f.Name())
	if err != nil {
		panic(err)
	}
	defer a.Free()

	entry, err := a.CreateEntry()
	if err != nil {
		panic(err)
	}
	entry.SetTag(acl.TagExtendedAllow)
	entry.SetQualifierUID(os.Getuid())
	pset, _ := entry.GetPermset()
	pset.AddPerm(acl.PermReadData)
	pset.AddPerm(acl.PermExecute)

	if err := a.SetFileAccess(f.Name()); err != nil {
		panic(err)
	}
	fmt.Println("ACL applied successfully")
	// Output:
	// ACL applied successfully
}

// ExampleEntry_GetFlagset demonstrates adding an inheritance flag to an
// NFSv4 ACL entry.
func ExampleEntry_GetFlagset() {
	a := acl.New()
	defer a.Free()

	entry, err := a.CreateEntry()
	if err != nil {
		panic(err)
	}
	entry.SetTag(acl.TagExtendedAllow)

	fs, err := entry.GetFlagset()
	if err != nil {
		panic(err)
	}
	fs.AddFlag(acl.FlagFileInherit)

	fmt.Println("has FlagFileInherit:", fs.HasFlag(acl.FlagFileInherit))
	fmt.Println("has FlagDirectoryInherit:", fs.HasFlag(acl.FlagDirectoryInherit))
	// Output:
	// has FlagFileInherit: true
	// has FlagDirectoryInherit: false
}
