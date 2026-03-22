// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build linux

package acl_test

import (
	"fmt"
	"os"

	acl "github.com/naegelejd/go-acl"
)

// ExampleGetFileAccess demonstrates reading the access ACL from a file and
// iterating over its entries.
func ExampleGetFileAccess() {
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

	for e := a.FirstEntry(); e != nil; e = a.NextEntry() {
		tag, _ := e.GetTag()
		pset, _ := e.GetPermset()
		fmt.Printf("tag=%v perms=%s\n", tag, pset)
	}
}

// ExampleFromMode demonstrates creating a minimal ACL from Unix permission
// bits and verifying it is equivalent to a plain Unix mode.
func ExampleFromMode() {
	a, err := acl.FromMode(0o644)
	if err != nil {
		panic(err)
	}
	defer a.Free()

	mode, isEquiv, err := a.EquivMode()
	if err != nil {
		panic(err)
	}
	if isEquiv {
		fmt.Printf("equivalent mode: %04o\n", mode)
	}
	// Output:
	// equivalent mode: 0644
}
