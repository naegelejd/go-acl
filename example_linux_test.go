// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

//go:build linux

package acl_test

import (
	"fmt"

	acl "github.com/naegelejd/go-acl"
)

// ExampleGetFileAccess demonstrates iterating over entries in an ACL
// constructed from Unix mode bits.
func ExampleGetFileAccess() {
	// Use FromMode so the entry set is deterministic regardless of the
	// host file system's umask or default ACL.
	a, err := acl.FromMode(0o700)
	if err != nil {
		panic(err)
	}
	defer a.Free()

	count := 0
	for e := a.FirstEntry(); e != nil; e = a.NextEntry() {
		_ = e
		count++
	}
	fmt.Printf("entry count: %d\n", count)
	// Output:
	// entry count: 3
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
