// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestApplyRecursive verifies that apply visits every file in a directory tree
// exactly once when recursive is enabled. This catches an earlier bug where the
// loop variable `p` was overwritten on each iteration, causing sibling entries
// to be joined against the previously-joined path instead of the parent directory.
func TestApplyRecursive(t *testing.T) {
	// Build a tree:
	//   root/
	//     a
	//     b
	//     sub/
	//       c
	//       d
	root := t.TempDir()
	for _, rel := range []string{"a", "b", filepath.Join("sub", "c"), filepath.Join("sub", "d")} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Enable recursive mode for this test; restore afterwards.
	old := recursive
	recursive = true
	defer func() { recursive = old }()

	var visited []string
	collector := func(p string) error {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		visited = append(visited, rel)
		return nil
	}

	if err := apply(collector, root); err != nil {
		t.Fatal(err)
	}

	want := []string{
		".",
		"a",
		"b",
		filepath.Join("sub"),
		filepath.Join("sub", "c"),
		filepath.Join("sub", "d"),
	}
	sort.Strings(visited)
	sort.Strings(want)

	if len(visited) != len(want) {
		t.Fatalf("visited %d paths, want %d\nvisited: %v\nwant:    %v", len(visited), len(want), visited, want)
	}
	for i := range want {
		if visited[i] != want[i] {
			t.Errorf("visited[%d] = %q, want %q", i, visited[i], want[i])
		}
	}
}
