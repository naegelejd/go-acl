// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

package os

import (
	"fmt"
	"os"
	"syscall"
)

func Owner(fname string) (owner, group int, err error) {
	var f *os.File
	f, err = os.Open(fname)
	if err != nil {
		return
	}
	// Close errors are intentionally ignored: Owner only reads file metadata
	// via Stat; no writes are performed, so a close failure cannot affect the
	// correctness of the returned values.
	defer func() { _ = f.Close() }()

	g := &File{*f}
	return g.Owner()
}

type File struct{ os.File }

func (f *File) Owner() (owner, group int, err error) {
	var fi os.FileInfo
	fi, err = f.Stat()
	if err != nil {
		return
	}

	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("could not stat file")
	}

	return int(sys.Uid), int(sys.Gid), nil
}
