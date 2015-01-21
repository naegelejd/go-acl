package acl

import (
	"os"
	"testing"
)

const filename = "go-acl-test-file"

func TestGetFile(t *testing.T) {
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	acl, err := GetFileAccess(filename)
	if err != nil {
		t.Fatal("Failed to get ACL from file: ", err)
	}

	acl.Free()

	err = os.Remove(filename)
	if err != nil {
		t.Fatal(err)
	}
}
