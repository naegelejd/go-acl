package main

import (
	"fmt"
	"github.com/naegelejd/go-acl"
	"log"
	"os"
)

func main() {
	filename := os.Args[1]

	acl, err := acl.GetFile(filename, acl.TYPE_ACCESS)
	if err != nil {
		log.Fatal("Failed to get ACL from ", filename)
	}

	size := acl.Size()
	str, err := acl.ToText()
	if err != nil {
		log.Fatal("Failed to get string representation of ACL")
	}

	fmt.Print("ACL repr:\n", str)
	fmt.Print("ACL size: ", size)

	err = acl.Free(acl)
	if err != nil {
		log.Fatal("Failed to free ACL")
	}
}
