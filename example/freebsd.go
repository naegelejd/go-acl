package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/naegelejd/go-acl"
)

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		log.Fatal("Missing filename")
	}
	filename := flag.Arg(0)

	acl, err := acls.GetFile(filename, acls.TYPE_ACCESS)
	if err != nil {
		log.Fatalf("Failed to get ACL from %s (%s)", filename, err)
	}

	str, err := acl.ToText()
	if err != nil {
		log.Fatalf("Failed to get string representation of ACL (%s)", err)
	}

	fmt.Print("ACL repr:\n", str)

	if err = acls.Free(acl); err != nil {
		log.Fatalf("Failed to free ACL (%s)", err)
	}
}
