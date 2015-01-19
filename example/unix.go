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

	a, err := acl.GetFile(filename, acl.TYPE_ACCESS)
	if err != nil {
		log.Fatalf("Failed to get ACL from %s (%s)", filename, err)
	}

	str, err := a.ToText()
	if err != nil {
		log.Fatalf("Failed to get string representation of ACL (%s)", err)
	}

	fmt.Print("ACL repr:\n", str)

	if err = acl.Free(a); err != nil {
		log.Fatalf("Failed to free ACL (%s)", err)
	}
}
